#!/usr/bin/env python3
#
# Original work copyright (C) Citrix systems
# Modified work copyright (C) Vates SAS and XCP-ng community
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; version 2.1 only.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
# CEPHFSSR: Based on FileSR, mounts ceph fs share

from sm_typing import override

import errno
import os
import socket
import syslog as _syslog
import xmlrpc.client
from syslog import syslog

# careful with the import order here
# FileSR has a circular dependency:
# FileSR -> blktap2 -> lvutil -> EXTSR -> FileSR
# importing in this order seems to avoid triggering the issue.
import SR
import SRCommand
import FileSR
# end of careful
import VDI
import cleanup
import lock
import util
import vhdutil
import xs_errors

CAPABILITIES = ["SR_PROBE", "SR_UPDATE",
                "VDI_CREATE", "VDI_DELETE", "VDI_ATTACH", "VDI_DETACH",
                "VDI_UPDATE", "VDI_CLONE", "VDI_SNAPSHOT", "VDI_RESIZE", "VDI_MIRROR",
                "VDI_GENERATE_CONFIG",
                "VDI_RESET_ON_BOOT/2", "ATOMIC_PAUSE"]

CONFIGURATION = [
    ['server', 'Ceph server(s) (required, ex: "192.168.0.12" or "10.10.10.10,10.10.10.26")'],
    ['serverpath', 'Ceph FS path (required, ex: "/")'],
    ['serverport', 'ex: 6789'],
    ['options', 'Ceph FS client name, and secretfile (required, ex: "name=admin,secretfile=/etc/ceph/admin.secret")']
]

DRIVER_INFO = {
    'name': 'CephFS VHD',
    'description': 'SR plugin which stores disks as VHD files on a CephFS storage',
    'vendor': 'Vates SAS',
    'copyright': '(C) 2020 Vates SAS',
    'driver_version': '1.0',
    'required_api_version': '1.0',
    'capabilities': CAPABILITIES,
    'configuration': CONFIGURATION
}

DRIVER_CONFIG = {"ATTACH_FROM_CONFIG_WITH_TAPDISK": True}

# The mountpoint for the directory when performing an sr_probe.  All probes
# are guaranteed to be serialised by xapi, so this single mountpoint is fine.
PROBE_MOUNTPOINT = os.path.join(SR.MOUNT_BASE, "probe")


class CephFSException(Exception):
    def __init__(self, errstr):
        self.errstr = errstr


# mountpoint = /var/run/sr-mount/CephFS/uuid
# linkpath = mountpoint/uuid - path to SR directory on share
# path = /var/run/sr-mount/uuid - symlink to SR directory on share
class CephFSSR(FileSR.FileSR):
    """Ceph file-based storage repository"""

    DRIVER_TYPE = 'cephfs'

    @override
    @staticmethod
    def handles(sr_type) -> bool:
        # fudge, because the parent class (FileSR) checks for smb to alter its behavior
        return sr_type == CephFSSR.DRIVER_TYPE or sr_type == 'smb'

    @override
    def load(self, sr_uuid) -> None:
        if not self._is_ceph_available():
            raise xs_errors.XenError(
                'SRUnavailable',
                opterr='ceph is not installed'
            )

        self.ops_exclusive = FileSR.OPS_EXCLUSIVE
        self.lock = lock.Lock(lock.LOCK_TYPE_SR, self.uuid)
        self.sr_vditype = SR.DEFAULT_TAP
        self.driver_config = DRIVER_CONFIG
        if 'server' not in self.dconf:
            raise xs_errors.XenError('ConfigServerMissing')
        self.remoteserver = self.dconf['server']
        self.remotepath = self.dconf['serverpath']
        # if serverport is not specified, use default 6789
        if 'serverport' not in self.dconf:
            self.remoteport = "6789"
        else:
            self.remoteport = self.dconf['serverport']
        if self.sr_ref and self.session is not None:
            self.sm_config = self.session.xenapi.SR.get_sm_config(self.sr_ref)
        else:
            self.sm_config = self.srcmd.params.get('sr_sm_config') or {}
        self.mountpoint = os.path.join(SR.MOUNT_BASE, 'CephFS', sr_uuid)
        self.linkpath = os.path.join(self.mountpoint, sr_uuid or "")
        self.path = os.path.join(SR.MOUNT_BASE, sr_uuid)
        self._check_o_direct()

    def checkmount(self):
        return util.ioretry(lambda: ((util.pathexists(self.mountpoint) and
                                      util.ismount(self.mountpoint)) and
                                     util.pathexists(self.path)))

    def mount(self, mountpoint=None):
        """Mount the remote ceph export at 'mountpoint'"""
        if mountpoint is None:
            mountpoint = self.mountpoint
        elif not util.is_string(mountpoint) or mountpoint == "":
            raise CephFSException("mountpoint not a string object")

        try:
            if not util.ioretry(lambda: util.isdir(mountpoint)):
                util.ioretry(lambda: util.makedirs(mountpoint))
        except util.CommandException as inst:
            raise CephFSException("Failed to make directory: code is %d" % inst.code)

        try:
            options = []
            if 'options' in self.dconf:
                options.append(self.dconf['options'])
            if options:
                options = ['-o', ','.join(options)]
            acc = []
            for server in self.remoteserver.split(','):
                try:
                    addr_info = socket.getaddrinfo(server, 0)[0]
                except Exception:
                    continue

                acc.append('[' + server + ']' if addr_info[0] == socket.AF_INET6 else server)

            remoteserver = ','.join(acc)
            command = ["mount", '-t', 'ceph', remoteserver + ":" + self.remoteport + ":" + self.remotepath, mountpoint] + options
            util.ioretry(lambda: util.pread(command), errlist=[errno.EPIPE, errno.EIO], maxretry=2, nofail=True)
        except util.CommandException as inst:
            syslog(_syslog.LOG_ERR, 'CephFS mount failed ' + inst.__str__())
            raise CephFSException("mount failed with return code %d" % inst.code)

        # Sanity check to ensure that the user has at least RO access to the
        # mounted share. Windows sharing and security settings can be tricky.
        try:
            util.listdir(mountpoint)
        except util.CommandException:
            try:
                self.unmount(mountpoint, True)
            except CephFSException:
                util.logException('CephFSSR.unmount()')
            raise CephFSException("Permission denied. Please check user privileges.")

    def unmount(self, mountpoint, rmmountpoint):
        try:
            util.pread(["umount", mountpoint])
        except util.CommandException as inst:
            raise CephFSException("umount failed with return code %d" % inst.code)
        if rmmountpoint:
            try:
                os.rmdir(mountpoint)
            except OSError as inst:
                raise CephFSException("rmdir failed with error '%s'" % inst.strerror)

    @override
    def attach(self, sr_uuid) -> None:
        if not self.checkmount():
            try:
                self.mount()
                os.symlink(self.linkpath, self.path)
            except CephFSException as exc:
                raise xs_errors.SROSError(12, exc.errstr)
        self.attached = True

    @override
    def probe(self) -> str:
        try:
            self.mount(PROBE_MOUNTPOINT)
            sr_list = filter(util.match_uuid, util.listdir(PROBE_MOUNTPOINT))
            self.unmount(PROBE_MOUNTPOINT, True)
        except (util.CommandException, xs_errors.XenError):
            raise
        # Create a dictionary from the SR uuids to feed SRtoXML()
        return util.SRtoXML({sr_uuid: {} for sr_uuid in sr_list})

    @override
    def detach(self, sr_uuid) -> None:
        if not self.checkmount():
            return
        util.SMlog("Aborting GC/coalesce")
        cleanup.abort(self.uuid)
        # Change directory to avoid unmount conflicts
        os.chdir(SR.MOUNT_BASE)
        self.unmount(self.mountpoint, True)
        os.unlink(self.path)
        self.attached = False

    @override
    def create(self, sr_uuid, size) -> None:
        if self.checkmount():
            raise xs_errors.SROSError(113, 'CephFS mount point already attached')

        try:
            self.mount()
        except CephFSException as exc:
            # noinspection PyBroadException
            try:
                os.rmdir(self.mountpoint)
            except:
                # we have no recovery strategy
                pass
            raise xs_errors.SROSError(111, "CephFS mount error [opterr=%s]" % exc.errstr)

        if util.ioretry(lambda: util.pathexists(self.linkpath)):
            if len(util.ioretry(lambda: util.listdir(self.linkpath))) != 0:
                self.detach(sr_uuid)
                raise xs_errors.XenError('SRExists')
        else:
            try:
                util.ioretry(lambda: util.makedirs(self.linkpath))
                os.symlink(self.linkpath, self.path)
            except util.CommandException as inst:
                if inst.code != errno.EEXIST:
                    try:
                        self.unmount(self.mountpoint, True)
                    except CephFSException:
                        util.logException('CephFSSR.unmount()')
                    raise xs_errors.SROSError(116,
                                       "Failed to create CephFS SR. remote directory creation error: {}".format(
                                           os.strerror(inst.code)))
        self.detach(sr_uuid)

    @override
    def delete(self, sr_uuid) -> None:
        # try to remove/delete non VDI contents first
        super(CephFSSR, self).delete(sr_uuid)
        try:
            if self.checkmount():
                self.detach(sr_uuid)
            self.mount()
            if util.ioretry(lambda: util.pathexists(self.linkpath)):
                util.ioretry(lambda: os.rmdir(self.linkpath))
            util.SMlog(str(self.unmount(self.mountpoint, True)))
        except util.CommandException as inst:
            self.detach(sr_uuid)
            if inst.code != errno.ENOENT:
                raise xs_errors.SROSError(114, "Failed to remove CephFS mount point")

    @override
    def vdi(self, uuid, loadLocked=False) -> VDI.VDI:
        return CephFSFileVDI(self, uuid)

    @staticmethod
    def _is_ceph_available():
        return util.find_executable('ceph')

class CephFSFileVDI(FileSR.FileVDI):
    @override
    def attach(self, sr_uuid, vdi_uuid) -> str:
        if not hasattr(self, 'xenstore_data'):
            self.xenstore_data = {}

        self.xenstore_data['storage-type'] = CephFSSR.DRIVER_TYPE

        return super(CephFSFileVDI, self).attach(sr_uuid, vdi_uuid)

    @override
    def generate_config(self, sr_uuid, vdi_uuid) -> str:
        util.SMlog("SMBFileVDI.generate_config")
        if not util.pathexists(self.path):
            raise xs_errors.XenError('VDIUnavailable')
        resp = {'device_config': self.sr.dconf,
                'sr_uuid': sr_uuid,
                'vdi_uuid': vdi_uuid,
                'sr_sm_config': self.sr.sm_config,
                'command': 'vdi_attach_from_config'}
        # Return the 'config' encoded within a normal XMLRPC response so that
        # we can use the regular response/error parsing code.
        config = xmlrpc.client.dumps(tuple([resp]), "vdi_attach_from_config")
        return xmlrpc.client.dumps((config,), "", True)

    @override
    def attach_from_config(self, sr_uuid, vdi_uuid) -> str:
        try:
            if not util.pathexists(self.sr.path):
                return self.sr.attach(sr_uuid)
        except:
            util.logException("SMBFileVDI.attach_from_config")
            raise xs_errors.XenError('SRUnavailable',
                                     opterr='Unable to attach from config')
        return ''

if __name__ == '__main__':
    SRCommand.run(CephFSSR, DRIVER_INFO)
else:
    SR.registerSR(CephFSSR)
