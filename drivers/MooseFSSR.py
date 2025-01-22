#!/usr/bin/env python3
#
# Original work copyright (C) Citrix systems
# Modified work copyright (C) Tappest sp. z o.o., Vates SAS and XCP-ng community
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
# MooseFSSR: Based on CEPHFSSR and FileSR, mounts MooseFS share

from sm_typing import override

import errno
import os
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
import xs_errors

CAPABILITIES = ["SR_PROBE", "SR_UPDATE",
                "VDI_CREATE", "VDI_DELETE", "VDI_ATTACH", "VDI_DETACH",
                "VDI_UPDATE", "VDI_CLONE", "VDI_SNAPSHOT", "VDI_RESIZE", "VDI_MIRROR",
                "VDI_GENERATE_CONFIG",
                "VDI_RESET_ON_BOOT/2", "ATOMIC_PAUSE"]

CONFIGURATION = [
    ['masterhost', 'MooseFS Master Server hostname or IP address (required, e.g.: "mfsmaster.local.lan" or "10.10.10.1")'],
    ['masterport', 'MooseFS Master Server port, default: 9421'],
    ['rootpath', 'MooseFS path (required, e.g.: "/")'],
    ['options', 'MooseFS Client additional options (e.g.: "mfspassword=PASSWORD,mfstimeout=300")']
]

DRIVER_INFO = {
    'name': 'MooseFS VHD and QCOW2',
    'description': 'SR plugin which stores disks as VHD and QCOW2 files on a MooseFS storage',
    'vendor': 'Tappest sp. z o.o.',
    'copyright': '(C) 2021 Tappest sp. z o.o.',
    'driver_version': '1.0',
    'required_api_version': '1.0',
    'capabilities': CAPABILITIES,
    'configuration': CONFIGURATION
}

DRIVER_CONFIG = {"ATTACH_FROM_CONFIG_WITH_TAPDISK": True}

# The mountpoint for the directory when performing an sr_probe.  All probes
# are guaranteed to be serialised by xapi, so this single mountpoint is fine.
PROBE_MOUNTPOINT = os.path.join(SR.MOUNT_BASE, "probe")


class MooseFSException(Exception):
    def __init__(self, errstr):
        self.errstr = errstr


class MooseFSSR(FileSR.FileSR):
    """MooseFS file-based storage"""

    DRIVER_TYPE = 'moosefs'

    @override
    @staticmethod
    def handles(sr_type) -> bool:
        # fudge, because the parent class (FileSR) checks for smb to alter its behavior
        return sr_type == MooseFSSR.DRIVER_TYPE or sr_type == 'smb'

    @override
    def load(self, sr_uuid) -> None:
        if not self._is_moosefs_available():
            raise xs_errors.XenError(
                'SRUnavailable',
                opterr='MooseFS Client is not installed!'
            )

        self.ops_exclusive = FileSR.OPS_EXCLUSIVE
        self.lock = lock.Lock(lock.LOCK_TYPE_SR, self.uuid)
        self.sr_vditype = SR.DEFAULT_TAP
        self.driver_config = DRIVER_CONFIG
        if 'masterhost' not in self.dconf:
            raise xs_errors.XenError('ConfigServerMissing')
        self.remoteserver = self.dconf['masterhost']
        self.rootpath = self.dconf['rootpath']
        self.remotepath = self.rootpath
        # if masterport is not specified, use default: 9421
        if 'masterport' not in self.dconf:
            self.remoteport = "9421"
        else:
            self.remoteport = self.dconf['masterport']
        if self.sr_ref and self.session is not None:
            self.sm_config = self.session.xenapi.SR.get_sm_config(self.sr_ref)
        else:
            self.sm_config = self.srcmd.params.get('sr_sm_config') or {}

        if self.srcmd.cmd != 'sr_create':
            self.subdir = util.strtobool(self.sm_config.get('subdir'))
            if self.subdir:
                self.remotepath = os.path.join(self.remotepath, sr_uuid)

        self.attached = False
        self.path = os.path.join(SR.MOUNT_BASE, sr_uuid)
        self.mountpoint = self.path
        self.linkpath = self.path
        self._check_o_direct()

    def checkmount(self):
        return util.ioretry(lambda: ((util.pathexists(self.mountpoint) and
                                      util.ismount(self.mountpoint))))

    def mount(self, mountpoint=None):
        """Mount MooseFS share at 'mountpoint'"""
        if mountpoint is None:
            mountpoint = self.mountpoint
        elif not util.is_string(mountpoint) or mountpoint == "":
            raise MooseFSException("Mountpoint is not a string object")

        try:
            if not util.ioretry(lambda: util.isdir(mountpoint)):
                util.ioretry(lambda: util.makedirs(mountpoint))
        except util.CommandException as inst:
            raise MooseFSException("Failed to make directory: code is %d" % inst.code)

        try:
            options = []
            if 'options' in self.dconf:
                options.append(self.dconf['options'])
            if options:
                options = ['-o', ','.join(options)]
            remote = '{}:{}:{}'.format(
                self.remoteserver, self.remoteport, self.remotepath
            )
            command = ["mount", '-t', 'moosefs', remote, mountpoint] + options
            util.ioretry(lambda: util.pread(command), errlist=[errno.EPIPE, errno.EIO], maxretry=2, nofail=True)
        except util.CommandException as inst:
            syslog(_syslog.LOG_ERR, 'MooseFS mount failed ' + inst.__str__())
            raise MooseFSException("Mount failed with return code %d" % inst.code)

        # Sanity check to ensure that the user has at least RO access to the
        # mounted share. Windows sharing and security settings can be tricky.
        try:
            util.listdir(mountpoint)
        except util.CommandException:
            try:
                self.unmount(mountpoint, True)
            except MooseFSException:
                util.logException('MooseFSSR.unmount()')
            raise MooseFSException("Permission denied. Please check user privileges.")

    def unmount(self, mountpoint, rmmountpoint):
        try:
            util.pread(["umount", mountpoint])
        except util.CommandException as inst:
            raise MooseFSException("Command umount failed with return code %d" % inst.code)
        if rmmountpoint:
            try:
                os.rmdir(mountpoint)
            except OSError as inst:
                raise MooseFSException("Command rmdir failed with error '%s'" % inst.strerror)

    @override
    def attach(self, sr_uuid) -> None:
        if not self.checkmount():
            try:
                self.mount()
            except MooseFSException as exc:
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
        cleanup.abort(sr_uuid)
        # Change directory to avoid unmount conflicts
        os.chdir(SR.MOUNT_BASE)
        self.unmount(self.mountpoint, True)
        self.attached = False

    @override
    def create(self, sr_uuid, size) -> None:
        if self.checkmount():
            raise xs_errors.SROSError(113, 'MooseFS mount point already attached')

        assert self.remotepath == self.rootpath
        try:
            self.mount()
        except MooseFSException as exc:
            # noinspection PyBroadException
            try:
                os.rmdir(self.mountpoint)
            except:
                # we have no recovery strategy
                pass
            raise xs_errors.SROSError(111, "MooseFS mount error [opterr=%s]" % exc.errstr)

        try:
            self.subdir = self.sm_config.get('subdir')
            if self.subdir is None:
                self.subdir = True
            else:
                self.subdir = util.strtobool(self.subdir)

            self.sm_config['subdir'] = str(self.subdir)
            self.session.xenapi.SR.set_sm_config(self.sr_ref, self.sm_config)

            if not self.subdir:
                return

            subdir = os.path.join(self.mountpoint, sr_uuid)
            if util.ioretry(lambda: util.pathexists(subdir)):
                if util.ioretry(lambda: util.isdir(subdir)):
                    raise xs_errors.XenError('SRExists')
            else:
                try:
                    util.ioretry(lambda: util.makedirs(subdir))
                except util.CommandException as e:
                    if e.code != errno.EEXIST:
                        raise MooseFSException(
                            'Failed to create SR subdir: {}'.format(e)
                        )
        finally:
            self.detach(sr_uuid)

    @override
    def delete(self, sr_uuid) -> None:
        # try to remove/delete non VDI contents first
        super(MooseFSSR, self).delete(sr_uuid)
        try:
            if self.checkmount():
                self.detach(sr_uuid)

            if self.subdir:
                # Mount using rootpath (<root>) instead of <root>/<sr_uuid>.
                self.remotepath = self.rootpath
                self.attach(sr_uuid)
                subdir = os.path.join(self.mountpoint, sr_uuid)
                if util.ioretry(lambda: util.pathexists(subdir)):
                    util.ioretry(lambda: os.rmdir(subdir))
                self.detach(sr_uuid)
        except util.CommandException as inst:
            self.detach(sr_uuid)
            if inst.code != errno.ENOENT:
                raise xs_errors.SROSError(114, "Failed to remove MooseFS mount point")

    @override
    def vdi(self, uuid, loadLocked=False) -> VDI.VDI:
        return MooseFSFileVDI(self, uuid)

    @staticmethod
    def _is_moosefs_available():
        return util.find_executable('mfsmount')

class MooseFSFileVDI(FileSR.FileVDI):
    @override
    def attach(self, sr_uuid, vdi_uuid) -> str:
        if not hasattr(self, 'xenstore_data'):
            self.xenstore_data = {}

        self.xenstore_data['storage-type'] = MooseFSSR.DRIVER_TYPE

        return super(MooseFSFileVDI, self).attach(sr_uuid, vdi_uuid)

    @override
    def generate_config(self, sr_uuid, vdi_uuid) -> str:
        util.SMlog("MooseFSFileVDI.generate_config")
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
            util.logException("MooseFSFileVDI.attach_from_config")
            raise xs_errors.XenError('SRUnavailable',
                                     opterr='Unable to attach from config')
        return ''

if __name__ == '__main__':
    SRCommand.run(MooseFSSR, DRIVER_INFO)
else:
    SR.registerSR(MooseFSSR)
