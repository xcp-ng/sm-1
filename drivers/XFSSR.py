#!/usr/bin/python3
#
# Original work copyright (C) Citrix Systems Inc.
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
# XFSSR: Based on local-file storage repository, mounts xfs partition

from sm_typing import override

import SR
from SR import deviceCheck
import SRCommand
import VDI
import FileSR
import util
import lvutil
import scsiutil

import lock
import os
import xs_errors
from constants import EXT_PREFIX

CAPABILITIES = ["SR_PROBE", "SR_UPDATE", "SR_SUPPORTS_LOCAL_CACHING", \
                "VDI_CREATE", "VDI_DELETE", "VDI_ATTACH", "VDI_DETACH", \
                "VDI_UPDATE", "VDI_CLONE", "VDI_SNAPSHOT", "VDI_RESIZE", "VDI_MIRROR", \
                "VDI_GENERATE_CONFIG", \
                "VDI_RESET_ON_BOOT/2", "ATOMIC_PAUSE", "VDI_CONFIG_CBT",
                "VDI_ACTIVATE", "VDI_DEACTIVATE", "THIN_PROVISIONING", "VDI_READ_CACHING"]

CONFIGURATION = [['device', 'local device path (required) (e.g. /dev/sda3)']]

DRIVER_INFO = {
    'name': 'Local XFS VHD and QCOW2',
    'description': 'SR plugin which represents disks as VHD and QCOW2 files stored on a local XFS filesystem, created inside an LVM volume',
    'vendor': 'Vates SAS',
    'copyright': '(C) 2019 Vates SAS',
    'driver_version': '1.0',
    'required_api_version': '1.0',
    'capabilities': CAPABILITIES,
    'configuration': CONFIGURATION
    }

DRIVER_CONFIG = {"ATTACH_FROM_CONFIG_WITH_TAPDISK": True}


class XFSSR(FileSR.FileSR):
    """XFS Local file storage repository"""

    DRIVER_TYPE = 'xfs'

    @override
    @staticmethod
    def handles(srtype) -> bool:
        return srtype == XFSSR.DRIVER_TYPE

    @override
    def load(self, sr_uuid) -> None:
        if not self._is_xfs_available():
            raise xs_errors.XenError(
                'SRUnavailable',
                opterr='xfsprogs is not installed'
            )

        self.ops_exclusive = FileSR.OPS_EXCLUSIVE
        self.lock = lock.Lock(lock.LOCK_TYPE_SR, self.uuid)
        self.sr_vditype = SR.DEFAULT_TAP

        self.path = os.path.join(SR.MOUNT_BASE, sr_uuid)
        self.vgname = EXT_PREFIX + sr_uuid
        self.remotepath = os.path.join("/dev", self.vgname, sr_uuid)
        self.attached = self._checkmount()
        self.driver_config = DRIVER_CONFIG

    @override
    def delete(self, sr_uuid) -> None:
        super(XFSSR, self).delete(sr_uuid)

        # Check PVs match VG
        try:
            for dev in self.dconf['device'].split(','):
                cmd = ["pvs", dev]
                txt = util.pread2(cmd)
                if txt.find(self.vgname) == -1:
                    raise xs_errors.XenError('VolNotFound', \
                          opterr='volume is %s' % self.vgname)
        except util.CommandException as inst:
            raise xs_errors.XenError('PVSfailed', \
                  opterr='error is %d' % inst.code)

        # Remove LV, VG and pv
        try:
            cmd = ["lvremove", "-f", self.remotepath]
            util.pread2(cmd)

            cmd = ["vgremove", self.vgname]
            util.pread2(cmd)

            for dev in self.dconf['device'].split(','):
                cmd = ["pvremove", dev]
                util.pread2(cmd)
        except util.CommandException as inst:
            raise xs_errors.XenError('LVMDelete', \
                  opterr='errno is %d' % inst.code)

    @override
    def attach(self, sr_uuid) -> None:
        if not self._checkmount():
            try:
                #Activate LV
                cmd = ['lvchange', '-ay', self.remotepath]
                util.pread2(cmd)

                # make a mountpoint:
                if not os.path.isdir(self.path):
                    os.makedirs(self.path)
            except util.CommandException as inst:
                raise xs_errors.XenError('LVMMount', \
                      opterr='Unable to activate LV. Errno is %d' % inst.code)

            try:
                util.pread(["fsck", "-a", self.remotepath])
            except util.CommandException as inst:
                if inst.code == 1:
                    util.SMlog("FSCK detected and corrected FS errors. Not fatal.")
                else:
                    raise xs_errors.XenError('LVMMount', \
                         opterr='FSCK failed on %s. Errno is %d' % (self.remotepath, inst.code))

            try:
                util.pread(["mount", self.remotepath, self.path])
            except util.CommandException as inst:
                raise xs_errors.XenError('LVMMount', \
                      opterr='Failed to mount FS. Errno is %d' % inst.code)

        self.attached = True

        #Update SCSIid string
        scsiutil.add_serial_record(self.session, self.sr_ref, \
                scsiutil.devlist_to_serialstring(self.dconf['device'].split(',')))

        # Set the block scheduler
        for dev in self.dconf['device'].split(','):
            self.block_setscheduler(dev)

    @override
    def detach(self, sr_uuid) -> None:
        super(XFSSR, self).detach(sr_uuid)
        try:
            # deactivate SR
            cmd = ["lvchange", "-an", self.remotepath]
            util.pread2(cmd)
        except util.CommandException as inst:
            raise xs_errors.XenError('LVMUnMount', \
                  opterr='lvm -an failed errno is %d' % inst.code)

    @override
    @deviceCheck
    def probe(self) -> str:
        return lvutil.srlist_toxml(lvutil.scan_srlist(EXT_PREFIX, self.dconf['device']),
                EXT_PREFIX)

    @override
    @deviceCheck
    def create(self, sr_uuid, size) -> None:
        if self._checkmount():
            raise xs_errors.XenError('SRExists')

        # Check none of the devices already in use by other PBDs
        if util.test_hostPBD_devs(self.session, sr_uuid, self.dconf['device']):
            raise xs_errors.XenError('SRInUse')

        # Check serial number entry in SR records
        for dev in self.dconf['device'].split(','):
            if util.test_scsiserial(self.session, dev):
                raise xs_errors.XenError('SRInUse')

        if not lvutil._checkVG(self.vgname):
            lvutil.createVG(self.dconf['device'], self.vgname)

        if lvutil._checkLV(self.remotepath):
            raise xs_errors.XenError('SRExists')

        try:
            numdevs = len(self.dconf['device'].split(','))
            cmd = ["lvcreate", "-n", sr_uuid]
            if numdevs > 1:
                lowest = -1
                for dev in self.dconf['device'].split(','):
                    stats = lvutil._getPVstats(dev)
                    if lowest < 0  or stats['freespace'] < lowest:
                        lowest = stats['freespace']
                size_mb = (lowest // (1024 * 1024)) * numdevs

                # Add stripe parameter to command
                cmd += ["-i", str(numdevs), "-I", "2048"]
            else:
                stats = lvutil._getVGstats(self.vgname)
                size_mb = stats['freespace'] // (1024 * 1024)
            assert(size_mb > 0)
            cmd += ["-L", str(size_mb), self.vgname]
            text = util.pread(cmd)

            cmd = ["lvchange", "-ay", self.remotepath]
            text = util.pread(cmd)
        except util.CommandException as inst:
            raise xs_errors.XenError('LVMCreate', \
                  opterr='lv operation, error %d' % inst.code)
        except AssertionError:
            raise xs_errors.XenError('SRNoSpace', \
                  opterr='Insufficient space in VG %s' % self.vgname)

        try:
            util.pread2(["mkfs.xfs", self.remotepath])
        except util.CommandException as inst:
            raise xs_errors.XenError('LVMFilesystem', \
                  opterr='mkfs failed error %d' % inst.code)

        #Update serial number string
        scsiutil.add_serial_record(self.session, self.sr_ref, \
                  scsiutil.devlist_to_serialstring(self.dconf['device'].split(',')))

    @override
    def vdi(self, uuid, loadLocked = False) -> VDI.VDI:
        return XFSFileVDI(self, uuid)

    @staticmethod
    def _is_xfs_available():
        return util.find_executable('mkfs.xfs')


class XFSFileVDI(FileSR.FileVDI):
    @override
    def attach(self, sr_uuid, vdi_uuid) -> str:
        if not hasattr(self, 'xenstore_data'):
            self.xenstore_data = {}

        self.xenstore_data['storage-type'] = XFSSR.DRIVER_TYPE

        return super(XFSFileVDI, self).attach(sr_uuid, vdi_uuid)


if __name__ == '__main__':
    SRCommand.run(XFSSR, DRIVER_INFO)
else:
    SR.registerSR(XFSSR)
