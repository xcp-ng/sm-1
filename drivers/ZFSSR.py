#!/usr/bin/env python3
#
# Copyright (C) 2020  Vates SAS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from sm_typing import override

import SR
import SRCommand
import VDI

import FileSR

import util
import xs_errors

CAPABILITIES = [
    'SR_UPDATE',
    'VDI_CREATE',
    'VDI_DELETE',
    'VDI_ATTACH',
    'VDI_DETACH',
    'VDI_CLONE',
    'VDI_SNAPSHOT',
    'VDI_RESIZE',
    'VDI_MIRROR',
    'VDI_GENERATE_CONFIG',
    'ATOMIC_PAUSE',
    'VDI_CONFIG_CBT',
    'VDI_ACTIVATE',
    'VDI_DEACTIVATE',
    'THIN_PROVISIONING'
]

CONFIGURATION = [
    ['location', 'local ZFS directory path (required)']
]

DRIVER_INFO = {
    'name': 'Local ZFS VHD',
    'description':
        'SR plugin which represents disks as VHD files stored on a ZFS disk',
    'vendor': 'Vates SAS',
    'copyright': '(C) 2020 Vates SAS',
    'driver_version': '1.0',
    'required_api_version': '1.0',
    'capabilities': CAPABILITIES,
    'configuration': CONFIGURATION
}


def is_zfs_available():
    return util.find_executable('zfs') and \
        util.pathexists('/sys/module/zfs/initstate')


def is_zfs_path(path):
    cmd = ['findmnt', '-o', 'FSTYPE', '-n', path]
    fs_type = util.pread2(cmd).split('\n')[0]
    return fs_type == 'zfs'


class ZFSSR(FileSR.FileSR):
    DRIVER_TYPE = 'zfs'

    @override
    @staticmethod
    def handles(type) -> bool:
        return type == ZFSSR.DRIVER_TYPE

    @override
    def load(self, sr_uuid) -> None:
        if not is_zfs_available():
            raise xs_errors.XenError(
                'SRUnavailable',
                opterr='zfs is not installed or module is not loaded'
            )
        return super(ZFSSR, self).load(sr_uuid)

    @override
    def create(self, sr_uuid, size) -> None:
        if not is_zfs_path(self.remotepath):
            raise xs_errors.XenError(
                'ZFSSRCreate',
                opterr='Cannot create SR, path is not a ZFS mountpoint'
            )
        return super(ZFSSR, self).create(sr_uuid, size)

    @override
    def delete(self, sr_uuid) -> None:
        if not self._checkmount():
            raise xs_errors.XenError(
                'ZFSSRDelete',
                opterr='ZFS SR is not mounted or uses an invalid FS type'
            )
        return super(ZFSSR, self).delete(sr_uuid)

    @override
    def attach(self, sr_uuid) -> None:
        if not is_zfs_path(self.remotepath):
            raise xs_errors.XenError(
                'SRUnavailable',
                opterr='Invalid ZFS path'
            )
        super(ZFSSR, self).attach(sr_uuid)

    @override
    def detach(self, sr_uuid) -> None:
        return super(ZFSSR, self).detach(sr_uuid)

    @override
    def vdi(self, uuid, loadLocked=False) -> VDI.VDI:
        return ZFSFileVDI(self, uuid)

    # Ensure _checkmount is overridden to prevent bad behaviors in FileSR.
    @override
    def _checkmount(self) -> bool:
        return super(ZFSSR, self)._checkmount() and \
            is_zfs_path(self.remotepath)


class ZFSFileVDI(FileSR.FileVDI):
    @override
    def attach(self, sr_uuid, vdi_uuid) -> str:
        if not hasattr(self, 'xenstore_data'):
            self.xenstore_data = {}

        self.xenstore_data['storage-type'] = ZFSSR.DRIVER_TYPE

        return super(ZFSFileVDI, self).attach(sr_uuid, vdi_uuid)


if __name__ == '__main__':
    SRCommand.run(ZFSSR, DRIVER_INFO)
else:
    SR.registerSR(ZFSSR)
