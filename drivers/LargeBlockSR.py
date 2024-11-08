#!/usr/bin/env python3
#
# Copyright (C) 2024  Vates SAS - damien.thenot@vates.tech
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
from SR import deviceCheck
import SRCommand
import EXTSR
import util
import xs_errors
import os
import re
import lvutil

CAPABILITIES = ["SR_PROBE", "SR_UPDATE", "SR_SUPPORTS_LOCAL_CACHING",
                "VDI_CREATE", "VDI_DELETE", "VDI_ATTACH", "VDI_DETACH",
                "VDI_UPDATE", "VDI_CLONE", "VDI_SNAPSHOT", "VDI_RESIZE", "VDI_MIRROR",
                "VDI_GENERATE_CONFIG",
                "VDI_RESET_ON_BOOT/2", "ATOMIC_PAUSE", "VDI_CONFIG_CBT",
                "VDI_ACTIVATE", "VDI_DEACTIVATE", "THIN_PROVISIONING", "VDI_READ_CACHING"]

CONFIGURATION = [['device', 'local device path (required) (e.g. /dev/sda3)']]

DRIVER_INFO = {
    'name': 'Large Block SR',
    'description': 'SR plugin which emulates a 512 bytes disk on top of a 4KiB device then create a EXT SR',
    'vendor': 'Vates',
    'copyright': '(C) 2024 Vates',
    'driver_version': '1.0',
    'required_api_version': '1.0',
    'capabilities': CAPABILITIES,
    'configuration': CONFIGURATION
}

LARGEBLOCK_PREFIX = "XSLocalLargeBlock-"

class LargeBlockSR(EXTSR.EXTSR):
    """Emulating 512b drives for EXT storage repository"""

    DRIVER_TYPE = "largeblock"
    LOOP_SECTOR_SIZE = 512

    @override
    @staticmethod
    def handles(srtype) -> bool:
        return srtype == LargeBlockSR.DRIVER_TYPE

    @override
    def load(self, sr_uuid) -> None:
        super(LargeBlockSR, self).load(sr_uuid)
        self.is_deleting = False
        self.vgname = LARGEBLOCK_PREFIX + sr_uuid
        self.remotepath = os.path.join("/dev", self.vgname, sr_uuid)

    @override
    def attach(self, sr_uuid) -> None:
        if not self.is_deleting:
            vg_device = self._get_device()
            self.dconf["device"] = ",".join(vg_device)
            self._create_emulated_device()
            if not self._is_vg_connection_correct(): # Check if we need to redo the connection by parsing `vgs -o vg_name,devices self.vgname`
                self._redo_vg_connection() # Call redo VG connection to connect it correctly to the loop device instead of the real 4KiB block device
        super(LargeBlockSR, self).attach(sr_uuid)

    @override
    def detach(self, sr_uuid) -> None:
        if not self.is_deleting:
            vg_device = self._get_device()
            self.dconf["device"] = ",".join(vg_device)
        super(LargeBlockSR, self).detach(sr_uuid)
        if not self.is_deleting:
            self._destroy_emulated_device()

    @override
    @deviceCheck
    def create(self, sr_uuid, size) -> None:
        base_devices = self.dconf["device"].split(",")
        if len(base_devices) > 1:
            raise xs_errors.XenError("ConfigDeviceInvalid", opterr="Multiple devices configuration is not supported")

        for dev in base_devices:
            logical_blocksize = util.pread2(["blockdev", "--getss", dev]).strip()
            if logical_blocksize == "512":
                raise xs_errors.XenError("LargeBlockIncorrectBlocksize", opterr="The logical blocksize of the device {} is compatible with normal SR types".format(dev))

        try:
            self._create_emulated_device()
            super(LargeBlockSR, self).create(sr_uuid, size)
        finally:
            self._destroy_emulated_device(base_devices)

    @override
    def delete(self, sr_uuid) -> None:
        base_devices = self._get_device()
        self.dconf["device"] = ",".join(self._get_loopdev_from_device(base_devices))

        self.is_deleting = True
        try:
            super(LargeBlockSR, self).delete(sr_uuid)
        except xs_errors.SROSError:
            # In case, the lvremove doesn't like the loop device, it will throw an error.
            # We need to remove the device ourselves using the real device in this case.
            for dev in base_devices:
                util.pread2(["pvremove", dev])
        finally:
            self._destroy_emulated_device(base_devices)
            self.is_deleting = False

    @override
    @deviceCheck
    def probe(self) -> str:
        # We override EXTSR.probe because it uses EXT_PREFIX in this call
        return lvutil.srlist_toxml(
            lvutil.scan_srlist(LARGEBLOCK_PREFIX, self.dconf['device']),
            LARGEBLOCK_PREFIX
        )

    def _create_loopdev(self, dev, emulated_path):
        cmd = ["losetup", "-f", "-v", "--show", "--sector-size", str(self.LOOP_SECTOR_SIZE), dev]
        loopdev = util.pread2(cmd).rstrip()

        if os.path.exists(emulated_path) and os.path.islink(emulated_path):
            os.unlink(emulated_path)

        try:
            os.symlink(loopdev, emulated_path)
        except OSError:
            raise xs_errors.XenError("LargeBlockSymlinkExist", opterr="Symlink {} couldn't be created".format(emulated_path))

    def _delete_loopdev(self, dev, emulated_path):
            if os.path.exists(emulated_path) and os.path.islink(emulated_path):
                os.unlink(emulated_path)

            # The backing file isn't a symlink if given by ID in device-config but the real device
            dev = os.path.realpath(dev)
            loopdevs = self._get_loopdev_from_device(dev)

            if loopdevs != None:
                try:
                    for lp in loopdevs:
                        cmd = ["losetup", "-d", lp] # Remove the loop device
                        util.pread2(cmd)
                except xs_errors.SROSError:
                    util.SMlog("Couldn't removed losetup devices: {}".format(loopdevs))
            else:
                xs_errors.XenError("LargeBlockNoLosetup", opterr="Couldn't find loop device for {}".format(dev))

    @staticmethod
    def _get_loopdev_from_device(device):
        lpdevs = []
        output = util.pread2(["losetup", "--list"]).rstrip()
        if output:
            for line in output.split("\n"):
                line = line.split()
                loopdev = line[0]
                dev = line[5].strip()
                if dev in device:
                    lpdevs.append(loopdev)
        return lpdevs

    @staticmethod
    def _get_device_from_loopdev(loopdevs):
        devices = []
        output = util.pread2(["losetup", "--list"]).rstrip()
        if output:
            for line in output.split("\n"):
                line = line.split()
                lpdev = line[0]
                dev = line[5]
                if lpdev in loopdevs:
                    devices.append(dev)
        return devices

    def _get_device_from_vg(self):
        devices = []
        output = util.pread2(["vgs", "--noheadings", "-o", "vg_name,devices", self.vgname]).splitlines()
        for line in output:
            line = line.split()
            dev = line[1].split("(")[0]
            if os.path.islink(dev):
                dev = os.path.realpath(dev)
            devices.append(dev)
        return devices

    def _get_device(self):
        vg_device = self._get_device_from_vg()
        for dev in vg_device:
            if re.match(r"(.*\.512)|(/dev/loop[0-9]+)", dev):
                lpdev = os.path.realpath(dev)
                realdev = self._get_device_from_loopdev(lpdev)[0]
                vg_device.remove(dev)
                vg_device.append(realdev)

        return vg_device

    def _is_vg_connection_correct(self):
        output = util.pread2(["vgs", "--noheadings", "-o", "vg_name,devices", self.vgname]).split()
        output[1] = output[1].split("(")[0]
        return bool(re.match(r"(.*\.512)|(/dev/loop[0-9]+)", output[1]))

    def _redo_vg_connection(self):
        """
        In case of using a LargeBlockSR, the LVM scan at boot will find the LogicalVolume on the real block device.
        And when the PBD is connecting, it will mount from the original device instead of the loop device since LVM prefers real devices it has seen first.
        The PBD plug will succeed but then the SR will be accessed through the 4KiB device, returning to the erroneous behaviour on 4KiB device.
        VM won't be able to run because vhd-util will fail to scan the VDI.
        This function force the LogicalVolume to be mounted on top of our emulation layer by disabling the VolumeGroup and re-enabling while applying a filter.
        """

        util.SMlog("Reconnecting VG {} to use emulated device".format(self.vgname))
        try:
            lvutil.setActiveVG(self.vgname, False)
            lvutil.setActiveVG(self.vgname, True, config="devices{ global_filter = [ \"r|^/dev/nvme.*|\", \"a|/dev/loop.*|\" ] }")
        except util.CommandException as e:
            xs_errors.XenError("LargeBlockVGReconnectFailed", opterr="Failed to reconnect the VolumeGroup {}, error: {}".format(self.vgname, e))


    @classmethod
    def _get_emulated_device_path(cls, dev):
        return "{dev}.{bs}".format(dev=dev, bs=cls.LOOP_SECTOR_SIZE)

    def _create_emulated_device(self):
        base_devices = self.dconf["device"].split(",")
        emulated_devices = []
        for dev in base_devices:
            emulated_path = self._get_emulated_device_path(dev)
            self._create_loopdev(dev, emulated_path)
            emulated_devices.append(emulated_path)

        emulated_devices = ",".join(emulated_devices)
        self.dconf["device"] = emulated_devices

    def _destroy_emulated_device(self, devices=None):
        if devices is None:
            devices = self.dconf["device"].split(",")

        for dev in devices:
            emulated_path = self._get_emulated_device_path(dev)
            self._delete_loopdev(dev, emulated_path)

if __name__ == '__main__':
    SRCommand.run(LargeBlockSR, DRIVER_INFO)
else:
    SR.registerSR(LargeBlockSR)
