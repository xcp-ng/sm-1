#!/usr/bin/python3
#
# Copyright (C) Citrix Systems Inc.
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
# LVMoISCSISR: LVM over Hardware HBA LUN driver, e.g. Fibre Channel or
# hardware based iSCSI
#

from sm_typing import override

import SR
import LVMSR
import SRCommand
import VDI
import lvutil
import HBASR
import os
import re
import sys
import xs_errors
import xmlrpc.client
import util
import scsiutil
import mpath_cli
import glob

CAPABILITIES = ["SR_PROBE", "SR_UPDATE", "SR_METADATA", "SR_TRIM",
                "VDI_CREATE", "VDI_DELETE", "VDI_ATTACH", "VDI_DETACH",
                "VDI_GENERATE_CONFIG", "VDI_SNAPSHOT", "VDI_CLONE", "VDI_MIRROR",
                "VDI_RESIZE", "ATOMIC_PAUSE", "VDI_RESET_ON_BOOT/2",
                "VDI_UPDATE", "VDI_CONFIG_CBT", "VDI_ACTIVATE", "VDI_DEACTIVATE"]

CONFIGURATION = [['SCSIid', 'The scsi_id of the destination LUN'], \
                  ['allocation', 'Valid values are thick or thin (optional, defaults to thick)']]

DRIVER_INFO = {
    'name': 'LVM over FC',
    'description': 'SR plugin which represents disks as VHDs and QCOW2s on Logical Volumes within a Volume Group created on an HBA LUN, e.g. hardware-based iSCSI or FC support',
    'vendor': 'Citrix Systems Inc',
    'copyright': '(C) 2008 Citrix Systems Inc',
    'driver_version': '1.0',
    'required_api_version': '1.0',
    'capabilities': CAPABILITIES,
    'configuration': CONFIGURATION
    }


class LVMoHBASR(LVMSR.LVMSR):
    """LVM over HBA storage repository"""

    @override
    @staticmethod
    def handles(type) -> bool:
        if __name__ == '__main__':
            name = sys.argv[0]
        else:
            name = __name__
        if name.endswith("LVMoHBASR"):
            return type == "lvmohba"  # for the initial switch from LVM
        if type == "lvhdohba":
            return True
        return False

    @override
    def load(self, sr_uuid) -> None:
        driver = SR.driver('hba')
        self.hbasr = driver(self.original_srcmd, sr_uuid)

        # If this is a vdi command, don't initialise SR
        if not (util.isVDICommand(self.original_srcmd.cmd)):
            pbd = None
            try:
                pbd = util.find_my_pbd(self.session, self.host_ref, self.sr_ref)
            except:
                pass

            try:
                if 'SCSIid' not in self.dconf and 'device' in self.dconf:
                    # UPGRADE FROM MIAMI: add SCSIid key to device_config
                    util.SMlog("Performing upgrade from Miami")
                    if not os.path.exists(self.dconf['device']):
                        raise xs_errors.XenError('InvalidDev')
                    SCSIid = scsiutil.getSCSIid(self.dconf['device'])
                    self.dconf['SCSIid'] = SCSIid
                    del self.dconf['device']

                    if pbd is not None:
                        device_config = self.session.xenapi.PBD.get_device_config(pbd)
                        device_config['SCSIid'] = SCSIid
                        device_config['upgraded_from_miami'] = 'true'
                        del device_config['device']
                        self.session.xenapi.PBD.set_device_config(pbd, device_config)
            except:
                pass

            if 'SCSIid' not in self.dconf or not self.dconf['SCSIid']:
                print(self.hbasr.print_devs(), file=sys.stderr)
                raise xs_errors.XenError('ConfigSCSIid')

        self.SCSIid = self.dconf['SCSIid']
        super(LVMoHBASR, self).load(sr_uuid)

    @override
    def create(self, sr_uuid, size) -> None:
        self.hbasr.attach(sr_uuid)
        if self.mpath == "true":
            self.mpathmodule.refresh(self.SCSIid, 0)
        self._pathrefresh(LVMoHBASR)
        try:
            LVMSR.LVMSR.create(self, sr_uuid, size)
        finally:
            if self.mpath == "true":
                self.mpathmodule.reset(self.SCSIid, explicit_unmap=True)
                util.remove_mpathcount_field(self.session, self.host_ref, \
                                             self.sr_ref, self.SCSIid)

    @override
    def attach(self, sr_uuid) -> None:
        self.hbasr.attach(sr_uuid)
        if self.mpath == "true":
            self.mpathmodule.refresh(self.SCSIid, 0)
            # set the device mapper's I/O scheduler
            path = '/dev/disk/by-scsid/%s' % self.dconf['SCSIid']
            for file in os.listdir(path):
                self.block_setscheduler('%s/%s' % (path, file))

        self._pathrefresh(LVMoHBASR)
        if not os.path.exists(self.dconf['device']):
            # Force a rescan on the bus
            self.hbasr._init_hbadict()
            # Must re-initialise the multipath node
            if self.mpath == "true":
                self.mpathmodule.refresh(self.SCSIid, 0)
        LVMSR.LVMSR.attach(self, sr_uuid)
        self._setMultipathableFlag(SCSIid=self.SCSIid)

    @override
    def scan(self, sr_uuid) -> None:
        # During a reboot, scan is called ahead of attach, which causes the MGT
        # to point of the wrong device instead of dm-x. Running multipathing will
        # take care of this scenario.
        if self.mpath == "true":
            if 'device' not in self.dconf or not os.path.exists(self.dconf['device']):
                util.SMlog("@@@@@ path does not exists")
                self.mpathmodule.refresh(self.SCSIid, 0)
                self._pathrefresh(LVMoHBASR)
                self._setMultipathableFlag(SCSIid=self.SCSIid)
        else:
                self._pathrefresh(LVMoHBASR)
        LVMSR.LVMSR.scan(self, sr_uuid)

    @override
    def probe(self) -> str:
        if self.mpath == "true" and 'SCSIid' in self.dconf:
        # When multipathing is enabled, since we don't refcount the multipath maps,
        # we should not attempt to do the iscsi.attach/detach when the map is already present,
        # as this will remove it (which may well be in use).
            maps = []
            try:
                maps = mpath_cli.list_maps()
            except:
                pass

            if self.dconf['SCSIid'] in maps:
                raise xs_errors.XenError('SRInUse')

            self.mpathmodule.refresh(self.SCSIid, 0)

        try:
            self._pathrefresh(LVMoHBASR)
            result = LVMSR.LVMSR.probe(self)
            if self.mpath == "true":
                self.mpathmodule.reset(self.SCSIid, explicit_unmap=True)
            return result
        except:
            if self.mpath == "true":
                self.mpathmodule.reset(self.SCSIid, explicit_unmap=True)
            raise

    @override
    def detach(self, sr_uuid) -> None:
        LVMSR.LVMSR.detach(self, sr_uuid)
        self.mpathmodule.reset(self.SCSIid, explicit_unmap=True)
        try:
            pbdref = util.find_my_pbd(self.session, self.host_ref, self.sr_ref)
        except:
            pass
        for key in ["mpath-" + self.SCSIid, "multipathed"]:
            try:
                self.session.xenapi.PBD.remove_from_other_config(pbdref, key)
            except:
                pass

    def _remove_device_nodes(self):
        """
        Remove the kernel device nodes
        """
        nodes = glob.glob('/dev/disk/by-scsid/%s/*' % self.SCSIid)
        util.SMlog('Remove_nodes, nodes are %s' % nodes)
        for node in nodes:
            with open('/sys/block/%s/device/delete' %
                      (os.path.basename(node)), 'w') as f:
                f.write('1\n')

    @override
    def delete(self, sr_uuid) -> None:
        self._pathrefresh(LVMoHBASR)
        try:
            LVMSR.LVMSR.delete(self, sr_uuid)
        finally:
            if self.mpath == "true":
                self.mpathmodule.reset(self.SCSIid, explicit_unmap=True)
            self._remove_device_nodes()

    @override
    def vdi(self, uuid) -> VDI.VDI:
        return LVMoHBAVDI(self, uuid)


class LVMoHBAVDI(LVMSR.LVMVDI):
    @override
    def generate_config(self, sr_uuid, vdi_uuid) -> str:
        util.SMlog("LVMoHBAVDI.generate_config")
        if not lvutil._checkLV(self.path):
            raise xs_errors.XenError('VDIUnavailable')
        dict = {}
        self.sr.dconf['multipathing'] = self.sr.mpath
        self.sr.dconf['multipathhandle'] = self.sr.mpathhandle
        dict['device_config'] = self.sr.dconf
        dict['sr_uuid'] = sr_uuid
        dict['vdi_uuid'] = vdi_uuid
        dict['command'] = 'vdi_attach_from_config'
        # Return the 'config' encoded within a normal XMLRPC response so that
        # we can use the regular response/error parsing code.
        config = xmlrpc.client.dumps(tuple([dict]), "vdi_attach_from_config")
        return xmlrpc.client.dumps((config, ), "", True)

    @override
    def attach_from_config(self, sr_uuid, vdi_uuid) -> str:
        util.SMlog("LVMoHBAVDI.attach_from_config")
        self.sr.hbasr.attach(sr_uuid)
        if self.sr.mpath == "true":
            self.sr.mpathmodule.refresh(self.sr.SCSIid, 0)
        try:
            return self.attach(sr_uuid, vdi_uuid)
        except:
            util.logException("LVMoHBAVDI.attach_from_config")
            raise xs_errors.XenError('SRUnavailable', \
                        opterr='Unable to attach the heartbeat disk')


def match_scsidev(s):
    regex = re.compile("^/dev/disk/by-id|^/dev/mapper")
    return regex.search(s, 0)

if __name__ == '__main__':
    SRCommand.run(LVMoHBASR, DRIVER_INFO)
else:
    SR.registerSR(LVMoHBASR)