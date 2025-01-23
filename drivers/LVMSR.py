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
# LVMSR: VHD and QCOW2 on LVM storage repository
#

from sm_typing import Dict, List, override

import SR
from SR import deviceCheck
import VDI
import SRCommand
import util
import lvutil
import lvmcache
import scsiutil
import lock
import os
import sys
import time
import errno
import xs_errors
import cleanup
import blktap2
from journaler import Journaler
from refcounter import RefCounter
from ipc import IPCFlag
from constants import NS_PREFIX_LVM, VG_LOCATION, VG_PREFIX
from cowutil import getCowUtil
from lvmcowutil import LV_PREFIX, LvmCowUtil
from lvmanager import LVActivator
from vditype import VdiType
import XenAPI # pylint: disable=import-error
import re
from srmetadata import ALLOCATION_TAG, NAME_LABEL_TAG, NAME_DESCRIPTION_TAG, \
    UUID_TAG, IS_A_SNAPSHOT_TAG, SNAPSHOT_OF_TAG, TYPE_TAG, VDI_TYPE_TAG, \
    READ_ONLY_TAG, MANAGED_TAG, SNAPSHOT_TIME_TAG, METADATA_OF_POOL_TAG, \
    LVMMetadataHandler, METADATA_OBJECT_TYPE_VDI, \
    METADATA_OBJECT_TYPE_SR, METADATA_UPDATE_OBJECT_TYPE_TAG
from metadata import retrieveXMLfromFile, _parseXML
from xmlrpc.client import DateTime
import glob
from constants import CBTLOG_TAG
from fairlock import Fairlock
DEV_MAPPER_ROOT = os.path.join('/dev/mapper', VG_PREFIX)

geneology: Dict[str, List[str]] = {}
CAPABILITIES = ["SR_PROBE", "SR_UPDATE", "SR_TRIM",
        "VDI_CREATE", "VDI_DELETE", "VDI_ATTACH", "VDI_DETACH", "VDI_MIRROR",
        "VDI_CLONE", "VDI_SNAPSHOT", "VDI_RESIZE", "ATOMIC_PAUSE",
        "VDI_RESET_ON_BOOT/2", "VDI_UPDATE", "VDI_CONFIG_CBT",
        "VDI_ACTIVATE", "VDI_DEACTIVATE"]

CONFIGURATION = [['device', 'local device path (required) (e.g. /dev/sda3)']]

DRIVER_INFO = {
    'name': 'Local VHD and QCOW2 on LVM',
    'description': 'SR plugin which represents disks as VHD and QCOW2 disks on ' + \
            'Logical Volumes within a locally-attached Volume Group',
    'vendor': 'XenSource Inc',
    'copyright': '(C) 2008 XenSource Inc',
    'driver_version': '1.0',
    'required_api_version': '1.0',
    'capabilities': CAPABILITIES,
    'configuration': CONFIGURATION
    }

CREATE_PARAM_TYPES = {
    "raw": VdiType.RAW,
    "vhd": VdiType.VHD,
    "qcow2": VdiType.QCOW2
}

OPS_EXCLUSIVE = [
        "sr_create", "sr_delete", "sr_attach", "sr_detach", "sr_scan",
        "sr_update", "vdi_create", "vdi_delete", "vdi_resize", "vdi_snapshot",
        "vdi_clone"]

# Log if snapshot pauses VM for more than this many seconds
LONG_SNAPTIME = 60

class LVMSR(SR.SR):
    DRIVER_TYPE = 'lvhd'

    PROVISIONING_TYPES = ["thin", "thick"]
    PROVISIONING_DEFAULT = "thick"
    THIN_PLUGIN = "lvhd-thin"

    PLUGIN_ON_SLAVE = "on-slave"

    FLAG_USE_VHD = "use_vhd"
    MDVOLUME_NAME = "MGT"

    ALLOCATION_QUANTUM = "allocation_quantum"
    INITIAL_ALLOCATION = "initial_allocation"

    LOCK_RETRY_INTERVAL = 3
    LOCK_RETRY_ATTEMPTS = 10

    TEST_MODE_KEY = "testmode"
    TEST_MODE_VHD_FAIL_REPARENT_BEGIN = "vhd_fail_reparent_begin"
    TEST_MODE_VHD_FAIL_REPARENT_LOCATOR = "vhd_fail_reparent_locator"
    TEST_MODE_VHD_FAIL_REPARENT_END = "vhd_fail_reparent_end"
    TEST_MODE_VHD_FAIL_RESIZE_BEGIN = "vhd_fail_resize_begin"
    TEST_MODE_VHD_FAIL_RESIZE_DATA = "vhd_fail_resize_data"
    TEST_MODE_VHD_FAIL_RESIZE_METADATA = "vhd_fail_resize_metadata"
    TEST_MODE_VHD_FAIL_RESIZE_END = "vhd_fail_resize_end"

    ENV_VAR_VHD_TEST = {
            TEST_MODE_VHD_FAIL_REPARENT_BEGIN:
                "VHD_UTIL_TEST_FAIL_REPARENT_BEGIN",
            TEST_MODE_VHD_FAIL_REPARENT_LOCATOR:
                "VHD_UTIL_TEST_FAIL_REPARENT_LOCATOR",
            TEST_MODE_VHD_FAIL_REPARENT_END:
                "VHD_UTIL_TEST_FAIL_REPARENT_END",
            TEST_MODE_VHD_FAIL_RESIZE_BEGIN:
                "VHD_UTIL_TEST_FAIL_RESIZE_BEGIN",
            TEST_MODE_VHD_FAIL_RESIZE_DATA:
                "VHD_UTIL_TEST_FAIL_RESIZE_DATA_MOVED",
            TEST_MODE_VHD_FAIL_RESIZE_METADATA:
                "VHD_UTIL_TEST_FAIL_RESIZE_METADATA_MOVED",
            TEST_MODE_VHD_FAIL_RESIZE_END:
                "VHD_UTIL_TEST_FAIL_RESIZE_END"
    }
    testMode = ""

    legacyMode = True

    @override
    @staticmethod
    def handles(type) -> bool:
        """Returns True if this SR class understands the given dconf string"""
        # we can pose as LVMSR or EXTSR for compatibility purposes
        if __name__ == '__main__':
            name = sys.argv[0]
        else:
            name = __name__
        if name.endswith("LVMSR"):
            return type == "lvm"
        elif name.endswith("EXTSR"):
            return type == "ext"
        return type == LVMSR.DRIVER_TYPE

    @override
    def load(self, sr_uuid) -> None:
        self.ops_exclusive = OPS_EXCLUSIVE

        self.isMaster = False
        if 'SRmaster' in self.dconf and self.dconf['SRmaster'] == 'true':
            self.isMaster = True

        self.lock = lock.Lock(lock.LOCK_TYPE_SR, self.uuid)
        self.sr_vditype = SR.DEFAULT_TAP
        self.uuid = sr_uuid
        self.vgname = VG_PREFIX + self.uuid
        self.path = os.path.join(VG_LOCATION, self.vgname)
        self.mdpath = os.path.join(self.path, self.MDVOLUME_NAME)
        self.provision = self.PROVISIONING_DEFAULT

        self.other_conf = None
        if self.srcmd.params.get("sr_ref"):
            self.other_conf = self.session.xenapi.SR.get_other_config(self.sr_ref)

        self.lvm_conf = None
        if self.other_conf:
            self.lvm_conf = self.other_conf.get('lvm-conf')

        try:
            self.lvmCache = lvmcache.LVMCache(self.vgname, self.lvm_conf)
        except:
            raise xs_errors.XenError('SRUnavailable', \
                        opterr='Failed to initialise the LVMCache')
        self.lvActivator = LVActivator(self.uuid, self.lvmCache)
        self.journaler = Journaler(self.lvmCache)
        if not self.other_conf:
            return  # must be a probe call
        # Test for thick vs thin provisioning conf parameter
        if 'allocation' in self.dconf:
            if self.dconf['allocation'] in self.PROVISIONING_TYPES:
                self.provision = self.dconf['allocation']
            else:
                raise xs_errors.XenError('InvalidArg', \
                        opterr='Allocation parameter must be one of %s' % self.PROVISIONING_TYPES)

        if self.other_conf.get(self.TEST_MODE_KEY):
            self.testMode = self.other_conf[self.TEST_MODE_KEY]
            self._prepareTestMode()

        self.sm_config = self.session.xenapi.SR.get_sm_config(self.sr_ref)
        # sm_config flag overrides PBD, if any
        if self.sm_config.get('allocation') in self.PROVISIONING_TYPES:
            self.provision = self.sm_config.get('allocation')

        if self.sm_config.get(self.FLAG_USE_VHD) == "true":
            self.legacyMode = False

        if lvutil._checkVG(self.vgname):
            if self.isMaster and not self.cmd in ["vdi_attach", "vdi_detach",
                    "vdi_activate", "vdi_deactivate"]:
                self._undoAllJournals()
            if not self.cmd in ["sr_attach", "sr_probe"]:
                self._checkMetadataVolume()

        self.mdexists = False

        # get a VDI -> TYPE map from the storage
        contains_uuid_regex = \
            re.compile("^.*[0-9a-f]{8}-(([0-9a-f]{4})-){3}[0-9a-f]{12}.*")
        self.storageVDIs = {}

        for key in self.lvmCache.lvs.keys():
            # if the lvname has a uuid in it
            type = None
            if contains_uuid_regex.search(key) is not None:
                for vdi_type, prefix in LV_PREFIX.items():
                    if key.startswith(prefix):
                        vdi = key[len(prefix):]
                        self.storageVDIs[vdi] = vdi_type
                        break

        # check if metadata volume exists
        try:
            self.mdexists = self.lvmCache.checkLV(self.MDVOLUME_NAME)
        except:
            pass

    @override
    def cleanup(self) -> None:
        # we don't need to hold the lock to dec refcounts of activated LVs
        if not self.lvActivator.deactivateAll():
            raise util.SMException("failed to deactivate LVs")

    def updateSRMetadata(self, allocation):
        try:
            # Add SR specific SR metadata
            sr_info = \
            {ALLOCATION_TAG: allocation,
              UUID_TAG: self.uuid,
              NAME_LABEL_TAG: util.to_plain_string(self.session.xenapi.SR.get_name_label(self.sr_ref)),
              NAME_DESCRIPTION_TAG: util.to_plain_string(self.session.xenapi.SR.get_name_description(self.sr_ref))
            }

            vdi_info = {}
            for vdi in self.session.xenapi.SR.get_VDIs(self.sr_ref):
                vdi_uuid = self.session.xenapi.VDI.get_uuid(vdi)

                # Create the VDI entry in the SR metadata
                vdi_info[vdi_uuid] = \
                {
                    UUID_TAG: vdi_uuid,
                    NAME_LABEL_TAG: util.to_plain_string(self.session.xenapi.VDI.get_name_label(vdi)),
                    NAME_DESCRIPTION_TAG: util.to_plain_string(self.session.xenapi.VDI.get_name_description(vdi)),
                    IS_A_SNAPSHOT_TAG: \
                        int(self.session.xenapi.VDI.get_is_a_snapshot(vdi)),
                    SNAPSHOT_OF_TAG: \
                        self.session.xenapi.VDI.get_snapshot_of(vdi),
                   SNAPSHOT_TIME_TAG: \
                        self.session.xenapi.VDI.get_snapshot_time(vdi),
                    TYPE_TAG: \
                        self.session.xenapi.VDI.get_type(vdi),
                    VDI_TYPE_TAG: \
                       self.session.xenapi.VDI.get_sm_config(vdi)['vdi_type'],
                    READ_ONLY_TAG: \
                        int(self.session.xenapi.VDI.get_read_only(vdi)),
                    METADATA_OF_POOL_TAG: \
                        self.session.xenapi.VDI.get_metadata_of_pool(vdi),
                    MANAGED_TAG: \
                        int(self.session.xenapi.VDI.get_managed(vdi))
                }
            LVMMetadataHandler(self.mdpath).writeMetadata(sr_info, vdi_info)

        except Exception as e:
            raise xs_errors.XenError('MetadataError', \
                         opterr='Error upgrading SR Metadata: %s' % str(e))

    def syncMetadataAndStorage(self):
        try:
            # if a VDI is present in the metadata but not in the storage
            # then delete it from the metadata
            vdi_info = LVMMetadataHandler(self.mdpath, False).getMetadata()[1]
            for vdi in list(vdi_info.keys()):
                update_map = {}
                if not vdi_info[vdi][UUID_TAG] in set(self.storageVDIs.keys()):
                    # delete this from metadata
                    LVMMetadataHandler(self.mdpath). \
                        deleteVdiFromMetadata(vdi_info[vdi][UUID_TAG])
                else:
                    # search for this in the metadata, compare types
                    # self.storageVDIs is a map of vdi_uuid to vdi_type
                    if vdi_info[vdi][VDI_TYPE_TAG] != \
                        self.storageVDIs[vdi_info[vdi][UUID_TAG]]:
                        # storage type takes authority
                        update_map[METADATA_UPDATE_OBJECT_TYPE_TAG] \
                            = METADATA_OBJECT_TYPE_VDI
                        update_map[UUID_TAG] = vdi_info[vdi][UUID_TAG]
                        update_map[VDI_TYPE_TAG] = \
                            self.storageVDIs[vdi_info[vdi][UUID_TAG]]
                        LVMMetadataHandler(self.mdpath) \
                            .updateMetadata(update_map)
                    else:
                        # This should never happen
                        pass

        except Exception as e:
            raise xs_errors.XenError('MetadataError', \
                opterr='Error synching SR Metadata and storage: %s' % str(e))

    def syncMetadataAndXapi(self):
        try:
            # get metadata
            (sr_info, vdi_info) = \
                LVMMetadataHandler(self.mdpath, False).getMetadata()

            # First synch SR parameters
            self.update(self.uuid)

            # Now update the VDI information in the metadata if required
            for vdi_offset in vdi_info.keys():
                try:
                    vdi_ref = \
                        self.session.xenapi.VDI.get_by_uuid( \
                                        vdi_info[vdi_offset][UUID_TAG])
                except:
                    # may be the VDI is not in XAPI yet dont bother
                    continue

                new_name_label = util.to_plain_string(self.session.xenapi.VDI.get_name_label(vdi_ref))
                new_name_description = util.to_plain_string(self.session.xenapi.VDI.get_name_description(vdi_ref))

                if vdi_info[vdi_offset][NAME_LABEL_TAG] != new_name_label or \
                    vdi_info[vdi_offset][NAME_DESCRIPTION_TAG] != \
                    new_name_description:
                    update_map = {}
                    update_map[METADATA_UPDATE_OBJECT_TYPE_TAG] = \
                        METADATA_OBJECT_TYPE_VDI
                    update_map[UUID_TAG] = vdi_info[vdi_offset][UUID_TAG]
                    update_map[NAME_LABEL_TAG] = new_name_label
                    update_map[NAME_DESCRIPTION_TAG] = new_name_description
                    LVMMetadataHandler(self.mdpath) \
                        .updateMetadata(update_map)
        except Exception as e:
            raise xs_errors.XenError('MetadataError', \
                opterr='Error synching SR Metadata and XAPI: %s' % str(e))

    def _checkMetadataVolume(self):
        util.SMlog("Entering _checkMetadataVolume")
        self.mdexists = self.lvmCache.checkLV(self.MDVOLUME_NAME)
        if self.isMaster:
            if self.mdexists and self.cmd == "sr_attach":
                try:
                    # activate the management volume
                    # will be deactivated at detach time
                    self.lvmCache.activateNoRefcount(self.MDVOLUME_NAME)
                    self._synchSmConfigWithMetaData()
                    util.SMlog("Sync SR metadata and the state on the storage.")
                    self.syncMetadataAndStorage()
                    self.syncMetadataAndXapi()
                except Exception as e:
                    util.SMlog("Exception in _checkMetadataVolume, " \
                               "Error: %s." % str(e))
            elif not self.mdexists and not self.legacyMode:
                self._introduceMetaDataVolume()

        if self.mdexists:
            self.legacyMode = False

    def _synchSmConfigWithMetaData(self):
        util.SMlog("Synching sm-config with metadata volume")

        try:
            # get SR info from metadata
            sr_info = {}
            map = {}
            sr_info = LVMMetadataHandler(self.mdpath, False).getMetadata()[0]

            if sr_info == {}:
                raise Exception("Failed to get SR information from metadata.")

            if "allocation" in sr_info:
                self.provision = sr_info.get("allocation")
                map['allocation'] = sr_info.get("allocation")
            else:
                raise Exception("Allocation key not found in SR metadata. "
                                "SR info found: %s" % sr_info)

        except Exception as e:
            raise xs_errors.XenError(
                'MetadataError',
                opterr='Error reading SR params from '
                       'metadata Volume: %s' % str(e))
        try:
            map[self.FLAG_USE_VHD] = 'true'
            self.session.xenapi.SR.set_sm_config(self.sr_ref, map)
        except:
            raise xs_errors.XenError(
                'MetadataError',
                opterr='Error updating sm_config key')

    def _introduceMetaDataVolume(self):
        util.SMlog("Creating Metadata volume")
        try:
            config = {}
            self.lvmCache.create(self.MDVOLUME_NAME, 4 * 1024 * 1024)

            # activate the management volume, will be deactivated at detach time
            self.lvmCache.activateNoRefcount(self.MDVOLUME_NAME)

            name_label = util.to_plain_string( \
                            self.session.xenapi.SR.get_name_label(self.sr_ref))
            name_description = util.to_plain_string( \
                    self.session.xenapi.SR.get_name_description(self.sr_ref))
            config[self.FLAG_USE_VHD] = "true"
            config['allocation'] = self.provision
            self.session.xenapi.SR.set_sm_config(self.sr_ref, config)

            # Add the SR metadata
            self.updateSRMetadata(self.provision)
        except Exception as e:
            raise xs_errors.XenError('MetadataError', \
                        opterr='Error introducing Metadata Volume: %s' % str(e))

    def _removeMetadataVolume(self):
        if self.mdexists:
            try:
                self.lvmCache.remove(self.MDVOLUME_NAME)
            except:
                raise xs_errors.XenError('MetadataError', \
                             opterr='Failed to delete MGT Volume')

    def _refresh_size(self):
        """
        Refreshs the size of the backing device.
        Return true if all paths/devices agree on the same size.
        """
        if hasattr(self, 'SCSIid'):
            # LVMoHBASR, LVMoISCSISR
            return scsiutil.refresh_lun_size_by_SCSIid(getattr(self, 'SCSIid'))
        else:
            # LVMSR
            devices = self.dconf['device'].split(',')
            scsiutil.refreshdev(devices)
            return True

    def _expand_size(self):
        """
        Expands the size of the SR by growing into additional availiable
        space, if extra space is availiable on the backing device.
        Needs to be called after a successful call of _refresh_size.
        """
        currentvgsize = lvutil._getVGstats(self.vgname)['physical_size']
        # We are comparing PV- with VG-sizes that are aligned. Need a threshold
        resizethreshold = 100 * 1024 * 1024  # 100MB
        devices = self.dconf['device'].split(',')
        totaldevicesize = 0
        for device in devices:
            totaldevicesize = totaldevicesize + scsiutil.getsize(device)
        if totaldevicesize >= (currentvgsize + resizethreshold):
            try:
                if hasattr(self, 'SCSIid'):
                    # LVMoHBASR, LVMoISCSISR might have slaves
                    scsiutil.refresh_lun_size_by_SCSIid_on_slaves(self.session,
                                                       getattr(self, 'SCSIid'))
                util.SMlog("LVMSR._expand_size for %s will resize the pv." %
                           self.uuid)
                for pv in lvutil.get_pv_for_vg(self.vgname):
                    lvutil.resizePV(pv)
            except:
                util.logException("LVMSR._expand_size for %s failed to resize"
                                  " the PV" % self.uuid)

    @override
    @deviceCheck
    def create(self, uuid, size) -> None:
        util.SMlog("LVMSR.create for %s" % self.uuid)
        if not self.isMaster:
            util.SMlog('sr_create blocked for non-master')
            raise xs_errors.XenError('LVMMaster')

        if lvutil._checkVG(self.vgname):
            raise xs_errors.XenError('SRExists')

        # Check none of the devices already in use by other PBDs
        if util.test_hostPBD_devs(self.session, uuid, self.dconf['device']):
            raise xs_errors.XenError('SRInUse')

        # Check serial number entry in SR records
        for dev in self.dconf['device'].split(','):
            if util.test_scsiserial(self.session, dev):
                raise xs_errors.XenError('SRInUse')

        lvutil.createVG(self.dconf['device'], self.vgname)

        #Update serial number string
        scsiutil.add_serial_record(self.session, self.sr_ref, \
                scsiutil.devlist_to_serialstring(self.dconf['device'].split(',')))

        # since this is an SR.create turn off legacy mode
        self.session.xenapi.SR.add_to_sm_config(self.sr_ref, \
                                                self.FLAG_USE_VHD, 'true')

    @override
    def delete(self, uuid) -> None:
        util.SMlog("LVMSR.delete for %s" % self.uuid)
        if not self.isMaster:
            raise xs_errors.XenError('LVMMaster')
        cleanup.gc_force(self.session, self.uuid)

        success = True
        for fileName in glob.glob(DEV_MAPPER_ROOT + '*'):
            if util.extractSRFromDevMapper(fileName) != self.uuid:
                continue

            if util.doesFileHaveOpenHandles(fileName):
                util.SMlog("LVMSR.delete: The dev mapper entry %s has open " \
                           "handles" % fileName)
                success = False
                continue

            # Now attempt to remove the dev mapper entry
            if not lvutil.removeDevMapperEntry(fileName, False):
                success = False
                continue

            try:
                lvname = os.path.basename(fileName.replace('-', '/'). \
                                          replace('//', '-'))
                lpath = os.path.join(self.path, lvname)
                os.unlink(lpath)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    util.SMlog("LVMSR.delete: failed to remove the symlink for " \
                               "file %s. Error: %s" % (fileName, str(e)))
                    success = False

        if success:
            try:
                if util.pathexists(self.path):
                    os.rmdir(self.path)
            except Exception as e:
                util.SMlog("LVMSR.delete: failed to remove the symlink " \
                           "directory %s. Error: %s" % (self.path, str(e)))
                success = False

        self._removeMetadataVolume()
        self.lvmCache.refresh()
        if LvmCowUtil.getVolumeInfo(self.lvmCache):
            raise xs_errors.XenError('SRNotEmpty')

        if not success:
            raise Exception("LVMSR delete failed, please refer to the log " \
                            "for details.")

        lvutil.removeVG(self.dconf['device'], self.vgname)
        self._cleanup()

    @override
    def attach(self, uuid) -> None:
        util.SMlog("LVMSR.attach for %s" % self.uuid)

        self._cleanup(True)  # in case of host crashes, if detach wasn't called

        if not util.match_uuid(self.uuid) or not lvutil._checkVG(self.vgname):
            raise xs_errors.XenError('SRUnavailable', \
                    opterr='no such volume group: %s' % self.vgname)

        # Refresh the metadata status
        self._checkMetadataVolume()

        refreshsizeok = self._refresh_size()

        if self.isMaster:
            if refreshsizeok:
                self._expand_size()

            # Update SCSIid string
            util.SMlog("Calling devlist_to_serial")
            scsiutil.add_serial_record(
                self.session, self.sr_ref,
                scsiutil.devlist_to_serialstring(self.dconf['device'].split(',')))

        # Test Legacy Mode Flag and update if VHD volumes exist
        if self.isMaster and self.legacyMode:
            vdiInfo = LvmCowUtil.getVDIInfo(self.lvmCache)
            for uuid, info in vdiInfo.items():
                if VdiType.isCowImage(info.vdiType):
                    self.legacyMode = False
                    map = self.session.xenapi.SR.get_sm_config(self.sr_ref)
                    self._introduceMetaDataVolume()
                    break

        # Set the block scheduler
        for dev in self.dconf['device'].split(','):
            self.block_setscheduler(dev)

    @override
    def detach(self, uuid) -> None:
        util.SMlog("LVMSR.detach for %s" % self.uuid)
        cleanup.abort(self.uuid)

        # Do a best effort cleanup of the dev mapper entries
        # go through all devmapper entries for this VG
        success = True
        for fileName in glob.glob(DEV_MAPPER_ROOT + '*'):
            if util.extractSRFromDevMapper(fileName) != self.uuid:
                continue

            with Fairlock('devicemapper'):
                # check if any file has open handles
                if util.doesFileHaveOpenHandles(fileName):
                    # if yes, log this and signal failure
                    util.SMlog(
                        f"LVMSR.detach: The dev mapper entry {fileName} has "
                        "open handles")
                    success = False
                    continue

            # Now attempt to remove the dev mapper entry
            if not lvutil.removeDevMapperEntry(fileName, False):
                success = False
                continue

            # also remove the symlinks from /dev/VG-XenStorage-SRUUID/*
            try:
                lvname = os.path.basename(fileName.replace('-', '/'). \
                                          replace('//', '-'))
                lvname = os.path.join(self.path, lvname)
                util.force_unlink(lvname)
            except Exception as e:
                util.SMlog("LVMSR.detach: failed to remove the symlink for " \
                           "file %s. Error: %s" % (fileName, str(e)))
                success = False

        # now remove the directory where the symlinks are
        # this should pass as the directory should be empty by now
        if success:
            try:
                if util.pathexists(self.path):
                    os.rmdir(self.path)
            except Exception as e:
                util.SMlog("LVMSR.detach: failed to remove the symlink " \
                           "directory %s. Error: %s" % (self.path, str(e)))
                success = False

        if not success:
            raise Exception("SR detach failed, please refer to the log " \
                            "for details.")

        # Don't delete lock files on the master as it will break the locking
        # between SM and any GC thread that survives through SR.detach.
        # However, we should still delete lock files on slaves as it is the
        # only place to do so.
        self._cleanup(self.isMaster)

    @override
    def forget_vdi(self, uuid) -> None:
        if not self.legacyMode:
            LVMMetadataHandler(self.mdpath).deleteVdiFromMetadata(uuid)
        super(LVMSR, self).forget_vdi(uuid)

    @override
    def scan(self, uuid) -> None:
        activated = True
        try:
            lvname = ''
            util.SMlog("LVMSR.scan for %s" % self.uuid)
            if not self.isMaster:
                util.SMlog('sr_scan blocked for non-master')
                raise xs_errors.XenError('LVMMaster')

            if self._refresh_size():
                self._expand_size()
            self.lvmCache.refresh()
            cbt_vdis = self.lvmCache.getTagged(CBTLOG_TAG)
            self._loadvdis()
            stats = lvutil._getVGstats(self.vgname)
            self.physical_size = stats['physical_size']
            self.physical_utilisation = stats['physical_utilisation']

            # Now check if there are any VDIs in the metadata, which are not in
            # XAPI
            if self.mdexists:
                vdiToSnaps: Dict[str, List[str]] = {}
                # get VDIs from XAPI
                vdis = self.session.xenapi.SR.get_VDIs(self.sr_ref)
                vdi_uuids = set([])
                for vdi in vdis:
                    vdi_uuids.add(self.session.xenapi.VDI.get_uuid(vdi))

                info = LVMMetadataHandler(self.mdpath, False).getMetadata()[1]

                for vdi in list(info.keys()):
                    vdi_uuid = info[vdi][UUID_TAG]
                    if bool(int(info[vdi][IS_A_SNAPSHOT_TAG])):
                        if info[vdi][SNAPSHOT_OF_TAG] in vdiToSnaps:
                            vdiToSnaps[info[vdi][SNAPSHOT_OF_TAG]].append(vdi_uuid)
                        else:
                            vdiToSnaps[info[vdi][SNAPSHOT_OF_TAG]] = [vdi_uuid]

                    if vdi_uuid not in vdi_uuids:
                        util.SMlog("Introduce VDI %s as it is present in " \
                                   "metadata and not in XAPI." % vdi_uuid)
                        vdi_type = info[vdi][VDI_TYPE_TAG]
                        sm_config = {}
                        sm_config['vdi_type'] = vdi_type
                        lvname = "%s%s" % (LV_PREFIX[sm_config['vdi_type']], vdi_uuid)
                        self.lvmCache.activateNoRefcount(lvname)
                        activated = True
                        lvPath = os.path.join(self.path, lvname)

                        if not VdiType.isCowImage(vdi_type):
                            size = self.lvmCache.getSize(LV_PREFIX[vdi_type] + vdi_uuid)
                            utilisation = \
                                        util.roundup(lvutil.LVM_SIZE_INCREMENT,
                                                       int(size))
                        else:
                            cowutil = getCowUtil(vdi_type)
                            lvmcowutil = LvmCowUtil(cowutil)

                            parent = cowutil.getParentNoCheck(lvPath)

                            if parent is not None:
                                sm_config['vhd-parent'] = parent[len(LV_PREFIX[VdiType.VHD]):]
                            size = cowutil.getSizeVirt(lvPath)
                            if self.provision == "thin":
                                utilisation = util.roundup(
                                    lvutil.LVM_SIZE_INCREMENT,
                                    cowutil.calcOverheadEmpty(max(size, cowutil.getDefaultPreallocationSizeVirt()))
                                )
                            else:
                                utilisation = lvmcowutil.calcVolumeSize(int(size))

                        vdi_ref = self.session.xenapi.VDI.db_introduce(
                                        vdi_uuid,
                                        info[vdi][NAME_LABEL_TAG],
                                        info[vdi][NAME_DESCRIPTION_TAG],
                                        self.sr_ref,
                                        info[vdi][TYPE_TAG],
                                        False,
                                        bool(int(info[vdi][READ_ONLY_TAG])),
                                        {},
                                        vdi_uuid,
                                        {},
                                        sm_config)

                        self.session.xenapi.VDI.set_managed(vdi_ref,
                                                    bool(int(info[vdi][MANAGED_TAG])))
                        self.session.xenapi.VDI.set_virtual_size(vdi_ref,
                                                                 str(size))
                        self.session.xenapi.VDI.set_physical_utilisation( \
                            vdi_ref, str(utilisation))
                        self.session.xenapi.VDI.set_is_a_snapshot( \
                            vdi_ref, bool(int(info[vdi][IS_A_SNAPSHOT_TAG])))
                        if bool(int(info[vdi][IS_A_SNAPSHOT_TAG])):
                            self.session.xenapi.VDI.set_snapshot_time( \
                                vdi_ref, DateTime(info[vdi][SNAPSHOT_TIME_TAG]))
                        if info[vdi][TYPE_TAG] == 'metadata':
                            self.session.xenapi.VDI.set_metadata_of_pool( \
                                vdi_ref, info[vdi][METADATA_OF_POOL_TAG])

                    # Update CBT status of disks either just added
                    # or already in XAPI
                    cbt_logname = "%s.%s" % (vdi_uuid, CBTLOG_TAG)
                    if cbt_logname in cbt_vdis:
                        vdi_ref = self.session.xenapi.VDI.get_by_uuid(vdi_uuid)
                        self.session.xenapi.VDI.set_cbt_enabled(vdi_ref, True)
                        # For existing VDIs, update local state too
                        # Scan in base class SR updates existing VDIs
                        # again based on local states
                        if vdi_uuid in self.vdis:
                            self.vdis[vdi_uuid].cbt_enabled = True
                        cbt_vdis.remove(cbt_logname)

                # Now set the snapshot statuses correctly in XAPI
                for srcvdi in vdiToSnaps.keys():
                    try:
                        srcref = self.session.xenapi.VDI.get_by_uuid(srcvdi)
                    except:
                        # the source VDI no longer exists, continue
                        continue

                    for snapvdi in vdiToSnaps[srcvdi]:
                        try:
                            # this might fail in cases where its already set
                            snapref = \
                                self.session.xenapi.VDI.get_by_uuid(snapvdi)
                            self.session.xenapi.VDI.set_snapshot_of(snapref, srcref)
                        except Exception as e:
                            util.SMlog("Setting snapshot failed. " \
                                       "Error: %s" % str(e))

            if cbt_vdis:
                # If we have items remaining in this list,
                # they are cbt_metadata VDI that XAPI doesn't know about
                # Add them to self.vdis and they'll get added to the DB
                for cbt_vdi in cbt_vdis:
                    cbt_uuid = cbt_vdi.split(".")[0]
                    new_vdi = self.vdi(cbt_uuid)
                    new_vdi.ty = "cbt_metadata"
                    new_vdi.cbt_enabled = True
                    self.vdis[cbt_uuid] = new_vdi

            super(LVMSR, self).scan(uuid)
            self._kickGC()

        finally:
            if lvname != '' and activated:
                self.lvmCache.deactivateNoRefcount(lvname)

    @override
    def update(self, uuid) -> None:
        if not lvutil._checkVG(self.vgname):
            return
        self._updateStats(uuid, 0)

        if self.legacyMode:
            return

        # synch name_label in metadata with XAPI
        update_map = {}
        update_map = {METADATA_UPDATE_OBJECT_TYPE_TAG: \
                        METADATA_OBJECT_TYPE_SR,
                        NAME_LABEL_TAG: util.to_plain_string( \
                            self.session.xenapi.SR.get_name_label(self.sr_ref)),
                        NAME_DESCRIPTION_TAG: util.to_plain_string( \
                        self.session.xenapi.SR.get_name_description(self.sr_ref))
                        }
        LVMMetadataHandler(self.mdpath).updateMetadata(update_map)

    def _updateStats(self, uuid, virtAllocDelta):
        valloc = int(self.session.xenapi.SR.get_virtual_allocation(self.sr_ref))
        self.virtual_allocation = valloc + virtAllocDelta
        util.SMlog("Setting virtual_allocation of SR %s to %d" %
                   (uuid, self.virtual_allocation))
        stats = lvutil._getVGstats(self.vgname)
        self.physical_size = stats['physical_size']
        self.physical_utilisation = stats['physical_utilisation']
        self._db_update()

    @override
    @deviceCheck
    def probe(self) -> str:
        return lvutil.srlist_toxml(
                lvutil.scan_srlist(VG_PREFIX, self.dconf['device']),
                VG_PREFIX,
                ('metadata' in self.srcmd.params['sr_sm_config'] and \
                 self.srcmd.params['sr_sm_config']['metadata'] == 'true'))

    @override
    def vdi(self, uuid) -> VDI.VDI:
        return LVMVDI(self, uuid)

    def _loadvdis(self):
        self.virtual_allocation = 0
        self.vdiInfo = LvmCowUtil.getVDIInfo(self.lvmCache)
        self.allVDIs = {}

        for uuid, info in self.vdiInfo.items():
            if uuid.startswith(cleanup.SR.TMP_RENAME_PREFIX):
                continue
            if info.scanError:
                raise xs_errors.XenError('VDIUnavailable', \
                        opterr='Error scanning VDI %s' % uuid)
            self.vdis[uuid] = self.allVDIs[uuid] = self.vdi(uuid)
            if not self.vdis[uuid].hidden:
                self.virtual_allocation += self.vdis[uuid].utilisation

        for uuid, vdi in self.vdis.items():
            if vdi.parent:
                if vdi.parent in self.vdis:
                    self.vdis[vdi.parent].read_only = True
                if vdi.parent in geneology:
                    geneology[vdi.parent].append(uuid)
                else:
                    geneology[vdi.parent] = [uuid]

        # Now remove all hidden leaf nodes to avoid introducing records that
        # will be GC'ed
        for uuid in list(self.vdis.keys()):
            if uuid not in geneology and self.vdis[uuid].hidden:
                util.SMlog("Scan found hidden leaf (%s), ignoring" % uuid)
                del self.vdis[uuid]

    def _ensureSpaceAvailable(self, amount_needed):
        space_available = lvutil._getVGstats(self.vgname)['freespace']
        if (space_available < amount_needed):
            util.SMlog("Not enough space! free space: %d, need: %d" % \
                    (space_available, amount_needed))
            raise xs_errors.XenError('SRNoSpace')

    def _handleInterruptedCloneOps(self):
        entries = self.journaler.getAll(LVMVDI.JRN_CLONE)
        for uuid, val in entries.items():
            util.fistpoint.activate("LVHDRT_clone_vdi_before_undo_clone", self.uuid)
            self._handleInterruptedCloneOp(uuid, val)
            util.fistpoint.activate("LVHDRT_clone_vdi_after_undo_clone", self.uuid)
            self.journaler.remove(LVMVDI.JRN_CLONE, uuid)

    def _handleInterruptedCoalesceLeaf(self):
        entries = self.journaler.getAll(cleanup.VDI.JRN_LEAF)
        if len(entries) > 0:
            util.SMlog("*** INTERRUPTED COALESCE-LEAF OP DETECTED ***")
            cleanup.gc_force(self.session, self.uuid)
            self.lvmCache.refresh()

    def _handleInterruptedCloneOp(self, origUuid, jval, forceUndo=False):
        """Either roll back or finalize the interrupted snapshot/clone
        operation. Rolling back is unsafe if the leaf images have already been
        in use and written to. However, it is always safe to roll back while
        we're still in the context of the failed snapshot operation since the
        VBD is paused for the duration of the operation"""
        util.SMlog("*** INTERRUPTED CLONE OP: for %s (%s)" % (origUuid, jval))
        lvs = LvmCowUtil.getVolumeInfo(self.lvmCache)
        baseUuid, clonUuid = jval.split("_")

        # is there a "base copy" VDI?
        if not lvs.get(baseUuid):
            # no base copy: make sure the original is there
            if lvs.get(origUuid):
                util.SMlog("*** INTERRUPTED CLONE OP: nothing to do")
                return
            raise util.SMException("base copy %s not present, " \
                    "but no original %s found" % (baseUuid, origUuid))

        cowutil = getCowUtil(base.vdiType)

        if forceUndo:
            util.SMlog("Explicit revert")
            self._undoCloneOp(cowutil, lvs, origUuid, baseUuid, clonUuid)
            return

        if not lvs.get(origUuid) or (clonUuid and not lvs.get(clonUuid)):
            util.SMlog("One or both leaves missing => revert")
            self._undoCloneOp(cowutil, lvs, origUuid, baseUuid, clonUuid)
            return

        vdis = LvmCowUtil.getVDIInfo(self.lvmCache)
        if vdis[origUuid].scanError or (clonUuid and vdis[clonUuid].scanError):
            util.SMlog("One or both leaves invalid => revert")
            self._undoCloneOp(cowutil, lvs, origUuid, baseUuid, clonUuid)
            return

        orig = vdis[origUuid]
        base = vdis[baseUuid]
        self.lvActivator.activate(baseUuid, base.lvName, False)
        self.lvActivator.activate(origUuid, orig.lvName, False)
        if orig.parentUuid != baseUuid:
            parent = vdis[orig.parentUuid]
            self.lvActivator.activate(parent.uuid, parent.lvName, False)
        origPath = os.path.join(self.path, orig.lvName)

        if cowutil.check(origPath) != CowUtil.CheckResult.Success:
            util.SMlog("Orig image invalid => revert")
            self._undoCloneOp(cowutil, lvs, origUuid, baseUuid, clonUuid)
            return

        if clonUuid:
            clon = vdis[clonUuid]
            clonPath = os.path.join(self.path, clon.lvName)
            self.lvActivator.activate(clonUuid, clon.lvName, False)
            if cowutil.check(clonPath) != CowUtil.CheckResult.Success:
                util.SMlog("Clon image invalid => revert")
                self._undoCloneOp(cowutil, lvs, origUuid, baseUuid, clonUuid)
                return

        util.SMlog("Snapshot appears valid, will not roll back")
        self._completeCloneOp(cowutil, vdis, origUuid, baseUuid, clonUuid)

    def _undoCloneOp(self, cowutil, lvs, origUuid, baseUuid, clonUuid):
        base = lvs[baseUuid]
        basePath = os.path.join(self.path, base.name)

        # make the parent RW
        if base.readonly:
            self.lvmCache.setReadonly(base.name, False)

        ns = NS_PREFIX_LVM + self.uuid
        origRefcountBinary = RefCounter.check(origUuid, ns)[1]
        origRefcountNormal = 0

        # un-hide the parent
        if VdiType.isCowImage(base.vdiType):
            self.lvActivator.activate(baseUuid, base.name, False)
            origRefcountNormal = 1
            imageInfo = cowutil.getInfo(basePath, LvmCowUtil.extractUuid, False)
            if imageInfo.hidden:
                cowutil.setHidden(basePath, False)
        elif base.hidden:
            self.lvmCache.setHidden(base.name, False)

        # remove the child nodes
        if clonUuid and lvs.get(clonUuid):
            if not VdiType.isCowImage(lvs[clonUuid].vdiType):
                raise util.SMException("clone %s not a COW image" % clonUuid)
            self.lvmCache.remove(lvs[clonUuid].name)
            if self.lvActivator.get(clonUuid, False):
                self.lvActivator.remove(clonUuid, False)
        if lvs.get(origUuid):
            self.lvmCache.remove(lvs[origUuid].name)

        # inflate the parent to fully-allocated size
        if VdiType.isCowImage(base.vdiType):
            lvmcowutil = LvmCowUtil(cowutil)
            fullSize = lvmcowutil.calcVolumeSize(imageInfo.sizeVirt)
            lvmcowutil.inflate(self.journaler, self.uuid, baseUuid, base.vdiType, fullSize)

        # rename back
        origLV = LV_PREFIX[base.vdiType] + origUuid
        self.lvmCache.rename(base.name, origLV)
        RefCounter.reset(baseUuid, ns)
        if self.lvActivator.get(baseUuid, False):
            self.lvActivator.replace(baseUuid, origUuid, origLV, False)
        RefCounter.set(origUuid, origRefcountNormal, origRefcountBinary, ns)

        # At this stage, tapdisk and SM vdi will be in paused state. Remove
        # flag to facilitate vm deactivate
        origVdiRef = self.session.xenapi.VDI.get_by_uuid(origUuid)
        self.session.xenapi.VDI.remove_from_sm_config(origVdiRef, 'paused')

        # update LVM metadata on slaves
        slaves = util.get_slaves_attached_on(self.session, [origUuid])
        LvmCowUtil.refreshVolumeOnSlaves(self.session, self.uuid, self.vgname,
                origLV, origUuid, slaves)

        util.SMlog("*** INTERRUPTED CLONE OP: rollback success")

    def _completeCloneOp(self, cowutil, vdis, origUuid, baseUuid, clonUuid):
        """Finalize the interrupted snapshot/clone operation. This must not be
        called from the live snapshot op context because we attempt to pause/
        unpause the VBD here (the VBD is already paused during snapshot, so it
        would cause a deadlock)"""
        base = vdis[baseUuid]
        clon = None
        if clonUuid:
            clon = vdis[clonUuid]

        cleanup.abort(self.uuid)

        # make sure the parent is hidden and read-only
        if not base.hidden:
            if not VdiType.isCowImage(base.vdiType):
                self.lvmCache.setHidden(base.lvName)
            else:
                basePath = os.path.join(self.path, base.lvName)
                cowutil.setHidden(basePath)
        if not base.lvReadonly:
            self.lvmCache.setReadonly(base.lvName, True)

        # NB: since this snapshot-preserving call is only invoked outside the
        # snapshot op context, we assume the LVM metadata on the involved slave
        # has by now been refreshed and do not attempt to do it here

        # Update the original record
        try:
            vdi_ref = self.session.xenapi.VDI.get_by_uuid(origUuid)
            sm_config = self.session.xenapi.VDI.get_sm_config(vdi_ref)
            type = self.session.xenapi.VDI.get_type(vdi_ref)
            sm_config["vdi_type"] = vdis[origUuid].vdiType
            sm_config['vhd-parent'] = baseUuid
            self.session.xenapi.VDI.set_sm_config(vdi_ref, sm_config)
        except XenAPI.Failure:
            util.SMlog("ERROR updating the orig record")

        # introduce the new VDI records
        if clonUuid:
            try:
                clon_vdi = VDI.VDI(self, clonUuid)
                clon_vdi.read_only = False
                clon_vdi.location = clonUuid
                clon_vdi.utilisation = clon.sizeLV
                clon_vdi.sm_config = {
                        "vdi_type": clon.vdiType,
                        "vhd-parent": baseUuid}

                if not self.legacyMode:
                    LVMMetadataHandler(self.mdpath). \
                                       ensureSpaceIsAvailableForVdis(1)

                clon_vdi_ref = clon_vdi._db_introduce()
                util.SMlog("introduced clon VDI: %s (%s)" % \
                        (clon_vdi_ref, clonUuid))

                vdi_info = {UUID_TAG: clonUuid,
                                NAME_LABEL_TAG: clon_vdi.label,
                                NAME_DESCRIPTION_TAG: clon_vdi.description,
                                IS_A_SNAPSHOT_TAG: 0,
                                SNAPSHOT_OF_TAG: '',
                                SNAPSHOT_TIME_TAG: '',
                                TYPE_TAG: type,
                                VDI_TYPE_TAG: clon_vdi.sm_config['vdi_type'],
                                READ_ONLY_TAG: int(clon_vdi.read_only),
                                MANAGED_TAG: int(clon_vdi.managed),
                                METADATA_OF_POOL_TAG: ''
                }

                if not self.legacyMode:
                    LVMMetadataHandler(self.mdpath).addVdi(vdi_info)

            except XenAPI.Failure:
                util.SMlog("ERROR introducing the clon record")

        try:
            base_vdi = VDI.VDI(self, baseUuid)  # readonly parent
            base_vdi.label = "base copy"
            base_vdi.read_only = True
            base_vdi.location = baseUuid
            base_vdi.size = base.sizeVirt
            base_vdi.utilisation = base.sizeLV
            base_vdi.managed = False
            base_vdi.sm_config = {
                    "vdi_type": base.vdiType,
                    "vhd-parent": baseUuid}

            if not self.legacyMode:
                LVMMetadataHandler(self.mdpath).ensureSpaceIsAvailableForVdis(1)

            base_vdi_ref = base_vdi._db_introduce()
            util.SMlog("introduced base VDI: %s (%s)" % \
                    (base_vdi_ref, baseUuid))

            vdi_info = {UUID_TAG: baseUuid,
                                NAME_LABEL_TAG: base_vdi.label,
                                NAME_DESCRIPTION_TAG: base_vdi.description,
                                IS_A_SNAPSHOT_TAG: 0,
                                SNAPSHOT_OF_TAG: '',
                                SNAPSHOT_TIME_TAG: '',
                                TYPE_TAG: type,
                                VDI_TYPE_TAG: base_vdi.sm_config['vdi_type'],
                                READ_ONLY_TAG: int(base_vdi.read_only),
                                MANAGED_TAG: int(base_vdi.managed),
                                METADATA_OF_POOL_TAG: ''
                }

            if not self.legacyMode:
                LVMMetadataHandler(self.mdpath).addVdi(vdi_info)
        except XenAPI.Failure:
            util.SMlog("ERROR introducing the base record")

        util.SMlog("*** INTERRUPTED CLONE OP: complete")

    def _undoAllJournals(self):
        """Undo all COW image & SM interrupted journaled operations. This call must
        be serialized with respect to all operations that create journals"""
        # undoing interrupted inflates must be done first, since undoing COW images
        # ops might require inflations
        self.lock.acquire()
        try:
            self._undoAllInflateJournals()
            self._undoAllCowJournals()
            self._handleInterruptedCloneOps()
            self._handleInterruptedCoalesceLeaf()
        finally:
            self.lock.release()
            self.cleanup()

    def _undoAllInflateJournals(self):
        entries = self.journaler.getAll(LvmCowUtil.JOURNAL_INFLATE)
        if len(entries) == 0:
            return
        self._loadvdis()
        for uuid, val in entries.items():
            vdi = self.vdis.get(uuid)
            if vdi:
                util.SMlog("Found inflate journal %s, deflating %s to %s" % \
                        (uuid, vdi.path, val))
                if vdi.readonly:
                    self.lvmCache.setReadonly(vdi.lvname, False)
                self.lvActivator.activate(uuid, vdi.lvname, False)
                currSizeLV = self.lvmCache.getSize(vdi.lvname)

                cowutil = getCowUtil(vdi.vdi_type)
                lvmcowutil = LvmCowUtil(cowutil)

                footer_size = cowutil.getFooterSize()
                util.zeroOut(vdi.path, currSizeLV - footer_size, footer_size)
                lvmcowutil.deflate(self.lvmCache, vdi.lvname, int(val))
                if vdi.readonly:
                    self.lvmCache.setReadonly(vdi.lvname, True)
                if "true" == self.session.xenapi.SR.get_shared(self.sr_ref):
                    LvmCowUtil.refreshVolumeOnAllSlaves(
                        self.session, self.uuid, self.vgname, vdi.lvname, uuid
                    )
            self.journaler.remove(LvmCowUtil.JOURNAL_INFLATE, uuid)
        delattr(self, "vdiInfo")
        delattr(self, "allVDIs")

    def _undoAllCowJournals(self):
        """
        Check if there are COW journals in existence and revert them.
        """
        journals = LvmCowUtil.getAllResizeJournals(self.lvmCache)
        if len(journals) == 0:
            return
        self._loadvdis()

        for uuid, jlvName in journals:
            vdi = self.vdis[uuid]
            util.SMlog("Found COW journal %s, reverting %s" % (uuid, vdi.path))
            cowutil = getCowUtil(vdi.vdi_type)
            lvmcowutil = LvmCowUtil(cowutil)

            self.lvActivator.activate(uuid, vdi.lvname, False)
            self.lvmCache.activateNoRefcount(jlvName)
            fullSize = lvmcowutil.calcVolumeSize(vdi.size)
            lvmcowutil.inflate(self.journaler, self.uuid, vdi.uuid, vdi.vdi_type, fullSize)
            try:
                jFile = os.path.join(self.path, jlvName)
                cowutil.revert(vdi.path, jFile)
            except util.CommandException:
                util.logException("COW journal revert")
                cowutil.check(vdi.path)
                util.SMlog("COW image revert failed but COW image ok: removing journal")
            # Attempt to reclaim unused space


            imageInfo = cowutil.getInfo(vdi.path, LvmCowUtil.extractUuid, False)
            NewSize = lvmcowutil.calcVolumeSize(imageInfo.sizeVirt)
            if NewSize < fullSize:
                lvmcowutil.deflate(self.lvmCache, vdi.lvname, int(NewSize))
            LvmCowUtil.refreshVolumeOnAllSlaves(self.session, self.uuid, self.vgname, vdi.lvname, uuid)
            self.lvmCache.remove(jlvName)
        delattr(self, "vdiInfo")
        delattr(self, "allVDIs")

    def _updateSlavesPreClone(self, hostRefs, origOldLV):
        masterRef = util.get_this_host_ref(self.session)
        args = {"vgName": self.vgname,
                "action1": "deactivateNoRefcount",
                "lvName1": origOldLV}
        for hostRef in hostRefs:
            if hostRef == masterRef:
                continue
            util.SMlog("Deactivate VDI on %s" % hostRef)
            rv = self.session.xenapi.host.call_plugin(hostRef, self.PLUGIN_ON_SLAVE, "multi", args)
            util.SMlog("call-plugin returned: %s" % rv)
            if not rv:
                raise Exception('plugin %s failed' % self.PLUGIN_ON_SLAVE)

    def _updateSlavesOnClone(self, hostRefs, origOldLV, origLV,
            baseUuid, baseLV):
        """We need to reactivate the original LV on each slave (note that the
        name for the original LV might change), as well as init the refcount
        for the base LV"""
        args = {"vgName": self.vgname,
                "action1": "refresh",
                "lvName1": origLV,
                "action2": "activate",
                "ns2": NS_PREFIX_LVM + self.uuid,
                "lvName2": baseLV,
                "uuid2": baseUuid}

        masterRef = util.get_this_host_ref(self.session)
        for hostRef in hostRefs:
            if hostRef == masterRef:
                continue
            util.SMlog("Updating %s, %s, %s on slave %s" % \
                    (origOldLV, origLV, baseLV, hostRef))
            rv = self.session.xenapi.host.call_plugin(
                hostRef, self.PLUGIN_ON_SLAVE, "multi", args)
            util.SMlog("call-plugin returned: %s" % rv)
            if not rv:
                raise Exception('plugin %s failed' % self.PLUGIN_ON_SLAVE)

    def _updateSlavesOnCBTClone(self, hostRefs, cbtlog):
        """Reactivate and refresh CBT log file on slaves"""
        args = {"vgName": self.vgname,
                "action1": "deactivateNoRefcount",
                "lvName1": cbtlog,
                "action2": "refresh",
                "lvName2": cbtlog}

        masterRef = util.get_this_host_ref(self.session)
        for hostRef in hostRefs:
            if hostRef == masterRef:
                continue
            util.SMlog("Updating %s on slave %s" % (cbtlog, hostRef))
            rv = self.session.xenapi.host.call_plugin(
                hostRef, self.PLUGIN_ON_SLAVE, "multi", args)
            util.SMlog("call-plugin returned: %s" % rv)
            if not rv:
                raise Exception('plugin %s failed' % self.PLUGIN_ON_SLAVE)

    def _updateSlavesOnRemove(self, hostRefs, baseUuid, baseLV):
        """Tell the slave we deleted the base image"""
        args = {"vgName": self.vgname,
                "action1": "cleanupLockAndRefcount",
                "uuid1": baseUuid,
                "ns1": NS_PREFIX_LVM + self.uuid}

        masterRef = util.get_this_host_ref(self.session)
        for hostRef in hostRefs:
            if hostRef == masterRef:
                continue
            util.SMlog("Cleaning locks for %s on slave %s" % (baseLV, hostRef))
            rv = self.session.xenapi.host.call_plugin(
                hostRef, self.PLUGIN_ON_SLAVE, "multi", args)
            util.SMlog("call-plugin returned: %s" % rv)
            if not rv:
                raise Exception('plugin %s failed' % self.PLUGIN_ON_SLAVE)

    def _cleanup(self, skipLockCleanup=False):
        """delete stale refcounter, flag, and lock files"""
        RefCounter.resetAll(NS_PREFIX_LVM + self.uuid)
        IPCFlag(self.uuid).clearAll()
        if not skipLockCleanup:
            lock.Lock.cleanupAll(self.uuid)
            lock.Lock.cleanupAll(NS_PREFIX_LVM + self.uuid)

    def _prepareTestMode(self):
        util.SMlog("Test mode: %s" % self.testMode)
        if self.ENV_VAR_VHD_TEST.get(self.testMode):
            os.environ[self.ENV_VAR_VHD_TEST[self.testMode]] = "yes"
            util.SMlog("Setting env %s" % self.ENV_VAR_VHD_TEST[self.testMode])

    def _kickGC(self):
        util.SMlog("Kicking GC")
        cleanup.start_gc_service(self.uuid)

    def ensureCBTSpace(self):
        # Ensure we have space for at least one LV
        self._ensureSpaceAvailable(self.journaler.LV_SIZE)


class LVMVDI(VDI.VDI):

    JRN_CLONE = "clone"  # journal entry type for the clone operation

    @override
    def load(self, vdi_uuid) -> None:
        self.lock = self.sr.lock
        self.lvActivator = self.sr.lvActivator
        self.loaded = False
        if self.sr.legacyMode or util.fistpoint.is_active("xenrt_default_vdi_type_legacy"):
            self._setType(VdiType.RAW)
        self.uuid = vdi_uuid
        self.location = self.uuid
        self.exists = True

        if hasattr(self.sr, "vdiInfo") and self.sr.vdiInfo.get(self.uuid):
            self._initFromVDIInfo(self.sr.vdiInfo[self.uuid])
            if self.parent:
                self.sm_config_override['vhd-parent'] = self.parent
            else:
                self.sm_config_override['vhd-parent'] = None
            return

        # scan() didn't run: determine the type of the VDI manually
        if self._determineType():
            return

        # the VDI must be in the process of being created
        self.exists = False
        if "vdi_sm_config" in self.sr.srcmd.params and \
                "type" in self.sr.srcmd.params["vdi_sm_config"]:
            type = self.sr.srcmd.params["vdi_sm_config"]["type"]
            
            try:
                self._setType(CREATE_PARAM_TYPES[type])
            except:
                raise xs_errors.XenError('VDICreate', opterr='bad type')
            if self.sr.legacyMode and self.sr.cmd == 'vdi_create' and VdiType.isCowImage(self.vdi_type):
                raise xs_errors.XenError('VDICreate', opterr='Cannot create COW type disk in legacy mode')

        self.lvname = "%s%s" % (LV_PREFIX[self.vdi_type], vdi_uuid)
        self.path = os.path.join(self.sr.path, self.lvname)

    @override
    def create(self, sr_uuid, vdi_uuid, size) -> str:
        util.SMlog("LVMVDI.create for %s" % self.uuid)
        if not self.sr.isMaster:
            raise xs_errors.XenError('LVMMaster')
        if self.exists:
            raise xs_errors.XenError('VDIExists')

        size = self.cowutil.validateAndRoundImageSize(int(size))

        util.SMlog("LVMVDI.create: type = %s, %s (size=%s)" % \
                (self.vdi_type, self.path, size))
        lvSize = 0
        self.sm_config = self.sr.srcmd.params["vdi_sm_config"]
        if not VdiType.isCowImage(self.vdi_type):
            lvSize = util.roundup(lvutil.LVM_SIZE_INCREMENT, int(size))
        else:
            if self.sr.provision == "thin":
                lvSize = util.roundup(
                    lvutil.LVM_SIZE_INCREMENT,
                    self.cowutil.calcOverheadEmpty(max(size, self.cowutil.getDefaultPreallocationSizeVirt()))
                )
            elif self.sr.provision == "thick":
                lvSize = self.lvmcowutil.calcVolumeSize(int(size))

        self.sr._ensureSpaceAvailable(lvSize)

        try:
            self.sr.lvmCache.create(self.lvname, lvSize)
            if not VdiType.isCowImage(self.vdi_type):
                self.size = self.sr.lvmCache.getSize(self.lvname)
            else:
                self.cowutil.create(
                    self.path, int(size), False, self.cowutil.getDefaultPreallocationSizeVirt()
                )
                self.size = self.cowutil.getSizeVirt(self.path)
            self.sr.lvmCache.deactivateNoRefcount(self.lvname)
        except util.CommandException as e:
            util.SMlog("Unable to create VDI")
            self.sr.lvmCache.remove(self.lvname)
            raise xs_errors.XenError('VDICreate', opterr='error %d' % e.code)

        self.utilisation = lvSize
        self.sm_config["vdi_type"] = self.vdi_type

        if not self.sr.legacyMode:
            LVMMetadataHandler(self.sr.mdpath).ensureSpaceIsAvailableForVdis(1)

        self.ref = self._db_introduce()
        self.sr._updateStats(self.sr.uuid, self.size)

        vdi_info = {UUID_TAG: self.uuid,
                                NAME_LABEL_TAG: util.to_plain_string(self.label),
                                NAME_DESCRIPTION_TAG: util.to_plain_string(self.description),
                                IS_A_SNAPSHOT_TAG: 0,
                                SNAPSHOT_OF_TAG: '',
                                SNAPSHOT_TIME_TAG: '',
                                TYPE_TAG: self.ty,
                                VDI_TYPE_TAG: self.vdi_type,
                                READ_ONLY_TAG: int(self.read_only),
                                MANAGED_TAG: int(self.managed),
                                METADATA_OF_POOL_TAG: ''
                }

        if not self.sr.legacyMode:
            LVMMetadataHandler(self.sr.mdpath).addVdi(vdi_info)

        return VDI.VDI.get_params(self)

    @override
    def delete(self, sr_uuid, vdi_uuid, data_only=False) -> None:
        util.SMlog("LVMVDI.delete for %s" % self.uuid)
        try:
            self._loadThis()
        except xs_errors.SRException as e:
            # Catch 'VDI doesn't exist' exception
            if e.errno == 46:
                return super(LVMVDI, self).delete(sr_uuid, vdi_uuid, data_only)
            raise

        vdi_ref = self.sr.srcmd.params['vdi_ref']
        if not self.session.xenapi.VDI.get_managed(vdi_ref):
            raise xs_errors.XenError("VDIDelete", \
                          opterr="Deleting non-leaf node not permitted")

        if not self.hidden:
            self._markHidden()

        if not data_only:
            # Remove from XAPI and delete from MGT
            self._db_forget()
        else:
            # If this is a data_destroy call, don't remove from XAPI db
            # Only delete from MGT
            if not self.sr.legacyMode:
                LVMMetadataHandler(self.sr.mdpath).deleteVdiFromMetadata(self.uuid)

        # deactivate here because it might be too late to do it in the "final"
        # step: GC might have removed the LV by then
        if self.sr.lvActivator.get(self.uuid, False):
            self.sr.lvActivator.deactivate(self.uuid, False)

        try:
            self.sr.lvmCache.remove(self.lvname)
            self.sr.lock.cleanup(vdi_uuid, NS_PREFIX_LVM + sr_uuid)
            self.sr.lock.cleanupAll(vdi_uuid)
        except xs_errors.SRException as e:
            util.SMlog(
                "Failed to remove the volume (maybe is leaf coalescing) "
                "for %s err:%d" % (self.uuid, e.errno))

        self.sr._updateStats(self.sr.uuid, -self.size)
        self.sr._kickGC()
        return super(LVMVDI, self).delete(sr_uuid, vdi_uuid, data_only)

    @override
    def attach(self, sr_uuid, vdi_uuid) -> str:
        util.SMlog("LVMVDI.attach for %s" % self.uuid)
        if self.sr.journaler.hasJournals(self.uuid):
            raise xs_errors.XenError('VDIUnavailable',
                    opterr='Interrupted operation detected on this VDI, '
                    'scan SR first to trigger auto-repair')

        writable = ('args' not in self.sr.srcmd.params) or \
                (self.sr.srcmd.params['args'][0] == "true")
        needInflate = True
        if not VdiType.isCowImage(self.vdi_type) or not writable:
            needInflate = False
        else:
            self._loadThis()
            if self.utilisation >= self.lvmcowutil.calcVolumeSize(self.size):
                needInflate = False

        if needInflate:
            try:
                self._prepareThin(True)
            except:
                util.logException("attach")
                raise xs_errors.XenError('LVMProvisionAttach')

        try:
            return self._attach()
        finally:
            if not self.sr.lvActivator.deactivateAll():
                util.SMlog("Failed to deactivate LVs back (%s)" % self.uuid)

    @override
    def detach(self, sr_uuid, vdi_uuid) -> None:
        util.SMlog("LVMVDI.detach for %s" % self.uuid)
        self._loadThis()
        already_deflated = (self.utilisation < \
                LvmCowUtil.calcVolumeSize(self.size))
        needDeflate = True
        if not VdiType.isCowImage(self.vdi_type) or already_deflated:
            needDeflate = False
        elif self.sr.provision == "thick":
            needDeflate = False
            # except for snapshots, which are always deflated
            if self.sr.srcmd.cmd != 'vdi_detach_from_config':
                vdi_ref = self.sr.srcmd.params['vdi_ref']
                snap = self.session.xenapi.VDI.get_is_a_snapshot(vdi_ref)
                if snap:
                    needDeflate = True

        if needDeflate:
            try:
                self._prepareThin(False)
            except:
                util.logException("_prepareThin")
                raise xs_errors.XenError('VDIUnavailable', opterr='deflate')

        try:
            self._detach()
        finally:
            if not self.sr.lvActivator.deactivateAll():
                raise xs_errors.XenError("SMGeneral", opterr="deactivation")

    # We only support offline resize
    @override
    def resize(self, sr_uuid, vdi_uuid, size) -> str:
        util.SMlog("LVMVDI.resize for %s" % self.uuid)
        if not self.sr.isMaster:
            raise xs_errors.XenError('LVMMaster')

        self._loadThis()
        if self.hidden:
            raise xs_errors.XenError('VDIUnavailable', opterr='hidden VDI')

        if size < self.size:
            util.SMlog('vdi_resize: shrinking not supported: ' + \
                    '(current size: %d, new size: %d)' % (self.size, size))
            raise xs_errors.XenError('VDISize', opterr='shrinking not allowed')

        size = self.cowutil.validateAndRoundImageSize(int(size))

        if size == self.size:
            return VDI.VDI.get_params(self)

        if not VdiType.isCowImage(self.vdi_type):
            lvSizeOld = self.size
            lvSizeNew = util.roundup(lvutil.LVM_SIZE_INCREMENT, size)
        else:
            lvSizeOld = self.utilisation
            lvSizeNew = LvmCowUtil.calcVolumeSize(size)
            if self.sr.provision == "thin":
                # VDI is currently deflated, so keep it deflated
                lvSizeNew = lvSizeOld
        assert(lvSizeNew >= lvSizeOld)
        spaceNeeded = lvSizeNew - lvSizeOld
        self.sr._ensureSpaceAvailable(spaceNeeded)

        oldSize = self.size
        if not VdiType.isCowImage(self.vdi_type):
            self.sr.lvmCache.setSize(self.lvname, lvSizeNew)
            self.size = self.sr.lvmCache.getSize(self.lvname)
            self.utilisation = self.size
        else:
            if lvSizeNew != lvSizeOld:
                self.lvmcowutil.inflate(self.sr.journaler, self.sr.uuid, self.uuid, self.vdi_type, lvSizeNew)
            self.cowutil.setSizeVirtFast(self.path, size)
            self.size = self.cowutil.getSizeVirt(self.path)
            self.utilisation = self.sr.lvmCache.getSize(self.lvname)

        vdi_ref = self.sr.srcmd.params['vdi_ref']
        self.session.xenapi.VDI.set_virtual_size(vdi_ref, str(self.size))
        self.session.xenapi.VDI.set_physical_utilisation(vdi_ref,
                str(self.utilisation))
        self.sr._updateStats(self.sr.uuid, self.size - oldSize)
        super(LVMVDI, self).resize_cbt(self.sr.uuid, self.uuid, self.size)
        return VDI.VDI.get_params(self)

    @override
    def clone(self, sr_uuid, vdi_uuid) -> str:
        return self._do_snapshot(
                     sr_uuid, vdi_uuid, VDI.SNAPSHOT_DOUBLE, cloneOp=True)

    @override
    def compose(self, sr_uuid, vdi1, vdi2) -> None:
        util.SMlog("LVMSR.compose for %s -> %s" % (vdi2, vdi1))
        if not VdiType.isCowImage(self.vdi_type):
            raise xs_errors.XenError('Unimplemented')

        parent_uuid = vdi1
        parent_lvname = LV_PREFIX[self.vdi_type] + parent_uuid
        assert(self.sr.lvmCache.checkLV(parent_lvname))
        parent_path = os.path.join(self.sr.path, parent_lvname)

        self.sr.lvActivator.activate(self.uuid, self.lvname, False)
        self.sr.lvActivator.activate(parent_uuid, parent_lvname, False)

        self.cowutil.setParent(self.path, parent_path, False)
        self.cowutil.setHidden(parent_path)
        self.sr.session.xenapi.VDI.set_managed(self.sr.srcmd.params['args'][0], False)

        if not blktap2.VDI.tap_refresh(self.session, self.sr.uuid, self.uuid,
                True):
            raise util.SMException("failed to refresh VDI %s" % self.uuid)

        util.SMlog("Compose done")

    def reset_leaf(self, sr_uuid, vdi_uuid):
        util.SMlog("LVMSR.reset_leaf for %s" % vdi_uuid)
        if not VdiType.isCowImage(self.vdi_type):
            raise xs_errors.XenError('Unimplemented')

        self.sr.lvActivator.activate(self.uuid, self.lvname, False)

        # safety check
        if not self.cowutil.hasParent(self.path):
            raise util.SMException("ERROR: VDI %s has no parent, " + \
                    "will not reset contents" % self.uuid)

        self.cowutil.killData(self.path)

    def _attach(self):
        self._chainSetActive(True, True, True)
        if not util.pathexists(self.path):
            raise xs_errors.XenError('VDIUnavailable', \
                    opterr='Could not find: %s' % self.path)

        if not hasattr(self, 'xenstore_data'):
            self.xenstore_data = {}

        self.xenstore_data.update(scsiutil.update_XS_SCSIdata(self.uuid, \
                                                                  scsiutil.gen_synthetic_page_data(self.uuid)))

        self.xenstore_data['storage-type'] = 'lvm'
        self.xenstore_data['vdi-type'] = self.vdi_type

        self.attached = True
        self.sr.lvActivator.persist()
        return VDI.VDI.attach(self, self.sr.uuid, self.uuid)

    def _detach(self):
        self._chainSetActive(False, True)
        self.attached = False

    @override
    def _do_snapshot(self, sr_uuid, vdi_uuid, snapType,
                     cloneOp=False, secondary=None, cbtlog=None) -> str:
        # If cbt enabled, save file consistency state
        if cbtlog is not None:
            if blktap2.VDI.tap_status(self.session, vdi_uuid):
                consistency_state = False
            else:
                consistency_state = True
            util.SMlog("Saving log consistency state of %s for vdi: %s" %
                       (consistency_state, vdi_uuid))
        else:
            consistency_state = None

        pause_time = time.time()
        if not blktap2.VDI.tap_pause(self.session, sr_uuid, vdi_uuid):
            raise util.SMException("failed to pause VDI %s" % vdi_uuid)

        snapResult = None
        try:
            snapResult = self._snapshot(snapType, cloneOp, cbtlog, consistency_state)
        except Exception as e1:
            try:
                blktap2.VDI.tap_unpause(self.session, sr_uuid, vdi_uuid,
                                        secondary=None)
            except Exception as e2:
                util.SMlog('WARNING: failed to clean up failed snapshot: '
                        '%s (error ignored)' % e2)
            raise
        blktap2.VDI.tap_unpause(self.session, sr_uuid, vdi_uuid, secondary)
        unpause_time = time.time()
        if (unpause_time - pause_time) > LONG_SNAPTIME:
            util.SMlog('WARNING: snapshot paused VM for %s seconds' %
                       (unpause_time - pause_time))
        return snapResult

    def _snapshot(self, snapType, cloneOp=False, cbtlog=None, cbt_consistency=None):
        util.SMlog("LVMVDI._snapshot for %s (type %s)" % (self.uuid, snapType))

        if not self.sr.isMaster:
            raise xs_errors.XenError('LVMMaster')
        if self.sr.legacyMode:
            raise xs_errors.XenError('Unimplemented', opterr='In legacy mode')

        self._loadThis()
        if self.hidden:
            raise xs_errors.XenError('VDISnapshot', opterr='hidden VDI')

        self.sm_config = self.session.xenapi.VDI.get_sm_config( \
                self.sr.srcmd.params['vdi_ref'])
        if "type" in self.sm_config and self.sm_config['type'] == 'raw':
            if not util.fistpoint.is_active("testsm_clone_allow_raw"):
                raise xs_errors.XenError('Unimplemented', \
                        opterr='Raw VDI, snapshot or clone not permitted')

        # we must activate the entire image chain because the real parent could
        # theoretically be anywhere in the chain if all images under it are empty
        self._chainSetActive(True, False)
        if not util.pathexists(self.path):
            raise xs_errors.XenError('VDIUnavailable', \
                    opterr='VDI unavailable: %s' % (self.path))

        if VdiType.isCowImage(self.vdi_type):
            depth = self.cowutil.getDepth(self.path)
            if depth == -1:
                raise xs_errors.XenError('VDIUnavailable', \
                        opterr='failed to get COW depth')
            elif depth >= self.cowutil.getMaxChainLength():
                raise xs_errors.XenError('SnapshotChainTooLong')

        self.issnap = self.session.xenapi.VDI.get_is_a_snapshot( \
                                                self.sr.srcmd.params['vdi_ref'])

        fullpr = self.lvmcowutil.calcVolumeSize(self.size)
        thinpr = util.roundup(
            lvutil.LVM_SIZE_INCREMENT,
            self.cowutil.calcOverheadEmpty(max(self.size, self.cowutil.getDefaultPreallocationSizeVirt()))
        )
        lvSizeOrig = thinpr
        lvSizeClon = thinpr

        hostRefs = []
        if self.sr.cmd == "vdi_snapshot":
            hostRefs = util.get_hosts_attached_on(self.session, [self.uuid])
            if hostRefs:
                lvSizeOrig = fullpr
        if self.sr.provision == "thick":
            if not self.issnap:
                lvSizeOrig = fullpr
            if self.sr.cmd != "vdi_snapshot":
                lvSizeClon = fullpr

        if (snapType == VDI.SNAPSHOT_SINGLE or
                snapType == VDI.SNAPSHOT_INTERNAL):
            lvSizeClon = 0

        # the space required must include 2 journal LVs: a clone journal and an
        # inflate journal (for the failure handling
        size_req = lvSizeOrig + lvSizeClon + 2 * self.sr.journaler.LV_SIZE
        lvSizeBase = self.size
        if VdiType.isCowImage(self.vdi_type):
            lvSizeBase = util.roundup(lvutil.LVM_SIZE_INCREMENT, self.cowutil.getSizePhys(self.path))
            size_req -= (self.utilisation - lvSizeBase)
        self.sr._ensureSpaceAvailable(size_req)

        if hostRefs:
            self.sr._updateSlavesPreClone(hostRefs, self.lvname)

        baseUuid = util.gen_uuid()
        origUuid = self.uuid
        clonUuid = ""
        if snapType == VDI.SNAPSHOT_DOUBLE:
            clonUuid = util.gen_uuid()
        jval = "%s_%s" % (baseUuid, clonUuid)
        self.sr.journaler.create(self.JRN_CLONE, origUuid, jval)
        util.fistpoint.activate("LVHDRT_clone_vdi_after_create_journal", self.sr.uuid)

        try:
            # self becomes the "base vdi"
            origOldLV = self.lvname
            baseLV = LV_PREFIX[self.vdi_type] + baseUuid
            self.sr.lvmCache.rename(self.lvname, baseLV)
            self.sr.lvActivator.replace(self.uuid, baseUuid, baseLV, False)
            RefCounter.set(baseUuid, 1, 0, NS_PREFIX_LVM + self.sr.uuid)
            self.uuid = baseUuid
            self.lvname = baseLV
            self.path = os.path.join(self.sr.path, baseLV)
            self.label = "base copy"
            self.read_only = True
            self.location = self.uuid
            self.managed = False

            # shrink the base copy to the minimum - we do it before creating
            # the snapshot volumes to avoid requiring double the space
            if VdiType.isCowImage(self.vdi_type):
                self.lvmcowutil.deflate(self.sr.lvmCache, self.lvname, lvSizeBase)
                self.utilisation = lvSizeBase
            util.fistpoint.activate("LVHDRT_clone_vdi_after_shrink_parent", self.sr.uuid)

            snapVDI = self._createSnap(origUuid, lvSizeOrig, False)
            util.fistpoint.activate("LVHDRT_clone_vdi_after_first_snap", self.sr.uuid)
            snapVDI2 = None
            if snapType == VDI.SNAPSHOT_DOUBLE:
                snapVDI2 = self._createSnap(clonUuid, lvSizeClon, True)
                # If we have CBT enabled on the VDI,
                # set CBT status for the new snapshot disk
                if cbtlog:
                    snapVDI2.cbt_enabled = True
            util.fistpoint.activate("LVHDRT_clone_vdi_after_second_snap", self.sr.uuid)

            # note: it is important to mark the parent hidden only AFTER the
            # new image children have been created, which are referencing it;
            # otherwise we would introduce a race with GC that could reclaim
            # the parent before we snapshot it
            if not VdiType.isCowImage(self.vdi_type):
                self.sr.lvmCache.setHidden(self.lvname)
            else:
                self.cowutil.setHidden(self.path)
            util.fistpoint.activate("LVHDRT_clone_vdi_after_parent_hidden", self.sr.uuid)

            # set the base copy to ReadOnly
            self.sr.lvmCache.setReadonly(self.lvname, True)
            util.fistpoint.activate("LVHDRT_clone_vdi_after_parent_ro", self.sr.uuid)

            if hostRefs:
                self.sr._updateSlavesOnClone(hostRefs, origOldLV,
                        snapVDI.lvname, self.uuid, self.lvname)

            # Update cbt files if user created snapshot (SNAPSHOT_DOUBLE)
            if snapType == VDI.SNAPSHOT_DOUBLE and cbtlog:
                snapVDI._cbt_snapshot(clonUuid, cbt_consistency)
                if hostRefs:
                    cbtlog_file = self._get_cbt_logname(snapVDI.uuid)
                    try:
                        self.sr._updateSlavesOnCBTClone(hostRefs, cbtlog_file)
                    except:
                        alert_name = "VDI_CBT_SNAPSHOT_FAILED"
                        alert_str = ("Creating CBT snapshot for {} failed"
                                     .format(snapVDI.uuid))
                        snapVDI._disable_cbt_on_error(alert_name, alert_str)
                        pass

        except (util.SMException, XenAPI.Failure) as e:
            util.logException("LVMVDI._snapshot")
            self._failClone(origUuid, jval, str(e))
        util.fistpoint.activate("LVHDRT_clone_vdi_before_remove_journal", self.sr.uuid)

        self.sr.journaler.remove(self.JRN_CLONE, origUuid)

        return self._finishSnapshot(snapVDI, snapVDI2, hostRefs, cloneOp, snapType)

    def _createSnap(self, snapUuid, snapSizeLV, isNew):
        """Snapshot self and return the snapshot VDI object"""
        snapLV = LV_PREFIX[self.vdi_type] + snapUuid
        snapPath = os.path.join(self.sr.path, snapLV)
        self.sr.lvmCache.create(snapLV, int(snapSizeLV))
        util.fistpoint.activate("LVHDRT_clone_vdi_after_lvcreate", self.sr.uuid)
        if isNew:
            RefCounter.set(snapUuid, 1, 0, NS_PREFIX_LVM + self.sr.uuid)
        self.sr.lvActivator.add(snapUuid, snapLV, False)
        parentRaw = (self.vdi_type == VdiType.RAW)
        self.cowutil.snapshot(
            snapPath, self.path, parentRaw, max(self.size, self.cowutil.getDefaultPreallocationSizeVirt())
        )
        snapParent = self.cowutil.getParent(snapPath, LvmCowUtil.extractUuid)

        snapVDI = LVMVDI(self.sr, snapUuid)
        snapVDI.read_only = False
        snapVDI.location = snapUuid
        snapVDI.size = self.size
        snapVDI.utilisation = snapSizeLV
        snapVDI.sm_config = dict()
        for key, val in self.sm_config.items():
            if key not in [
                    "type", "vdi_type", "vhd-parent", "paused", "relinking", "activating"] and \
                    not key.startswith("host_"):
                snapVDI.sm_config[key] = val
        snapVDI.sm_config["vdi_type"] = snapType
        snapVDI.sm_config["vhd-parent"] = snapParent
        snapVDI.lvname = snapLV
        return snapVDI

    def _finishSnapshot(self, snapVDI, snapVDI2, hostRefs, cloneOp=False, snapType=None):
        if snapType is not VDI.SNAPSHOT_INTERNAL:
            self.sr._updateStats(self.sr.uuid, self.size)
        basePresent = True

        # Verify parent locator field of both children and delete basePath if
        # unused
        snapParent = snapVDI.sm_config["vhd-parent"]
        snap2Parent = ""
        if snapVDI2:
            snap2Parent = snapVDI2.sm_config["vhd-parent"]
        if snapParent != self.uuid and \
                (not snapVDI2 or snap2Parent != self.uuid):
            util.SMlog("%s != %s != %s => deleting unused base %s" % \
                    (snapParent, self.uuid, snap2Parent, self.lvname))
            RefCounter.put(self.uuid, False, NS_PREFIX_LVM + self.sr.uuid)
            self.sr.lvmCache.remove(self.lvname)
            self.sr.lvActivator.remove(self.uuid, False)
            if hostRefs:
                self.sr._updateSlavesOnRemove(hostRefs, self.uuid, self.lvname)
            basePresent = False
        else:
            # assign the _binary_ refcount of the original VDI to the new base
            # VDI (but as the normal refcount, since binary refcounts are only
            # for leaf nodes). The normal refcount of the child is not
            # transferred to to the base VDI because normal refcounts are
            # incremented and decremented individually, and not based on the
            # image chain (i.e., the child's normal refcount will be decremented
            # independently of its parent situation). Add 1 for this clone op.
            # Note that we do not need to do protect the refcount operations
            # below with per-VDI locking like we do in lvutil because at this
            # point we have exclusive access to the VDIs involved. Other SM
            # operations are serialized by the Agent or with the SR lock, and
            # any coalesce activations are serialized with the SR lock.  (The
            # coalesce activates the coalesced VDI pair in the beginning, which
            # cannot affect the VDIs here because they cannot  possibly be
            # involved in coalescing at this point, and at the relinkSkip step
            # that activates the children, which takes the SR lock.)
            ns = NS_PREFIX_LVM + self.sr.uuid
            (cnt, bcnt) = RefCounter.check(snapVDI.uuid, ns)
            RefCounter.set(self.uuid, bcnt + 1, 0, ns)

        # the "paused" and "host_*" sm-config keys are special and must stay on
        # the leaf without being inherited by anyone else
        for key in [x for x in self.sm_config.keys() if x == "paused" or x.startswith("host_")]:
            snapVDI.sm_config[key] = self.sm_config[key]
            del self.sm_config[key]

        # Introduce any new VDI records & update the existing one
        type = self.session.xenapi.VDI.get_type( \
                                    self.sr.srcmd.params['vdi_ref'])
        if snapVDI2:
            LVMMetadataHandler(self.sr.mdpath).ensureSpaceIsAvailableForVdis(1)
            vdiRef = snapVDI2._db_introduce()
            if cloneOp:
                vdi_info = {UUID_TAG: snapVDI2.uuid,
                                NAME_LABEL_TAG: util.to_plain_string( \
                                    self.session.xenapi.VDI.get_name_label( \
                                    self.sr.srcmd.params['vdi_ref'])),
                                NAME_DESCRIPTION_TAG: util.to_plain_string( \
                                  self.session.xenapi.VDI.get_name_description(self.sr.srcmd.params['vdi_ref'])),
                                IS_A_SNAPSHOT_TAG: 0,
                                SNAPSHOT_OF_TAG: '',
                                SNAPSHOT_TIME_TAG: '',
                                TYPE_TAG: type,
                                VDI_TYPE_TAG: snapVDI2.sm_config['vdi_type'],
                                READ_ONLY_TAG: 0,
                                MANAGED_TAG: int(snapVDI2.managed),
                                METADATA_OF_POOL_TAG: ''
                }
            else:
                util.SMlog("snapshot VDI params: %s" % \
                    self.session.xenapi.VDI.get_snapshot_time(vdiRef))
                vdi_info = {UUID_TAG: snapVDI2.uuid,
                                NAME_LABEL_TAG: util.to_plain_string( \
                                    self.session.xenapi.VDI.get_name_label( \
                                    self.sr.srcmd.params['vdi_ref'])),
                                NAME_DESCRIPTION_TAG: util.to_plain_string( \
                                  self.session.xenapi.VDI.get_name_description(self.sr.srcmd.params['vdi_ref'])),
                                IS_A_SNAPSHOT_TAG: 1,
                                SNAPSHOT_OF_TAG: snapVDI.uuid,
                                SNAPSHOT_TIME_TAG: '',
                                TYPE_TAG: type,
                                VDI_TYPE_TAG: snapVDI2.sm_config['vdi_type'],
                                READ_ONLY_TAG: 0,
                                MANAGED_TAG: int(snapVDI2.managed),
                                METADATA_OF_POOL_TAG: ''
                }

            LVMMetadataHandler(self.sr.mdpath).addVdi(vdi_info)
            util.SMlog("vdi_clone: introduced 2nd snap VDI: %s (%s)" % \
                       (vdiRef, snapVDI2.uuid))

        if basePresent:
            LVMMetadataHandler(self.sr.mdpath).ensureSpaceIsAvailableForVdis(1)
            vdiRef = self._db_introduce()
            vdi_info = {UUID_TAG: self.uuid,
                                NAME_LABEL_TAG: self.label,
                                NAME_DESCRIPTION_TAG: self.description,
                                IS_A_SNAPSHOT_TAG: 0,
                                SNAPSHOT_OF_TAG: '',
                                SNAPSHOT_TIME_TAG: '',
                                TYPE_TAG: type,
                                VDI_TYPE_TAG: self.sm_config['vdi_type'],
                                READ_ONLY_TAG: 1,
                                MANAGED_TAG: 0,
                                METADATA_OF_POOL_TAG: ''
            }

            LVMMetadataHandler(self.sr.mdpath).addVdi(vdi_info)
            util.SMlog("vdi_clone: introduced base VDI: %s (%s)" % \
                    (vdiRef, self.uuid))

        # Update the original record
        vdi_ref = self.sr.srcmd.params['vdi_ref']
        self.session.xenapi.VDI.set_sm_config(vdi_ref, snapVDI.sm_config)
        self.session.xenapi.VDI.set_physical_utilisation(vdi_ref, \
                str(snapVDI.utilisation))

        # Return the info on the new snap VDI
        snap = snapVDI2
        if not snap:
            snap = self
            if not basePresent:
                # a single-snapshot of an empty VDI will be a noop, resulting
                # in no new VDIs, so return the existing one. The GC wouldn't
                # normally try to single-snapshot an empty image of course, but
                # if an external snapshot operation manages to sneak in right
                # before a snapshot-coalesce phase, we would get here
                snap = snapVDI
        return snap.get_params()

    def _setType(self, vdiType) -> None:
        self.vdi_type = vdiInfo.vdiType
        self.cowutil = getCowUtil(self.vdi_type)
        self.lvmcowutil = LvmCowUtil(self.cowutil)

    def _initFromVDIInfo(self, vdiInfo):
        self._setType(vdiType)
        self.lvname = vdiInfo.lvName
        self.size = vdiInfo.sizeVirt
        self.utilisation = vdiInfo.sizeLV
        self.hidden = vdiInfo.hidden
        if self.hidden:
            self.managed = False
        self.active = vdiInfo.lvActive
        self.readonly = vdiInfo.lvReadonly
        self.parent = vdiInfo.parentUuid
        self.path = os.path.join(self.sr.path, self.lvname)
        if hasattr(self, "sm_config_override"):
            self.sm_config_override["vdi_type"] = self.vdi_type
        else:
            self.sm_config_override = {'vdi_type': self.vdi_type}
        self.loaded = True

    def _initFromLVInfo(self, lvInfo):
        self._setType(lvInfo.vdiType)
        self.lvname = lvInfo.name
        self.size = lvInfo.size
        self.utilisation = lvInfo.size
        self.hidden = lvInfo.hidden
        self.active = lvInfo.active
        self.readonly = lvInfo.readonly
        self.parent = ''
        self.path = os.path.join(self.sr.path, self.lvname)
        if hasattr(self, "sm_config_override"):
            self.sm_config_override["vdi_type"] = self.vdi_type
        else:
            self.sm_config_override = {'vdi_type': self.vdi_type}
        if not VdiType.isCowImage(self.vdi_type):
            self.loaded = True

    def _initFromImageInfo(self, imageInfo):
        self.size = imageInfo.sizeVirt
        self.parent = imageInfo.parentUuid
        self.hidden = imageInfo.hidden
        self.loaded = True

    def _determineType(self):
        """
        Determine whether this is a RAW or a COW VDI.
        """
        if "vdi_ref" in self.sr.srcmd.params:
            vdi_ref = self.sr.srcmd.params["vdi_ref"]
            sm_config = self.session.xenapi.VDI.get_sm_config(vdi_ref)
            if sm_config.get("vdi_type"):
                self._setType(sm_config["vdi_type"])
                prefix = LV_PREFIX[self.vdi_type]
                self.lvname = "%s%s" % (prefix, self.uuid)
                self.path = os.path.join(self.sr.path, self.lvname)
                self.sm_config_override = sm_config
                return True

        # LVM commands can be costly, so check the file directly first in case
        # the LV is active
        found = False
        for vdiType, prefix in LV_PREFIX:
            lvname = "%s%s" % (prefix, self.uuid)
            path = os.path.join(self.sr.path, lvname)
            if util.pathexists(path):
                if found:
                    raise xs_errors.XenError('VDILoad',
                            opterr="multiple VDI's: uuid %s" % self.uuid)
                found = True
                self._setType(vdiType)
                self.lvname = lvname
                self.path = path
        if found:
            return True

        # now list all LV's
        if not lvutil._checkVG(self.sr.vgname):
            # when doing attach_from_config, the VG won't be there yet
            return False

        lvs = LvmCowUtil.getVolumeInfo(self.sr.lvmCache)
        if lvs.get(self.uuid):
            self._initFromLVInfo(lvs[self.uuid])
            return True
        return False

    def _loadThis(self):
        """
        Load VDI info for this VDI and activate the LV if it's COW. We
        don't do it in VDI.load() because not all VDI operations need it.
        """
        if self.loaded:
            if VdiType.isCowImage(self.vdi_type):
                self.sr.lvActivator.activate(self.uuid, self.lvname, False)
            return
        try:
            lvs = LvmCowUtil.getVolumeInfo(self.sr.lvmCache, self.lvname)
        except util.CommandException as e:
            raise xs_errors.XenError('VDIUnavailable',
                    opterr='%s (LV scan error)' % os.strerror(abs(e.code)))
        if not lvs.get(self.uuid):
            raise xs_errors.XenError('VDIUnavailable', opterr='LV not found')
        self._initFromLVInfo(lvs[self.uuid])
        if VdiType.isCowImage(self.vdi_type):
            self.sr.lvActivator.activate(self.uuid, self.lvname, False)
            imageInfo = self.cowutil.getInfo(self.path, LvmCowUtil.extractUuid, False)
            if not imageInfo:
                raise xs_errors.XenError('VDIUnavailable', opterr='getInfo failed')
            self._initFromImageInfo(imageInfo)
        self.loaded = True

    def _chainSetActive(self, active, binary, persistent=False):
        if binary:
            (count, bcount) = RefCounter.checkLocked(self.uuid,
                NS_PREFIX_LVM + self.sr.uuid)
            if (active and bcount > 0) or (not active and bcount == 0):
                return  # this is a redundant activation/deactivation call

        vdiList = {self.uuid: self.lvname}
        if VdiType.isCowImage(self.vdi_type):
            vdiList = self.cowutil.getParentChain(self.lvname, LvmCowUtil.extractUuid, self.sr.vgname)
        for uuid, lvName in vdiList.items():
            binaryParam = binary
            if uuid != self.uuid:
                binaryParam = False  # binary param only applies to leaf nodes
            if active:
                self.sr.lvActivator.activate(uuid, lvName, binaryParam,
                        persistent)
            else:
                # just add the LVs for deactivation in the final (cleanup)
                # step. The LVs must not have been activated during the current
                # operation
                self.sr.lvActivator.add(uuid, lvName, binaryParam)

    def _failClone(self, uuid, jval, msg):
        try:
            self.sr._handleInterruptedCloneOp(uuid, jval, True)
            self.sr.journaler.remove(self.JRN_CLONE, uuid)
        except Exception as e:
            util.SMlog('WARNING: failed to clean up failed snapshot: ' \
                    ' %s (error ignored)' % e)
        raise xs_errors.XenError('VDIClone', opterr=msg)

    def _markHidden(self):
        if not VdiType.isCowImage(self.vdi_type):
            self.sr.lvmCache.setHidden(self.lvname)
        else:
            self.cowutil.setHidden(self.path)
        self.hidden = 1

    def _prepareThin(self, attach):
        origUtilisation = self.sr.lvmCache.getSize(self.lvname)
        if self.sr.isMaster:
            # the master can prepare the VDI locally
            if attach:
                self.lvmcowutil.attachThin(self.sr.journaler, self.sr.uuid, self.uuid, self.vdi_type)
            else:
                self.lvmcowutil.detachThin(self.session, self.sr.lvmCache, self.sr.uuid, self.uuid, self.vdi_type)
        else:
            fn = "attach"
            if not attach:
                fn = "detach"
            pools = self.session.xenapi.pool.get_all()
            master = self.session.xenapi.pool.get_master(pools[0])
            rv = self.session.xenapi.host.call_plugin(
                    master, self.sr.THIN_PLUGIN, fn,
                    {"srUuid": self.sr.uuid, "vdiUuid": self.uuid})
            util.SMlog("call-plugin returned: %s" % rv)
            if not rv:
                raise Exception('plugin %s failed' % self.sr.THIN_PLUGIN)
            # refresh to pick up the size change on this slave
            self.sr.lvmCache.activateNoRefcount(self.lvname, True)

        self.utilisation = self.sr.lvmCache.getSize(self.lvname)
        if origUtilisation != self.utilisation:
            vdi_ref = self.sr.srcmd.params['vdi_ref']
            self.session.xenapi.VDI.set_physical_utilisation(vdi_ref,
                    str(self.utilisation))
            stats = lvutil._getVGstats(self.sr.vgname)
            sr_utilisation = stats['physical_utilisation']
            self.session.xenapi.SR.set_physical_utilisation(self.sr.sr_ref,
                    str(sr_utilisation))

    @override
    def update(self, sr_uuid, vdi_uuid) -> None:
        if self.sr.legacyMode:
            return

        #Synch the name_label of this VDI on storage with the name_label in XAPI
        vdi_ref = self.session.xenapi.VDI.get_by_uuid(self.uuid)
        update_map = {}
        update_map[METADATA_UPDATE_OBJECT_TYPE_TAG] = \
            METADATA_OBJECT_TYPE_VDI
        update_map[UUID_TAG] = self.uuid
        update_map[NAME_LABEL_TAG] = util.to_plain_string( \
            self.session.xenapi.VDI.get_name_label(vdi_ref))
        update_map[NAME_DESCRIPTION_TAG] = util.to_plain_string( \
            self.session.xenapi.VDI.get_name_description(vdi_ref))
        update_map[SNAPSHOT_TIME_TAG] = \
            self.session.xenapi.VDI.get_snapshot_time(vdi_ref)
        update_map[METADATA_OF_POOL_TAG] = \
            self.session.xenapi.VDI.get_metadata_of_pool(vdi_ref)
        LVMMetadataHandler(self.sr.mdpath).updateMetadata(update_map)

    @override
    def _ensure_cbt_space(self) -> None:
        self.sr.ensureCBTSpace()

    @override
    def _create_cbt_log(self) -> str:
        logname = self._get_cbt_logname(self.uuid)
        self.sr.lvmCache.create(logname, self.sr.journaler.LV_SIZE, CBTLOG_TAG)
        logpath = super(LVMVDI, self)._create_cbt_log()
        self.sr.lvmCache.deactivateNoRefcount(logname)
        return logpath

    @override
    def _delete_cbt_log(self) -> None:
        logpath = self._get_cbt_logpath(self.uuid)
        if self._cbt_log_exists(logpath):
            logname = self._get_cbt_logname(self.uuid)
            self.sr.lvmCache.remove(logname)

    @override
    def _rename(self, oldpath, newpath) -> None:
        oldname = os.path.basename(oldpath)
        newname = os.path.basename(newpath)
        self.sr.lvmCache.rename(oldname, newname)

    @override
    def _activate_cbt_log(self, lv_name) -> bool:
        self.sr.lvmCache.refresh()
        if not self.sr.lvmCache.is_active(lv_name):
            try:
                self.sr.lvmCache.activateNoRefcount(lv_name)
                return True
            except Exception as e:
                util.SMlog("Exception in _activate_cbt_log, "
                           "Error: %s." % str(e))
                raise
        else:
            return False

    @override
    def _deactivate_cbt_log(self, lv_name) -> None:
        try:
            self.sr.lvmCache.deactivateNoRefcount(lv_name)
        except Exception as e:
            util.SMlog("Exception in _deactivate_cbt_log, Error: %s." % str(e))
            raise

    @override
    def _cbt_log_exists(self, logpath) -> bool:
        return lvutil.exists(logpath)

if __name__ == '__main__':
    SRCommand.run(LVMSR, DRIVER_INFO)
else:
    SR.registerSR(LVMSR)
