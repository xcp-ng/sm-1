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

"""
Helper functions for LVMSR. This module knows about RAW, VHD and QCOW2 VDI's that live in LV's.
"""

from sm_typing import Dict, Final, List, Optional, Tuple, cast

import os
import sys
import time

import lock
import util
import XenAPI

from cowutil import CowImageInfo, CowUtil, getCowUtil
from journaler import Journaler
from lvmcache import LVInfo, LVMCache
from lvutil import calcSizeLV
from refcounter import RefCounter
from vditype import VdiType, VDI_COW_TYPES

# ------------------------------------------------------------------------------

VG_LOCATION: Final = "/dev"
VG_PREFIX: Final = "VG_XenStorage-"

# Ref counting for VDI's: we need a ref count for LV activation/deactivation
# on the master.
NS_PREFIX_LVM: Final = "lvm-"

LOCK_RETRY_ATTEMPTS: Final = 20

LV_PREFIX: Final = {
    VdiType.RAW: "LV-",
    VdiType.VHD: "VHD-",
    VdiType.QCOW2: "QCOW2-",
}

LV_PREFIX_TO_VDI_TYPE: Final = {v: k for k, v in LV_PREFIX.items()}

# ------------------------------------------------------------------------------

class VDIInfo:
    uuid = ""
    scanError = False
    vdiType = None
    lvName = ""
    sizeLV = -1
    sizeVirt = -1
    lvActive = False
    lvOpen = False
    lvReadonly = False
    hidden = False
    parentUuid = ""
    refcount = 0

    def __init__(self, uuid: str):
        self.uuid = uuid

# ------------------------------------------------------------------------------

class LvmCowUtil(object):
    JOURNAL_INFLATE: Final = "inflate"
    JOURNAL_RESIZE_TAG: Final = "jvhd"

    def __init__(self, cowutil: CowUtil):
        self.cowutil = cowutil

    def calcVolumeSize(self, sizeVirt: int) -> int:
        # all LVM COW VDIs have the metadata area preallocated for the maximum
        # possible virtual size in the VHD case (for fast online VDI.resize)
        metaOverhead = self.cowutil.calcOverheadEmpty(
            max(sizeVirt, self.cowutil.getDefaultPreallocationSizeVirt())
        )
        bitmapOverhead = self.cowutil.calcOverheadBitmap(sizeVirt)
        return calcSizeLV(sizeVirt + metaOverhead + bitmapOverhead)

    def createResizeJournal(self, lvmCache: LVMCache, jName: str) -> str:
        """
        Create a LV to hold a VDI resize journal.
        """
        size = self.cowutil.getResizeJournalSize()
        if size <= 0:
            return ''
        lvName = "%s_%s" % (self.JOURNAL_RESIZE_TAG, jName)
        lvmCache.create(lvName, size, self.JOURNAL_RESIZE_TAG)
        return os.path.join(lvmCache.vgPath, lvName)

    def destroyResizeJournal(self, lvmCache: LVMCache, jName: str) -> None:
        """
        Destroy a VDI resize journal.
        """
        if jName:
            lvName = "%s_%s" % (self.JOURNAL_RESIZE_TAG, jName)
            lvmCache.remove(lvName)

    @classmethod
    def getAllResizeJournals(cls, lvmCache: LVMCache) -> List[Tuple[str, str]]:
        """
        Get a list of all resize journals in VG vgName as (jName, sjFile) pairs.
        """
        journals = []
        lvList = lvmCache.getTagged(cls.JOURNAL_RESIZE_TAG)
        for lvName in lvList:
            jName = lvName[len(cls.JOURNAL_RESIZE_TAG) + 1:]
            journals.append((jName, lvName))
        return journals

    def setSizeVirt(
        self, journaler: Journaler, srUuid: str, vdiUuid: str, vdiType: str, size: int, jFile : str
    ) -> None:
        """
        When resizing the image virtual size, we might have to inflate the LV in
        case the metadata size increases.
        """
        lvName = LV_PREFIX[vdiType] + vdiUuid
        vgName = VG_PREFIX + srUuid
        path = os.path.join(VG_LOCATION, vgName, lvName)
        self.inflate(journaler, srUuid, vdiUuid, vdiType, self.calcVolumeSize(size))
        self.cowutil.setSizeVirt(path, size, jFile)

    def inflate(self, journaler: Journaler, srUuid: str, vdiUuid: str, vdiType: str, size: int) -> None:
        """
        Expand a VDI LV (and its image) to 'size'. If the LV is already bigger
        than that, it's a no-op. Does not change the virtual size of the VDI.
        """
        lvName = LV_PREFIX[vdiType] + vdiUuid
        vgName = VG_PREFIX + srUuid
        path = os.path.join(VG_LOCATION, vgName, lvName)
        lvmCache = journaler.lvmCache

        currSizeLV = lvmCache.getSize(lvName)
        newSize = calcSizeLV(size)
        if newSize <= currSizeLV:
            return
        journaler.create(self.JOURNAL_INFLATE, vdiUuid, str(currSizeLV))
        util.fistpoint.activate("LVHDRT_inflate_after_create_journal", srUuid)
        lvmCache.setSize(lvName, newSize)
        util.fistpoint.activate("LVHDRT_inflate_after_setSize", srUuid)
        footer_size = self.cowutil.getFooterSize()
        if not util.zeroOut(path, newSize - footer_size, footer_size):
            raise Exception('failed to zero out image footer')
        util.fistpoint.activate("LVHDRT_inflate_after_zeroOut", srUuid)
        self.cowutil.setSizePhys(path, newSize, False)
        util.fistpoint.activate("LVHDRT_inflate_after_setSizePhys", srUuid)
        journaler.remove(self.JOURNAL_INFLATE, vdiUuid)

    def deflate(self, lvmCache: LVMCache, lvName: str, size: int) -> None:
        """
        Shrink the LV and the image on it to 'size'. Does not change the
        virtual size of the VDI.
        """
        currSizeLV = lvmCache.getSize(lvName)
        newSize = calcSizeLV(size)
        if newSize >= currSizeLV:
            return
        path = os.path.join(VG_LOCATION, lvmCache.vgName, lvName)
        # no undo necessary if this fails at any point between now and the end
        self.cowutil.setSizePhys(path, newSize)
        lvmCache.setSize(lvName, newSize)

    def attachThin(self, journaler: Journaler, srUuid: str, vdiUuid: str, vdiType: str) -> None:
        """
        Ensure that the VDI LV is expanded to the fully-allocated size.
        """
        lvName = LV_PREFIX[vdiType] + vdiUuid
        vgName = VG_PREFIX + srUuid
        sr_lock = lock.Lock(lock.LOCK_TYPE_SR, srUuid)
        lvmCache = journaler.lvmCache
        self._tryAcquire(sr_lock)
        lvmCache.refresh()
        info = self.cowutil.getInfoFromLVM(lvName, self.extractUuid, vgName)
        if not info:
            raise Exception(f"unable to get LVM info from {vdiUuid}")
        newSize = self.calcVolumeSize(info.sizeVirt)
        currSizeLV = lvmCache.getSize(lvName)
        if newSize <= currSizeLV:
            return
        lvmCache.activate(NS_PREFIX_LVM + srUuid, vdiUuid, lvName, False)
        try:
            self.inflate(journaler, srUuid, vdiUuid, vdiType, newSize)
        finally:
            lvmCache.deactivate(NS_PREFIX_LVM + srUuid, vdiUuid, lvName, False)
        sr_lock.release()

    def detachThin(self, session: XenAPI.Session, lvmCache: LVMCache, srUuid: str, vdiUuid: str, vdiType: str) -> None:
        """
        Shrink the VDI to the minimal size if no one is using it.
        """
        lvName = LV_PREFIX[vdiType] + vdiUuid
        path = os.path.join(VG_LOCATION, VG_PREFIX + srUuid, lvName)
        sr_lock = lock.Lock(lock.LOCK_TYPE_SR, srUuid)
        self._tryAcquire(sr_lock)

        vdiRef = session.xenapi.VDI.get_by_uuid(vdiUuid)
        vbds = session.xenapi.VBD.get_all_records_where( \
                "field \"VDI\" = \"%s\"" % vdiRef)
        numPlugged = 0
        for vbdRec in vbds.values():
            if vbdRec["currently_attached"]:
                numPlugged += 1

        if numPlugged > 1:
            raise util.SMException("%s still in use by %d others" % \
                    (vdiUuid, numPlugged - 1))
        lvmCache.activate(NS_PREFIX_LVM + srUuid, vdiUuid, lvName, False)
        try:
            newSize = calcSizeLV(self.cowutil.getSizePhys(path))
            self.deflate(lvmCache, lvName, newSize)
        finally:
            lvmCache.deactivate(NS_PREFIX_LVM + srUuid, vdiUuid, lvName, False)
        sr_lock.release()

    @staticmethod
    def extractUuid(path: str) -> str:
        uuid = os.path.basename(path)
        if uuid.startswith(VG_PREFIX):
            # we are dealing with realpath
            uuid = uuid.replace("--", "-")
            uuid.replace(VG_PREFIX, "")
        for prefix in LV_PREFIX.values():
            if uuid.find(prefix) != -1:
                uuid = uuid.split(prefix)[-1]
                uuid = uuid.strip()
                # TODO: validate UUID format
                return uuid
        return ''

    @staticmethod
    def matchVolume(lvName: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Given LV name, return the VDI type and the UUID, or (None, None)
        if the name doesn't match any known type.
        """
        for vdiType, prefix in LV_PREFIX.items():
            if lvName.startswith(prefix):
                return (vdiType, lvName.replace(prefix, ""))
        return (None, None)

    @classmethod
    def getVolumeInfo(cls, lvmCache: LVMCache, lvName: Optional[str] = None) -> Dict[str, LVInfo]:
        """
        Load LV info for all LVs in the VG or an individual LV.
        This is a wrapper for lvutil.getLVInfo that filters out LV's that
        are not LVM COW VDI's and adds the vdi_type information.
        """
        allLVs = lvmCache.getLVInfo(lvName)

        lvs: Dict[str, LVInfo] = dict()
        for name, lv in allLVs.items():
            vdiType, uuid = cls.matchVolume(name)
            if not vdiType:
                continue
            lv.vdiType = vdiType
            lvs[cast(str, uuid)] = lv
        return lvs

    @classmethod
    def getVDIInfo(cls, lvmCache: LVMCache) -> Dict[str, VDIInfo]:
        """
        Load VDI info (both LV and if the VDI is not raw, VHD/QCOW2 info).
        """
        vdis: Dict[str, VDIInfo] = {}
        lvs = cls.getVolumeInfo(lvmCache)

        hasCowVdis = False
        for uuid, lvInfo in lvs.items():
            if VdiType.isCowImage(lvInfo.vdiType):
                hasCowVdis = True
            vdiInfo = VDIInfo(uuid)
            vdiInfo.vdiType = lvInfo.vdiType
            vdiInfo.lvName = lvInfo.name
            vdiInfo.sizeLV = lvInfo.size
            vdiInfo.sizeVirt = lvInfo.size
            vdiInfo.lvActive = lvInfo.active
            vdiInfo.lvOpen = lvInfo.open
            vdiInfo.lvReadonly = lvInfo.readonly
            vdiInfo.hidden = lvInfo.hidden
            vdis[uuid] = vdiInfo

        if not hasCowVdis:
            return vdis

        for vdi_type in VDI_COW_TYPES:
            pattern = "%s*" % LV_PREFIX[vdi_type]
            scan_result = getCowUtil(vdi_type).getAllInfoFromVG(pattern, cls.extractUuid, lvmCache.vgName)
            uuids = vdis.keys()
            for uuid in uuids:
                vdi = vdis[uuid]
                if VdiType.isCowImage(vdi.vdiType):
                    if not scan_result.get(uuid):
                        lvmCache.refresh()
                        if lvmCache.checkLV(vdi.lvName):
                            util.SMlog("*** COW image info missing: %s" % uuid)
                            vdis[uuid].scanError = True
                        else:
                            util.SMlog("LV disappeared since last scan: %s" % uuid)
                            del vdis[uuid]
                    elif scan_result[uuid].error:
                        util.SMlog("*** cow-scan error: %s" % uuid)
                        vdis[uuid].scanError = True
                    else:
                        vdis[uuid].sizeVirt = vdis[uuid].sizeVirt
                        vdis[uuid].parentUuid = vdis[uuid].parentUuid
                        vdis[uuid].hidden = vdis[uuid].hidden
        return vdis

    @staticmethod
    def refreshVolumeOnSlaves(
        session: XenAPI.Session, srUuid: str, vgName: str, lvName: str, vdiUuid: str, slaves: List[str]
    ) -> None:
        args = {
            "vgName": vgName,
            "action1": "activate",
            "uuid1": vdiUuid,
            "ns1": NS_PREFIX_LVM + srUuid,
            "lvName1": lvName,
            "action2": "refresh",
            "lvName2": lvName,
            "action3": "deactivate",
            "uuid3": vdiUuid,
            "ns3": NS_PREFIX_LVM + srUuid,
            "lvName3": lvName
        }
        for slave in slaves:
            util.SMlog("Refreshing %s on slave %s" % (lvName, slave))
            text = session.xenapi.host.call_plugin(slave, "on-slave", "multi", args)
            util.SMlog("call-plugin returned: '%s'" % text)

    @classmethod
    def refreshVolumeOnAllSlaves(
        cls, session: XenAPI.Session, srUuid: str, vgName: str, lvName: str, vdiUuid: str
    ) -> None:
        cls.refreshVolumeOnSlaves(session, srUuid, vgName, lvName, vdiUuid, util.get_all_slaves(session))

    @staticmethod
    def _tryAcquire(lock):
        """
        We must give up if the SR is locked because it could be locked by the
        coalesce thread trying to acquire the VDI lock we're holding, so as to
        avoid deadlock.
        """
        for i in range(LOCK_RETRY_ATTEMPTS):
            gotLock = lock.acquireNoblock()
            if gotLock:
                return
            time.sleep(1)
        raise util.SRBusyException()

# ------------------------------------------------------------------------------

def setInnerNodeRefcounts(lvmCache: LVMCache, srUuid: str) -> List[str]:
    """
    [Re]calculate and set the refcounts for inner image nodes based on
    refcounts of the leaf nodes. We can infer inner node refcounts on slaves
    directly because they are in use only when VDIs are attached - as opposed
    to the Master case where the coalesce process can also operate on inner
    nodes.
    Return all LVs (paths) that are active but not in use (i.e. that should
    be deactivated).
    """
    vdiInfo = LvmCowUtil.getVDIInfo(lvmCache)
    for uuid, vdi in vdiInfo.items():
        vdi.refcount = 0

    ns = NS_PREFIX_LVM + srUuid
    for uuid, vdi in vdiInfo.items():
        if vdi.hidden:
            continue  # only read leaf refcounts
        refcount = RefCounter.check(uuid, ns)
        assert(refcount == (0, 0) or refcount == (0, 1))
        if refcount[1]:
            vdi.refcount = 1
            while vdi.parentUuid:
                vdi = vdiInfo[vdi.parentUuid]
                vdi.refcount += 1

    pathsNotInUse = []
    for uuid, vdi in vdiInfo.items():
        if vdi.hidden:
            util.SMlog("Setting refcount for %s to %d" % (uuid, vdi.refcount))
            RefCounter.set(uuid, vdi.refcount, 0, ns)
        if vdi.refcount == 0 and vdi.lvActive:
            path = os.path.join("/dev", lvmCache.vgName, vdi.lvName)
            pathsNotInUse.append(path)

    return pathsNotInUse

# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # used by the master changeover script
    cmd = sys.argv[1]
    if cmd == "fixrefcounts":
        srUuid = sys.argv[2]
        try:
            vgName = VG_PREFIX + srUuid
            lvmCache = LVMCache(vgName)
            setInnerNodeRefcounts(lvmCache, srUuid)
        except:
            util.logException("setInnerNodeRefcounts")
    else:
        util.SMlog("Invalid usage")
        print("Usage: %s fixrefcounts <sr_uuid>" % sys.argv[0])
