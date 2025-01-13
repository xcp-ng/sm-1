#!/usr/bin/env python3
#
# Copyright (C) 2024  Vates SAS
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

from sm_typing import Any, Callable, Dict, Final, List, Optional, Sequence, Union, override

from abc import ABC, abstractmethod
from enum import IntEnum

import errno
import time

import util

from vditype import VdiType

# ------------------------------------------------------------------------------

IMAGE_FORMAT_COW_FLAG: Final = 1 << 8

class ImageFormat(IntEnum):
    RAW   = 1
    VHD   = 2 | IMAGE_FORMAT_COW_FLAG
    QCOW2 = 3 | IMAGE_FORMAT_COW_FLAG

IMAGE_FORMAT_TO_STR: Final = {
    ImageFormat.RAW:   "raw",
    ImageFormat.VHD:   "vhd",
    ImageFormat.QCOW2: "qcow2"
}

STR_TO_IMAGE_FORMAT: Final = {v: k for k, v in IMAGE_FORMAT_TO_STR.items()}

# ------------------------------------------------------------------------------

def parseImageFormats(str_formats: Optional[str], default_formats: List[ImageFormat]) -> List[ImageFormat]:
    if not str_formats:
        return default_formats

    entries = [entry.strip() for entry in str_formats.split(",")]

    image_formats: List[ImageFormat] = []
    for entry in entries:
        image_format = STR_TO_IMAGE_FORMAT.get(entry)
        if image_format:
          image_formats.append(image_format)

    if image_formats:
        return image_formats

    return default_formats

# ------------------------------------------------------------------------------

class CowImageInfo(object):
    uuid = ""
    path = ""
    sizeVirt = -1
    sizePhys = -1
    sizeAllocated = -1
    hidden = False
    parentUuid = ""
    parentPath = ""
    error: Any = 0

    def __init__(self, uuid):
        self.uuid = uuid

# ------------------------------------------------------------------------------

class CowUtil(ABC):
    class CheckResult(IntEnum):
        Success = 0
        Fail = 1
        Unavailable = 2

    @abstractmethod
    def getMinImageSize(self) -> int:
        pass

    @abstractmethod
    def getMaxImageSize(self) -> int:
        pass

    @abstractmethod
    def getBlockSize(self, path: str) -> int:
        pass

    @abstractmethod
    def getFooterSize(self) -> int:
        pass

    @abstractmethod
    def getDefaultPreallocationSizeVirt(self) -> int:
        pass

    @abstractmethod
    def getMaxChainLength(self) -> int:
        pass

    @abstractmethod
    def calcOverheadEmpty(self, virtual_size: int) -> int:
        pass

    @abstractmethod
    def calcOverheadBitmap(self, virtual_size: int) -> int:
        pass

    @abstractmethod
    def getInfo(
        self,
        path: str,
        extractUuidFunction: Callable[[str], str],
        includeParent: bool = True,
        resolveParent: bool = True,
        useBackupFooter: bool = False
    ) -> CowImageInfo:
        pass

    @abstractmethod
    def getInfoFromLVM(
        self, lvName: str, extractUuidFunction: Callable[[str], str], vgName: str
    ) -> Optional[CowImageInfo]:
        pass

    @abstractmethod
    def getAllInfoFromVG(
        self,
        pattern: str,
        extractUuidFunction: Callable[[str], str],
        vgName: Optional[str] = None,
        parents: bool = False,
        exitOnError: bool = False
    ) -> Dict[str, CowImageInfo]:
        pass

    @abstractmethod
    def getParent(self, path: str, extractUuidFunction: Callable[[str], str]) -> Optional[str]:
        pass

    @abstractmethod
    def getParentNoCheck(self, path: str) -> Optional[str]:
        pass

    @abstractmethod
    def hasParent(self, path: str) -> bool:
        pass

    @abstractmethod
    def setParent(self, path: str, parentPath: str, parentRaw: bool) -> None:
        pass

    @abstractmethod
    def getHidden(self, path: str) -> bool:
        pass

    @abstractmethod
    def setHidden(self, path: str, hidden: bool = True) -> None:
        pass

    @abstractmethod
    def getSizeVirt(self, path: str) -> int:
        pass

    @abstractmethod
    def setSizeVirt(self, path: str, size: int, jFile: str) -> None:
        pass

    @abstractmethod
    def setSizeVirtFast(self, path: str, size: int) -> None:
        pass

    @abstractmethod
    def getMaxResizeSize(self, path: str) -> int:
        pass

    @abstractmethod
    def getSizePhys(self, path: str) -> int:
        pass

    @abstractmethod
    def setSizePhys(self, path: str, size: int, debug: bool = True) -> None:
        pass

    @abstractmethod
    def getAllocatedSize(self, path: str) -> int:
        pass

    @abstractmethod
    def getResizeJournalSize(self) -> int:
        pass

    @abstractmethod
    def killData(self, path: str) -> None:
        pass

    @abstractmethod
    def getDepth(self, path: str) -> int:
        pass

    @abstractmethod
    def getBlockBitmap(self, path: str) -> bytes:
        pass

    @abstractmethod
    def coalesce(self, path: str) -> int:
        pass

    @abstractmethod
    def create(self, path: str, size: int, static: bool, msize: int = 0) -> None:
        pass

    @abstractmethod
    def snapshot(
        self,
        path: str,
        parent: str,
        parentRaw: bool,
        msize: int = 0,
        checkEmpty: Optional[bool] = True
    ) -> None:
        pass

    @abstractmethod
    def check(
        self,
        path: str,
        ignoreMissingFooter: Optional[bool] = False,
        fast: Optional[bool] = False
    ) -> CheckResult:
        pass

    @abstractmethod
    def revert(self, path: str, jFile: str) -> None:
        pass

    @abstractmethod
    def repair(self, path: str) -> None:
        pass

    @abstractmethod
    def validateAndRoundImageSize(self, size: int) -> int:
        pass

    @abstractmethod
    def getKeyHash(self, path: str) -> Optional[str]:
        pass

    @abstractmethod
    def setKey(self, path: str, key_hash: str) -> None:
        pass

    def getParentChain(self, lvName: str, extractUuidFunction: Callable[[str], str], vgName: str) -> Dict[str, str]:
        """
        Get the chain of all parents of 'path'. Safe to call for raw VDI's as well.
        """
        chain = {}
        vdis: Dict[str, CowImageInfo] = {}
        retries = 0
        while (not vdis):
            if retries > 60:
                util.SMlog('ERROR: getAllInfoFromVG returned 0 VDIs after %d retries' % retries)
                util.SMlog('ERROR: the image metadata might be corrupted')
                break
            vdis = self.getAllInfoFromVG(lvName, extractUuidFunction, vgName, True, True)
            if (not vdis):
                retries = retries + 1
                time.sleep(1)
        for uuid, vdi in vdis.items():
            chain[uuid] = vdi.path
        #util.SMlog("Parent chain for %s: %s" % (lvName, chain))
        return chain

    @staticmethod
    def isCowImage(image_format: ImageFormat) -> bool:
        return bool(image_format & IMAGE_FORMAT_COW_FLAG)

    @staticmethod
    def _ioretry(cmd: Sequence[str], text: bool = True) -> Union[str, bytes]:
        return util.ioretry(
            lambda: util.pread2(cmd, text=text),
            errlist=[errno.EIO, errno.EAGAIN]
        )

# ------------------------------------------------------------------------------

def getImageFormatFromVdiType(vdi_type: str) -> ImageFormat:
    if vdi_type == VdiType.RAW:
        return ImageFormat.RAW
    if vdi_type == VdiType.VHD:
        return ImageFormat.VHD
    if vdi_type == VdiType.QCOW2:
        return ImageFormat.QCOW2

    assert False, f"Unsupported vdi type: {vdi_type}"

def getVdiTypeFromImageFormat(image_format: ImageFormat) -> str:
    if image_format == ImageFormat.RAW:
        return VdiType.RAW
    if image_format == ImageFormat.VHD:
        return VdiType.VHD
    if image_format == ImageFormat.QCOW2:
        return VdiType.QCOW2

    assert False, f"Unsupported image format: {IMAGE_FORMAT_TO_STR[image_format]}"

def getCowUtil(vdi_type: str) -> CowUtil:
    import vhdutil

    if getImageFormatFromVdiType(vdi_type) in (ImageFormat.RAW, ImageFormat.VHD):
        return vhdutil.VhdUtil()

    assert False, f"Unsupported VDI type: {vdi_type}"
