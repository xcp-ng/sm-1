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
# Helper functions pertaining to VHD operations
#

from sm_typing import Callable, Dict, Final, Optional, Sequence, cast, override

from abc import abstractmethod

import errno
import os
import re
import zlib

from cowutil import CowImageInfo, CowUtil
import util
import XenAPI # pylint: disable=import-error
import xs_errors

# ------------------------------------------------------------------------------

MIN_VHD_SIZE: Final = 2 * 1024 * 1024
MAX_VHD_SIZE: Final = 2040 * 1024 * 1024 * 1024

MAX_VHD_JOURNAL_SIZE: Final = 6 * 1024 * 1024  # 2MB VHD block size, max 2TB VHD size.

VHD_BLOCK_SIZE: Final = 2 * 1024 * 1024

VHD_FOOTER_SIZE: Final = 512

MAX_VHD_CHAIN_LENGTH: Final = 30

VHD_UTIL: Final = "/usr/bin/vhd-util"

OPT_LOG_ERR: Final = "--debug"

# ------------------------------------------------------------------------------

class VhdUtil(CowUtil):
    @override
    def getMinImageSize(self) -> int:
        return MIN_VHD_SIZE

    @override
    def getMaxImageSize(self) -> int:
        return MAX_VHD_SIZE

    @override
    def getBlockSize(self, path: str) -> int:
        return VHD_BLOCK_SIZE

    @override
    def getFooterSize(self, path: str) -> int:
        return VHD_FOOTER_SIZE

    @override
    def getMaxChainLength(self) -> int:
        return MAX_VHD_CHAIN_LENGTH

    @override
    def calcOverheadEmpty(self, virtual_size: int) -> int:
        """
        Calculate the VHD space overhead (metadata size) for an empty VDI of
        size virtual_size.
        """
        overhead = 0
        size_mb = virtual_size // (1024 * 1024)

        # Footer + footer copy + header + possible CoW parent locator fields
        overhead = 3 * 1024

        # BAT 4 Bytes per block segment
        overhead += (size_mb // 2) * 4
        overhead = util.roundup(512, overhead)

        # BATMAP 1 bit per block segment
        overhead += (size_mb // 2) // 8
        overhead = util.roundup(4096, overhead)

        return overhead

    @override
    def calcOverheadBitmap(self, virtual_size: int) -> int:
        num_blocks = virtual_size // VHD_BLOCK_SIZE
        if virtual_size % VHD_BLOCK_SIZE:
            num_blocks += 1
        return num_blocks * 4096

    @override
    def getInfo(
        self,
        path: str,
        extractUuidFunction: Callable[[str], str],
        includeParent: bool = True,
        resolveParent: bool = True,
        useBackupFooter: bool = False
    ) -> CowImageInfo:
        """
        Get the VHD info. The parent info may optionally be omitted: vhd-util
        tries to verify the parent by opening it, which results in error if the VHD
        resides on an inactive LV.
        """
        opts = "-vsaf"
        if includeParent:
            opts += "p"
            if not resolveParent:
                opts += "u"
        if useBackupFooter:
            opts += "b"

        ret = cast(str, self._ioretry([VHD_UTIL, "query", OPT_LOG_ERR, opts, "-n", path]))
        fields = ret.strip().split("\n")
        uuid = extractUuidFunction(path)
        vhdInfo = CowImageInfo(uuid)
        vhdInfo.sizeVirt = int(fields[0]) * 1024 * 1024
        vhdInfo.sizePhys = int(fields[1])
        nextIndex = 2
        if includeParent:
            if fields[nextIndex].find("no parent") == -1:
                vhdInfo.parentPath = fields[nextIndex]
                vhdInfo.parentUuid = extractUuidFunction(fields[nextIndex])
            nextIndex += 1
        vhdInfo.hidden = bool(int(fields[nextIndex].replace("hidden: ", "")))
        vhdInfo.sizeAllocated = self._convertAllocatedSizeToBytes(int(fields[nextIndex+1]))
        vhdInfo.path = path
        return vhdInfo

    @override
    def getInfoFromLVM(
        self, lvName: str, extractUuidFunction: Callable[[str], str], vgName: str
    ) -> Optional[CowImageInfo]:
        """
        Get the VHD info. This function does not require the container LV to be
        active, but uses LVs & VGs.
        """
        ret = cast(str, self._ioretry([VHD_UTIL, "scan", "-f", "-l", vgName, "-m", lvName]))
        return self._parseVHDInfo(ret, extractUuidFunction)

    @override
    def getAllInfoFromVG(
        self,
        pattern: str,
        extractUuidFunction: Callable[[str], str],
        vgName: Optional[str] = None,
        parents: bool = False,
        exitOnError: bool = False
    ) -> Dict[str, CowImageInfo]:
        result: Dict[str, CowImageInfo] = dict()
        cmd = [VHD_UTIL, "scan", "-f", "-m", pattern]
        if vgName:
            cmd.append("-l")
            cmd.append(vgName)
        if parents:
            cmd.append("-a")
        try:
            ret = cast(str, self._ioretry(cmd))
        except Exception as e:
            util.SMlog("WARN: VHD scan failed: output: %s" % e)
            ret = cast(str, self._ioretry(cmd + ["-c"]))
            util.SMlog("WARN: VHD scan with NOFAIL flag, output: %s" % ret)
        for line in ret.split('\n'):
            if not line.strip():
                continue
            info = self._parseVHDInfo(line, extractUuidFunction)
            if info:
                if info.error != 0 and exitOnError:
                    # Just return an empty dict() so the scan will be done
                    # again by getParentChain. See CA-177063 for details on
                    # how this has been discovered during the stress tests.
                    return dict()
                result[info.uuid] = info
            else:
                util.SMlog("WARN: VHD info line doesn't parse correctly: %s" % line)
        return result

    @override
    def getParent(self, path: str, extractUuidFunction: Callable[[str], str]) -> Optional[str]:
        ret = cast(str, self._ioretry([VHD_UTIL, "query", OPT_LOG_ERR, "-p", "-n", path]))
        if ret.find("query failed") != -1 or ret.find("Failed opening") != -1:
            raise util.SMException("VHD query returned %s" % ret)
        if ret.find("no parent") != -1:
            return None
        return extractUuidFunction(ret)

    @override
    def getParentNoCheck(self, path: str) -> Optional[str]:
        text = util.pread([VHD_UTIL, "read", "-p", "-n", "%s" % path])
        util.SMlog(text)
        for line in text.split("\n"):
            if line.find("decoded name :") != -1:
                val = line.split(":")[1].strip()
                vdi = val.replace("--", "-")[-40:]
                if vdi[1:].startswith("LV-"):
                    vdi = vdi[1:]
                return vdi
        return None

    @override
    def hasParent(self, path: str) -> bool:
        """
        Check if the VHD has a parent. A VHD has a parent iff its type is
        'Differencing'. This function does not need the parent to actually
        be present (e.g. the parent LV to be activated).
        """
        ret = cast(str, self._ioretry([VHD_UTIL, "read", OPT_LOG_ERR, "-p", "-n", path]))
        # pylint: disable=no-member
        m = re.match(r".*Disk type\s+: (\S+) hard disk.*", ret, flags=re.S)
        if m:
            vhd_type = m.group(1)
            assert vhd_type == "Differencing" or vhd_type == "Dynamic"
            return vhd_type == "Differencing"
        assert False, f"Ill-formed {VHD_UTIL} output detected during VHD parent parsing"

    @override
    def setParent(self, path: str, parentPath: str, parentRaw: bool) -> None:
        normpath = os.path.normpath(parentPath)
        cmd = [VHD_UTIL, "modify", OPT_LOG_ERR, "-p", normpath, "-n", path]
        if parentRaw:
            cmd.append("-m")
        self._ioretry(cmd)

    @override
    def getHidden(self, path: str) -> bool:
        ret = cast(str, self._ioretry([VHD_UTIL, "query", OPT_LOG_ERR, "-f", "-n", path]))
        return bool(int(ret.split(":")[-1].strip()))

    @override
    def setHidden(self, path: str, hidden: bool = True) -> None:
        opt = "1"
        if not hidden:
            opt = "0"
        self._ioretry([VHD_UTIL, "set", OPT_LOG_ERR, "-n", path, "-f", "hidden", "-v", opt])

    @override
    def getSizeVirt(self, path: str) -> int:
        ret = self._ioretry([VHD_UTIL, "query", OPT_LOG_ERR, "-v", "-n", path])
        return int(ret) * 1024 * 1024

    @override
    def setSizeVirt(self, path: str, size: int, jFile: str) -> None:
        """
        Resize VHD offline
        """
        size_mb = size // (1024 * 1024)
        self._ioretry([VHD_UTIL, "resize", OPT_LOG_ERR, "-s", str(size_mb), "-n", path, "-j", jFile])

    @override
    def setSizeVirtFast(self, path: str, size: int) -> None:
        """
        Resize VHD online.
        """
        size_mb = size // (1024 * 1024)
        self._ioretry([VHD_UTIL, "resize", OPT_LOG_ERR, "-s", str(size_mb), "-n", path, "-f"])

    @override
    def getMaxResizeSize(self, path: str) -> int:
        """
        Get the max virtual size for fast resize.
        """
        ret = self._ioretry([VHD_UTIL, "query", OPT_LOG_ERR, "-S", "-n", path])
        return int(ret) * 1024 * 1024

    @override
    def getSizePhys(self, path: str) -> int:
        return int(self._ioretry([VHD_UTIL, "query", OPT_LOG_ERR, "-s", "-n", path]))

    @override
    def setSizePhys(self, path: str, size: int, debug: bool = True) -> None:
        """
        Set physical utilisation (applicable to VHD's on fixed-size files).
        """
        if debug:
            cmd = [VHD_UTIL, "modify", OPT_LOG_ERR, "-s", str(size), "-n", path]
        else:
            cmd = [VHD_UTIL, "modify", "-s", str(size), "-n", path]
        self._ioretry(cmd)

    @override
    def getAllocatedSize(self, path: str) -> int:
        ret = self._ioretry([VHD_UTIL, "query", OPT_LOG_ERR, "-a", "-n", path])
        return self._convertAllocatedSizeToBytes(int(ret))

    @override
    def getResizeJournalSize(self) -> int:
        return MAX_VHD_JOURNAL_SIZE

    @override
    def killData(self, path: str) -> None:
        """
        Zero out the disk (kill all data inside the VHD file).
        """
        self._ioretry([VHD_UTIL, "modify", OPT_LOG_ERR, "-z", "-n", path])

    @override
    def getDepth(self, path: str) -> int:
        """
        Get the VHD parent chain depth.
        """
        text = cast(str, self._ioretry([VHD_UTIL, "query", OPT_LOG_ERR, "-d", "-n", path]))
        depth = -1
        if text.startswith("chain depth:"):
            depth = int(text.split(":")[1].strip())
        return depth

    @override
    def getBlockBitmap(self, path: str) -> bytes:
        text = cast(bytes, self._ioretry([VHD_UTIL, "read", OPT_LOG_ERR, "-B", "-n", path], text=False))
        return zlib.compress(text)

    @override
    def coalesce(self, path: str) -> int:
        """
        Coalesce the VHD, on success it returns the number of sectors coalesced.
        """
        text = cast(str, self._ioretry([VHD_UTIL, "coalesce", OPT_LOG_ERR, "-n", path]))
        match = re.match(r"^Coalesced (\d+) sectors", text)
        if match:
            return int(match.group(1))
        return 0

    @override
    def create(self, path: str, size: int, static: bool, msize: int = 0) -> None:
        size_mb = size // (1024 * 1024)
        cmd = [VHD_UTIL, "create", OPT_LOG_ERR, "-n", path, "-s", str(size_mb)]
        if static:
            cmd.append("-r")
        if msize:
            cmd.append("-S")
            cmd.append(str(msize))
        self._ioretry(cmd)

    @override
    def snapshot(
        self,
        path: str,
        parent: str,
        parentRaw: bool,
        msize: int = 0,
        checkEmpty: Optional[bool] = True
    ) -> None:
        cmd = [VHD_UTIL, "snapshot", OPT_LOG_ERR, "-n", path, "-p", parent]
        if parentRaw:
            cmd.append("-m")
        if msize:
            cmd.append("-S")
            cmd.append(str(msize))
        if not checkEmpty:
            cmd.append("-e")
        self._ioretry(cmd)

    @override
    def check(
        self,
        path: str,
        ignoreMissingFooter: Optional[bool] = False,
        fast: Optional[bool] = False
    ) -> CowUtil.CheckResult:
        cmd = [VHD_UTIL, "check", OPT_LOG_ERR, "-n", path]
        if ignoreMissingFooter:
            cmd.append("-i")
        if fast:
            cmd.append("-B")
        try:
            self._ioretry(cmd)
            return CowUtil.CheckResult.Success
        except util.CommandException as e:
            if e.code in (errno.ENOENT, errno.EROFS, errno.EMEDIUMTYPE):
                return CowUtil.CheckResult.Unavailable
            return CowUtil.CheckResult.Fail

    @override
    def revert(self, path: str, jFile: str) -> None:
        self._ioretry([VHD_UTIL, "revert", OPT_LOG_ERR, "-n", path, "-j", jFile])

    @override
    def repair(self, path: str) -> None:
        """
        Repairs a VHD.
        """
        self._ioretry([VHD_UTIL, "repair", "-n", path])

    @override
    def validateAndRoundImageSize(self, size: int) -> int:
        """
        Take the supplied vhd size, in bytes, and check it is positive and less
        that the maximum supported size, rounding up to the next block boundary.
        """
        if size < 0 or size > MAX_VHD_SIZE:
            raise xs_errors.XenError(
                "VDISize",
                opterr="VDI size must be between 1 MB and %d MB" % (MAX_VHD_SIZE // (1024 * 1024))
            )

        if size < MIN_VHD_SIZE:
            size = MIN_VHD_SIZE

        return util.roundup(VHD_BLOCK_SIZE, size)

    @override
    def getKeyHash(self, path: str) -> Optional[str]:
        """
        Extract the hash of the encryption key from the header of an encrypted VHD.
        """
        ret = cast(str, self._ioretry([VHD_UTIL, "key", "-p", "-n", path])).strip()
        if ret == "none":
            return None
        vals = ret.split()
        if len(vals) != 2:
            util.SMlog("***** malformed output from vhd-util for VHD {}: \"{}\"".format(path, ret))
            return None
        [_nonce, key_hash] = vals
        return key_hash

    @override
    def setKey(self, path: str, key_hash: str) -> None:
        """
        Set the encryption key for a VHD.
        """
        self._ioretry([VHD_UTIL, "key", "-s", "-n", path, "-H", key_hash])

    @staticmethod
    def _convertAllocatedSizeToBytes(size: int):
        # Assume we have standard 2MB allocation blocks
        return size * 2 * 1024 * 1024

    @staticmethod
    def _parseVHDInfo(line: str, extractUuidFunction: Callable[[str], str]) -> Optional[CowImageInfo]:
        vhdInfo = None
        valueMap = line.split()

        try:
            (key, val) = valueMap[0].split("=")
        except:
            return None

        if key != "vhd":
            return None
 
        uuid = extractUuidFunction(val)
        if not uuid:
            util.SMlog("***** malformed output, no UUID: %s" % valueMap)
            return None
        vhdInfo = CowImageInfo(uuid)
        vhdInfo.path = val

        for keyval in valueMap:
            (key, val) = keyval.split("=")
            if key == "scan-error":
                vhdInfo.error = line
                util.SMlog("***** VHD scan error: %s" % line)
                break
            elif key == "capacity":
                vhdInfo.sizeVirt = int(val)
            elif key == "size":
                vhdInfo.sizePhys = int(val)
            elif key == "hidden":
                vhdInfo.hidden = bool(int(val))
            elif key == "parent" and val != "none":
                vhdInfo.parentPath = val
                vhdInfo.parentUuid = extractUuidFunction(val)
        return vhdInfo
