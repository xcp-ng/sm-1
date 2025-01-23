from sm_typing import Any, Callable, Dict, Final, List, Optional, override, cast
from typing import BinaryIO

import errno
import struct
from pathlib import Path
import zlib
import os

import util
from cowutil import CowUtil, CowImageInfo

MAX_QCOW_CHAIN_LENGTH: Final = 30

QCOW_CLUSTER_SIZE: Final = 64 * 1024 # 64 KiB

MIN_QCOW_SIZE: Final = QCOW_CLUSTER_SIZE

MAX_QCOW_SIZE: Final = 16 * 1024 * 1024 * 1024 * 1024

QEMU_IMG: Final = "/usr/bin/qemu-img"
#QEMU_IMG: Final = "/usr/lib64/xen/bin/qemu-img"

QCOW2_TYPE: Final = "qcow2"


class QCowUtil(CowUtil):

    # We followed specifications found here:
    # https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt

    QCOW2_MAGIC = 0x514649FB  # b"QFI\xfb": Magic number for QCOW2 files
    QCOW2_HEADER_SIZE = 104  # In fact the last information we need is at offset 40-47
    QCOW2_L2_SIZE = QCOW_CLUSTER_SIZE
    QCOW2_BACKING_FILE_OFFSET = 8

    ALLOCATED_ENTRY_BIT = (
        0x8000_0000_0000_0000  # Bit 63 is the allocated bit for standard cluster
    )
    CLUSTER_TYPE_BIT = 0x4000_0000_0000_0000  # 0 for standard, 1 for compressed cluster
    L2_OFFSET_MASK = 0x00FF_FFFF_FFFF_FF00  # Bits 9-55 are offset of L2 table.
    CLUSTER_DESCRIPTION_MASK = 0x3FFF_FFFF_FFFF_FFFF  # Bit 0-61 is cluster description
    STANDARD_CLUSTER_OFFSET_MASK = (
        0x00FF_FFFF_FFFF_FF00  # Bits 9-55 are offset of standard cluster
    )

    def __init__(self):
        self.qcow_read = False

    def _read_qcow2(self, path: str):
        with open(path, "rb") as qcow2_file:
            self.filename = path  # Keep the filename if clean is called
            self.header = self._read_qcow2_header(qcow2_file)
            self.l1 = self._get_l1_entries(qcow2_file)
            # The l1_to_l2 allows to get L2 entries for a given L1. If L1 entry
            # is not allocated we store an empty list.
            self.l1_to_l2: Dict[int, List[int]] = {}

            for l1_entry in self.l1:
                l2_offset = l1_entry & self.L2_OFFSET_MASK
                if l2_offset == 0:
                    self.l1_to_l2[l1_entry] = []
                else:
                    self.l1_to_l2[l1_entry] = self._get_l2_entries(
                        qcow2_file, l2_offset
                    )
        self.qcow_read = True

    def _get_l1_entries(self, file: BinaryIO) -> List[int]:
        """Returns the list of all L1 entries.

        Args:
            file: The qcow2 file object.

        Returns:
            list: List of all L1 entries
        """
        l1_table_offset = self.header["l1_table_offset"]
        file.seek(l1_table_offset)

        l1_table_size = self.header["l1_size"] * 8  # Each L1 entry is 8 bytes
        l1_table = file.read(l1_table_size)

        return [
            struct.unpack(">Q", l1_table[i : i + 8])[0]
            for i in range(0, len(l1_table), 8)
        ]

    @staticmethod
    def _get_l2_entries(file: BinaryIO, l2_offset: int) -> List[int]:
        """Returns the list of all L2 entries at a given L2 offset.

        Args:
            file: The qcow2 file.
            l2_offset: the L2 offset where to look for entries

        Returns:
            list: List of all L2 entries
        """
        # The size of L2 is 65536 bytes and each entry is 8 bytes.
        file.seek(l2_offset)
        l2_table = file.read(QCowUtil.QCOW2_L2_SIZE)

        return [
            struct.unpack(">Q", l2_table[i : i + 8])[0]
            for i in range(0, len(l2_table), 8)
        ]

    @staticmethod
    def _read_qcow2_backingfile(file: BinaryIO, backing_file_offset: int , backing_file_size: int) -> str:
        if backing_file_offset == 0:
            return ""

        file.seek(backing_file_offset)
        parent_name = file.read(backing_file_size)
        return parent_name.decode("UTF-8")

    @staticmethod
    def _read_qcow2_header(file: BinaryIO) -> Dict[str, Any]:
        """Returns a dict containing some information from QCow2 header.

        Args:
            file: The qcow2 file object.

        Returns:
            dict: magic, version, cluster_bits, l1_size and l1_table_offset.

        Raises:
            ValueError: if qcow2 magic is not recognized or cluster size not supported.
        """
        # The header is as follow:
        #
        # magic: u32,                   // Magic string "QFI\xfb"
        # version: u32,                 // Version (2 or 3)
        # backing_file_offset: u64,     // Offset to the backing file name
        # backing_file_size: u32,       // Size of the backing file name
        # cluster_bits: u32,            // Bits used for addressing within a cluster
        # size: u64,                    // Virtual disk size
        # crypt_method: u32,            // 0 = no encryption, 1 = AES encryption
        # l1_size: u32,                 // Number of entries in the L1 table
        # l1_table_offset: u64,         // Offset to the active L1 table
        # refcount_table_offset: u64,   // Offset to the refcount table
        # refcount_table_clusters: u32, // Number of clusters for the refcount table
        # nb_snapshots: u32,            // Number of snapshots in the image
        # snapshots_offset: u64,        // Offset to the snapshot table

        file.seek(0)
        header = file.read(QCowUtil.QCOW2_HEADER_SIZE)
        (
            magic,
            version,
            backing_file_offset,
            backing_file_size,
            cluster_bits,
            size,
            _,
            l1_size,
            l1_table_offset,
            refcount_table_offset,
            _,
            _,
            snapshots_offset,
        ) = struct.unpack(">IIQIIQIIQQIIQ", header[:72])

        if magic != QCowUtil.QCOW2_MAGIC:
            raise ValueError("Not a valid QCOW2 file")

        if cluster_bits != 16:
            raise ValueError("Only default cluster size of 64K is supported")

        parent_name = QCowUtil._read_qcow2_backingfile(file, backing_file_offset, backing_file_size)

        return {
            "version": version,
            "backing_file_offset": backing_file_offset,
            "backing_file_size": backing_file_size,
            "virtual_disk_size": size,
            "cluster_bits": cluster_bits,
            "l1_size": l1_size,
            "l1_table_offset": l1_table_offset,
            "refcount_table_offset": refcount_table_offset,
            "snapshots_offset": snapshots_offset,
            "parent": parent_name,
        }

    @staticmethod
    def _is_l1_allocated(entry: int) -> bool:
        """Checks if the given L1 entry is allocated.

        If the offset is 0 then the L2 table and all clusters described
        by this L2 table are unallocated.

        Args:
            entry: L1 entry

        Returns:
            bool: True if the L1 entry is allocated (ie has a valid offset).
                  False otherwise.
        """
        return (entry & QCowUtil.L2_OFFSET_MASK) != 0

    @staticmethod
    def _is_l2_allocated(entry: int) -> bool:
        """Checks if a given entry is allocated.

        Currently we only support standard clusters. And for standard clusters
        the bit 63 is set to 1 for allocated ones or offset is not 0.

        Args:
            entry: L2 entry

        Returns:
            bool: Returns True if the L2 entry is allocated, False otherwise

        Raises:
            raise an exception if the cluster is not a standard one.
        """
        assert entry & QCowUtil.CLUSTER_TYPE_BIT == 0
        return (entry & QCowUtil.ALLOCATED_ENTRY_BIT != 0) or (
            entry & QCowUtil.STANDARD_CLUSTER_OFFSET_MASK != 0
        )

    @staticmethod
    def _get_allocated_clusters(l2_entries: List[int]) -> List[int]:
        """Get all allocated clusters in a given list of L2 entries.

        Args:
            l2_entries: A list of L2 entries.

        Returns:
            A list of all allocated entries
        """
        return [entry for entry in l2_entries if QCowUtil._is_l2_allocated(entry)]

    @staticmethod
    def _get_cluster_to_byte(clusters: int, cluster_bits: int) -> int:
        # (1 << cluster_bits) give cluster size in byte
        return clusters * (1 << cluster_bits)

    def _get_number_of_allocated_clusters(self) -> int:
        """Get the number of allocated clusters.

        Args:
            self: A QcowInfo object.

        Returns:
            An integer that is the list of allocated clusters.
        """
        assert(self.qcow_read)

        allocated_clusters = 0

        for l2_entries in self.l1_to_l2.values():
            allocated_clusters += len(self._get_allocated_clusters(l2_entries))

        return allocated_clusters

    @staticmethod
    def _move_backing_file(
        f: BinaryIO, old_offset: int, new_offset: int, data_size: int
    ) -> None:
        """Move a number of bytes from old_offset to new_offset and replaces the old
           value by 0s. It is up to the caller to save the current position in the file
           if needed.

        Args:
            f: the file the will be modified
            old_offset: the current offset
            new_offset: the new offset where we want to move data
            data_size: Size in bytes of data that we want to move

        Returns:
            Nothing but the file f is modified and the position in the file also.
        """
        # Read the string at backing_file_offset
        f.seek(old_offset)
        data = f.read(data_size)

        # Write zeros at the original location
        f.seek(old_offset)
        f.write(b"\x00" * data_size)

        # Write the string to the new location
        f.seek(new_offset)
        f.write(data)

    def _add_or_find_custom_header(self) -> int:
        """Add custom header at the end of header extensions

        It finds the end of the header extensions and add the custom header.
        If the header already exists nothing is done.

        Args:

        Returns:
            It returns the data offset where custom header is found or created.
            If data offset is 0 something weird happens.
            The qcow2 file in self.filename can be modified.
        """
        assert self.qcow_read

        header_length = 72  # This is the default value for version 2 images

        custom_header_type = 0x76617465  # vate: it is easy to recognize with hexdump -C
        custom_header_length = 8
        custom_header_data = 0
        # We don't need padding because we are already aligned
        custom_header = struct.pack(
            ">IIQ", custom_header_type, custom_header_length, custom_header_data
        )

        with open(self.filename, "rb+") as qcow2_file:
            if self.header["version"] == 3:
                qcow2_file.seek(100)  # 100 is the offset of header_length
                header_length = int.from_bytes(qcow2_file.read(4), "big")

            # After the image header we found Header extension. So we need to find the end of
            # the header extension area and add our custom header.
            qcow2_file.seek(header_length)

            custom_data_offset = 0

            while True:
                ext_type = int.from_bytes(qcow2_file.read(4), "big")
                ext_len = int.from_bytes(qcow2_file.read(4), "big")

                if ext_type == custom_header_type:
                    # A custom header is already there
                    custom_data_offset = qcow2_file.tell()
                    break

                if ext_type == 0x00000000:
                    # End mark found. If we found the end mark it means that we didn't find
                    # the custom header. So we need to add it.
                    custom_data_offset = qcow2_file.tell()

                    # We will overwrite the end marker so rewind a little bit to
                    # write the new type extension and the new length. But if there is
                    # a backing file we need to move it to make some space.
                    if self.header["backing_file_offset"]:
                        # Keep current position
                        saved_pos = qcow2_file.tell()

                        bf_offset = self.header["backing_file_offset"]
                        bf_size = self.header["backing_file_size"]
                        bf_new_offset = bf_offset + len(custom_header)
                        self._move_backing_file(
                            qcow2_file, bf_offset, bf_new_offset, bf_size
                        )

                        # Update the header to match the new backing file offset
                        self.header["backing_file_offset"] = bf_new_offset
                        qcow2_file.seek(self.QCOW2_BACKING_FILE_OFFSET)
                        qcow2_file.write(struct.pack(">Q", bf_new_offset))

                        # Restore saved position
                        qcow2_file.seek(saved_pos)

                    qcow2_file.seek(-8, 1)
                    qcow2_file.write(custom_header)
                    break

                # Round up the header extension size to the next multiple of 8
                ext_len = (ext_len + 7) & 0xFFFFFFF8
                qcow2_file.seek(ext_len, 1)

            return custom_data_offset

    def _set_l1_zero(self):
        zero = int(0).to_bytes(1, "little")
        nb_of_entries_per_cluster  = QCOW_CLUSTER_SIZE/8
        return list(zero * int(nb_of_entries_per_cluster/8))

    def _set_l2_zero(self, b, i):
        return b & ~(1 << i)

    def _set_l2_one(self, b, i):
        return b | (1 << i)

    def _create_bitmap(self) -> bytes:
        idx: int = 0
        bitmap = list()
        b = 0
        for l1_idx, l1_entry in enumerate(self.l1):
            if not self._is_l1_allocated(l1_entry):
                bitmap.extend(self._set_l1_zero()) #Should define cluster_size/8 page to 0
                continue

            l2_table = self.l1_to_l2[l1_entry] #L2 is cluster_size/8 entries of cluster_size page
            for l2_entry in l2_table:
                if self._is_l2_allocated(l2_entry):
                    b = self._set_l2_one(b, idx)
                else:
                    b = self._set_l2_zero(b, idx)
                idx += 1
                if idx == 8:
                    bitmap.append(b)
                    b = 0
                    idx = 0
        return struct.pack("B"*len(bitmap), *bitmap)

    # ----
    # Implementation of CowUtil
    # ----

    @override
    def getMinImageSize(self) -> int:
        return MIN_QCOW_SIZE

    @override
    def getMaxImageSize(self) -> int:
        return MAX_QCOW_SIZE

    @override
    def getBlockSize(self, path: str) -> int:
        return QCOW_CLUSTER_SIZE

    @override
    def getFooterSize(self, path: str) -> int:
        return 0

    @override
    def getDefaultPreallocationSizeVirt(self) -> int:
        return 0

    @override
    def getMaxChainLength(self) -> int:
        return MAX_QCOW_CHAIN_LENGTH

    @override
    def calcOverheadEmpty(self, virtual_size: int) -> int:
        size_l1 = QCOW_CLUSTER_SIZE
        size_header = QCOW_CLUSTER_SIZE
        size_l2 = (virtual_size * 8) / QCOW_CLUSTER_SIZE #It is only an estimation

        size = size_l1 + size_l2 + size_header

        return util.roundup(QCOW_CLUSTER_SIZE, size)

    @override
    def calcOverheadBitmap(self, virtual_size: int) -> int:
        return 0 #TODO: What do we send back?

    @override
    def getInfo(
        self,
        path: str,
        extractUuidFunction: Callable[[str], str],
        includeParent: bool = True,
        resolveParent: bool = True,
        useBackupFooter: bool = False
    ) -> CowImageInfo:
        #TODO:  handle resolveParent
        self._read_qcow2(path)
        basename = Path(path).name
        uuid = extractUuidFunction(basename)
        cowinfo = CowImageInfo(uuid)
        cowinfo.path = basename
        cowinfo.sizeVirt = self.header["virtual_disk_size"]
        cowinfo.sizePhys = self.getSizePhys(path)
        cowinfo.hidden = self.getHidden(path)
        cowinfo.sizeAllocated = self._get_cluster_to_byte(self._get_number_of_allocated_clusters(), self.header["cluster_bits"])
        if includeParent:
            parent_path = self.header["parent"]
            if parent_path != "":
                cowinfo.parentPath = parent_path
                cowinfo.parentUuid = extractUuidFunction(parent_path)

        return cowinfo

    @override
    def getInfoFromLVM(
        self, lvName: str, extractUuidFunction: Callable[[str], str], vgName: str
    ) -> Optional[CowImageInfo]:
        pass

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
        pattern_p: Path = Path(pattern)
        list_qcow = list(pattern_p.parent.glob(pattern_p.name))
        #TODO: handle parents, it needs to getinfo from parents also
        #TODO: handle exitOnError
        for qcow in list_qcow:
            qcow_str = str(qcow)
            info = self.getInfo(qcow_str, extractUuidFunction)
            result[info.uuid] = info
        return result

    @override
    def getParent(self, path: str, extractUuidFunction: Callable[[str], str]) -> Optional[str]:
        parent = self.getParentNoCheck(path)
        if parent:
            return extractUuidFunction(parent)
        return None

    @override
    def getParentNoCheck(self, path: str) -> Optional[str]:
        self._read_qcow2(path)
        parent_path = self.header["parent"]
        if parent_path == "":
            return None
        return parent_path

    @override
    def hasParent(self, path: str) -> bool:
        if self.getParentNoCheck(path):
            return True
        return False

    @override
    def setParent(self, path: str, parentPath: str, parentRaw: bool) -> None:
        parentType = QCOW2_TYPE
        if parentRaw:
            parentType = "raw"
        cmd = [QEMU_IMG, "rebase", "-u", "-f", QCOW2_TYPE, "-F", parentType, "-b", parentPath, path]
        self._ioretry(cmd)

    @override
    def getHidden(self, path: str) -> bool:
        """Get hidden property according to the value b

        Args:

        Returns:
            True if hidden is set, False otherwise
        """
        self._read_qcow2(path)
        custom_data_offset = self._add_or_find_custom_header()
        if custom_data_offset == 0:
            print("ERROR: Custom data offset not found... should not reach this")
            return False #TODO: Add exception

        with open(path, "rb") as qcow2_file:
            qcow2_file.seek(custom_data_offset)
            hidden = qcow2_file.read(1)
            if hidden == b"\x00":
                return False
            return True

    @override
    def setHidden(self, path: str, hidden: bool = True) -> None:
        """Set hidden property according to the value b

        Args:
            bool: True if you want to set the property. False otherwise

        Returns:
            nothing. If the custom headers is not found it is created so the
            qcow file can be modified.
        """
        self._read_qcow2(path)
        custom_data_offset = self._add_or_find_custom_header()
        if custom_data_offset == 0:
            util.SMlog("ERROR: Custom data offset not found... should not reach this")
            return #TODO: Add exception

        with open(self.filename, "rb+") as qcow2_file:
            qcow2_file.seek(custom_data_offset)
            if hidden:
                qcow2_file.write(b"\x01")
            else:
                qcow2_file.write(b"\x00")

    @override
    def getSizeVirt(self, path: str) -> int:
        self._read_qcow2(path)
        return self.header['virtual_disk_size']

    @override
    def setSizeVirt(self, path: str, size: int, jFile: str) -> None:
        """
        size: byte
        jFile: a journal file used for resizing with VHD, not useful for QCOW2
        """
        cmd = [QEMU_IMG, "resize", path, str(size)]
        self._ioretry(cmd)

    @override
    def setSizeVirtFast(self, path: str, size: int) -> None:
        self.setSizeVirt(path, size, "")

    @override
    def getMaxResizeSize(self, path: str) -> int:
        return 0

    @override
    def getSizePhys(self, path: str) -> int:
        return os.stat(path).st_size

    @override
    def setSizePhys(self, path: str, size: int, debug: bool = True) -> None:
        pass #TODO: Doesn't exist for QCow2, do we need to use it?

    @override
    def getAllocatedSize(self, path: str) -> int:
        self._read_qcow2(path)
        clusters = self._get_number_of_allocated_clusters()
        cluster_bits =  self.header["cluster_bits"]
        return self._get_cluster_to_byte(clusters, cluster_bits)

    @override
    def getResizeJournalSize(self) -> int:
        return 0

    @override
    def killData(self, path: str) -> None:
        """Remove all data and reset L1/L2 table.

        Args:
            self: The QcowInfo object.

        Returns:
            nothing.
        """
        self._read_qcow2(path)
        # We need to reset L1 entries and then just truncate the file right
        # after L1 entries
        with open(self.filename, "r+b") as file:
            l1_table_offset = self.header["l1_table_offset"]
            file.seek(l1_table_offset)

            l1_table_size = (
                self.header["l1_size"] * 8
            )  # size in bytes, each entry is 8 bytes
            file.write(b"\x00" * l1_table_size)
            file.truncate(l1_table_offset + l1_table_size)

    @override
    def getDepth(self, path: str) -> int:
        return 0 #TODO: Get correct depth

    @override
    def getBlockBitmap(self, path: str) -> bytes:
        self._read_qcow2(path)
        return zlib.compress(self._create_bitmap())

    @override
    def coalesce(self, path: str) -> int:
        # -d on commit make it not empty the original image since we don't intend to keep it
        allocated_blocks = self.getAllocatedSize(path)
        cmd = [QEMU_IMG, "commit", "-f", QCOW2_TYPE, path, "-d"]
        ret = cast(str, self._ioretry(cmd))
        return allocated_blocks

    @override
    def create(self, path: str, size: int, static: bool, msize: int = 0) -> None:
        cmd = [QEMU_IMG, "create", "-f", QCOW2_TYPE, path, str(size)]
        if static:
            cmd.extend(["-o", "preallocation=full"])
        #TODO: msize is ignored for now, it's used to preallocate metadata for VHD so it can use resize without journal
        self._ioretry(cmd)
        self.setHidden(path, False) #We add hidden header at creation

    @override
    def snapshot(
        self,
        path: str,
        parent: str,
        parentRaw: bool,
        msize: int = 0,
        checkEmpty: Optional[bool] = True
    ) -> None:
        if parentRaw:
            util.SMlog("Parent can't be raw for QCOW2 snapshot") #TODO: Shouldn't happen
            return
        #TODO: msize is ignored for now, it's used to preallocate metadata for VHD so it can use resize without journal
        # TODO: checkEmpty? If it is False, then the parent could be empty and should still be used for snapshot
        cmd = [QEMU_IMG, "create", "-f", QCOW2_TYPE, "-b", parent, "-F", QCOW2_TYPE, path]
        self._ioretry(cmd)
        self.setHidden(path, False)

    @override
    def check(
        self,
        path: str,
        ignoreMissingFooter: Optional[bool] = False,
        fast: Optional[bool] = False
    ) -> CowUtil.CheckResult:
        cmd = [QEMU_IMG, "check", path]
        try:
            self._ioretry(cmd)
            return CowUtil.CheckResult.Success
        except util.CommandException as e:
            if e.code in (errno.EROFS, errno.EMEDIUMTYPE):
                return CowUtil.CheckResult.Unavailable
            # 1/EPERM is error in internal during check
            # 2/ENOENT is QCOW corrupted
            # 3/ESRCH is QCow has leaked clusters
            # 63/ENOSR is check unavailable on this image type
            return CowUtil.CheckResult.Fail

    @override
    def revert(self, path: str, jFile: str) -> None:
        pass #TODO: Used to get back from a failed operation using a journal, NOOP for qcow for the moment

    @override
    def repair(self, path: str) -> None:
        cmd = [QEMU_IMG, "check", "-f", QCOW2_TYPE, "-r", "all", path]
        self._ioretry(cmd)

    @override
    def validateAndRoundImageSize(self, size: int) -> int:
        return util.roundup(QCOW_CLUSTER_SIZE, size)

    @override
    def getKeyHash(self, path: str) -> Optional[str]:
        pass

    @override
    def setKey(self, path: str, key_hash: str) -> None:
        pass