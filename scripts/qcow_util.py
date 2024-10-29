#!/usr/bin/env python3
"""
Provides some usefull functions for Qcow2 files.
"""

import struct
import sys
from typing import BinaryIO, Dict, List, NoReturn


class QcowInfo:
    """
    Class used to store and manipulate Qcow2 metadata
    """

    # We followed specifications found here:
    # https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt

    QCOW2_MAGIC = 0x514649FB  # b"QFI\xfb": Magic number for QCOW2 files
    QCOW2_HEADER_SIZE = 104  # In fact the last information we need is at offset 40-47
    QCOW2_L2_SIZE = 65536
    QCOW2_BACKGING_FILE_OFFSET = 8

    ALLOCATED_ENTRY_BIT = (
        0x8000_0000_0000_0000  # Bit 63 is the allocated bit for standard cluster
    )
    CLUSTER_TYPE_BIT = 0x4000_0000_0000_0000  # 0 for standard, 1 for compressed cluster
    L2_OFFSET_MASK = 0x00FF_FFFF_FFFF_FF00  # Bits 9-55 are offset of L2 table.
    CLUSTER_DESCRIPTION_MASK = 0x3FFF_FFFF_FFFF_FFFF  # Bit 0-61 is cluster description
    STANDARD_CLUSTER_OFFSET_MASK = (
        0x00FF_FFFF_FFFF_FF00  # Bits 9-55 are offset of standard cluster
    )

    def __init__(self, filename: str):
        with open(filename, "rb") as qcow2_file:
            self.filename = filename  # Keep the filename if clean is called
            self.header = self._read_qcow2_header(qcow2_file)
            self.l1 = self._get_l1_entries(qcow2_file)
            # The l1_to_l2 allows to get L2 entries for a given L1. If L1 entry
            # is not allocated we store an empty list.
            self.l1_to_l2: Dict[int, List[int]] = {}

            for l1_entry in self.l1:
                l2_offset = l1_entry & QcowInfo.L2_OFFSET_MASK
                if l2_offset == 0:
                    self.l1_to_l2[l1_entry] = []
                else:
                    self.l1_to_l2[l1_entry] = self._get_l2_entries(
                        qcow2_file, l2_offset
                    )

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
                header_length = int.from_bytes(qcow2_file.read(4))

            # After the image header we found Header extension. So we need to find the end of
            # the header extension area and add our custom header.
            qcow2_file.seek(header_length)

            custom_data_offset = 0

            while True:
                ext_type = int.from_bytes(qcow2_file.read(4))
                ext_len = int.from_bytes(qcow2_file.read(4))

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
                        QcowInfo._move_backing_file(
                            qcow2_file, bf_offset, bf_new_offset, bf_size
                        )

                        # Update the header to match the new backing file offset
                        self.header["backing_file_offset"] = bf_new_offset
                        qcow2_file.seek(QcowInfo.QCOW2_BACKGING_FILE_OFFSET)
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
        return (entry & QcowInfo.L2_OFFSET_MASK) != 0

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
        assert entry & QcowInfo.CLUSTER_TYPE_BIT == 0
        return (entry & QcowInfo.ALLOCATED_ENTRY_BIT != 0) or (
            entry & QcowInfo.STANDARD_CLUSTER_OFFSET_MASK != 0
        )

    @staticmethod
    def _read_qcow2_header(file: BinaryIO) -> Dict[str, int]:
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
        header = file.read(QcowInfo.QCOW2_HEADER_SIZE)
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

        if magic != QcowInfo.QCOW2_MAGIC:
            raise ValueError("Not a valid QCOW2 file")

        if cluster_bits != 16:
            raise ValueError("Only default cluster size of 64K is supported")

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
        }

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
        l2_table = file.read(QcowInfo.QCOW2_L2_SIZE)

        return [
            struct.unpack(">Q", l2_table[i : i + 8])[0]
            for i in range(0, len(l2_table), 8)
        ]

    @staticmethod
    def _find_new_clusters(
        first_entries: List[int], second_entries: List[int]
    ) -> List[int]:
        """Find clusters that are allocated in second L2 entries and not in the
        first L2 entries. If an entry has been modified it is not a new entry.

        Args:
            first_entries: A list of L2 entries.
            second_entries: Another list of L2 entries.

        Returns:
            The clusters that are allocated in second_entries and not in first_entries.
        """
        return [
            new_e
            for base_e, new_e in zip(first_entries, second_entries)
            if QcowInfo._is_l2_allocated(new_e)
            and not QcowInfo._is_l2_allocated(base_e)
        ]

    @staticmethod
    def _get_allocated_clusters(l2_entries: List[int]) -> List[int]:
        """Get all allocated clusters in a given list of L2 entries.

        Args:
            l2_entries: A list of L2 entries.

        Returns:
            A list of all allocated entries
        """
        return [entry for entry in l2_entries if QcowInfo._is_l2_allocated(entry)]

    def get_number_of_allocated_clusters(self) -> int:
        """Get the number of allocated clusters.

        Args:
            self: A QcowInfo object.

        Returns:
            An integer that is the list of allocated clusters.
        """
        allocated_clusters = 0

        for l2_entries in self.l1_to_l2.values():
            allocated_clusters += len(QcowInfo._get_allocated_clusters(l2_entries))

        return allocated_clusters

    def newly_allocated_clusters(self, other: "QcowInfo") -> int:
        """Returns the number of clusters that are allocated in other
        but not in self.

        Args:
            self: The QcowInfo object used as the reference.
            other: The QcowInfo object used for comparaison.

        Returns:
            An integer that is the number of allocated clusters in other and
            not in self.
        """
        new_clusters = []
        base_mapping = self.l1_to_l2
        new_mapping = other.l1_to_l2

        for l1_entry in other.l1:
            # Check if the entry is already in the base file. If it is the case
            # We need to check if there are newly allocated L2 in other. If it
            # is not the case we can add all allocated L2 entries because L1 entry is
            # a new one.
            if l1_entry in self.l1:
                new_clusters.extend(
                    QcowInfo._find_new_clusters(
                        base_mapping[l1_entry], new_mapping[l1_entry]
                    )
                )
            else:
                new_clusters.extend(
                    QcowInfo._get_allocated_clusters(new_mapping[l1_entry])
                )

        return len(new_clusters)

    def dump_table(self) -> None:
        """Print allocated entries for L1 and L2 table.

        Args:
            self: The QcowInfo object.

        Returns:
            nothing.
        """

        for l1_idx, l1_entry in enumerate(self.l1):
            # Just print L1 that are allocated
            if not QcowInfo._is_l1_allocated(l1_entry):
                continue

            l2_offset = l1_entry & self.L2_OFFSET_MASK
            print(f"[L1 {l1_idx:04}] : {l1_entry:0x} -> L2@0x{l2_offset:0x}")

            l2_entries = self.l1_to_l2[l1_entry]
            for l2_idx, l2_entry in enumerate(l2_entries):
                # Same for L2 entries, only print the allocated ones
                if not QcowInfo._is_l2_allocated(l2_entry):
                    continue

                cluster_offset = l2_entry & self.STANDARD_CLUSTER_OFFSET_MASK
                print(f"  [L2 {l2_idx:04}] 0x{cluster_offset:0x}")

    def wipe_data(self) -> None:
        """Remove all data and reset L1/L2 table.

        Args:
            self: The QcowInfo object.

        Returns:
            nothing.
        """
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

    def set_hidden(self, b: bool) -> None:
        """Set hidden property according to the value b

        Args:
            bool: True if you want to set the property. False otherwise

        Returns:
            nothing. If the custom headers is not found it is created so the
            qcow file can be modified.
        """
        custom_data_offset = self._add_or_find_custom_header()
        if custom_data_offset == 0:
            print("ERROR: Custom data offset not found... should not reach this")
            return

        with open(self.filename, "rb+") as qcow2_file:
            qcow2_file.seek(custom_data_offset)
            if b:
                qcow2_file.write(b"\x01")
            else:
                qcow2_file.write(b"\x00")

    def get_hidden(self) -> bool:
        """Get hidden property according to the value b

        Args:

        Returns:
            True if hidden is set, False otherwise
        """
        custom_data_offset = self._add_or_find_custom_header()
        if custom_data_offset == 0:
            print("ERROR: Custom data offset not found... should not reach this")
            return False

        with open(self.filename, "rb") as qcow2_file:
            qcow2_file.seek(custom_data_offset)
            hidden = qcow2_file.read(1)
            if hidden == b"\x00":
                return False

            return True


def print_help() -> NoReturn:
    """Print help."""
    help_msg = """
Usage: ./qemu-get-info.py <command> <params>

Where command is:
    - alloc: returns the number of allocated clusters for a qcow file
    - diff: returns the newly allocated clusters in a file compared to a file
    - wipe: unallocate all clusters and free data
    - set: set hidden propertie in the custom file
    - unset: unset hidden propertie in the custom file
    - get: get the hidden propertie in the custom file

Params:
   - All command takes a qcow file. Only diff takes a backing file and a qcow.
"""
    print(help_msg)
    sys.exit(1)


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) >= 2 else print_help()

    # There is at least one file
    if len(sys.argv) < 3:
        print("A qcow file is expected")
        sys.exit(1)

    qcow_info = QcowInfo(sys.argv[2])

    if command == "alloc":
        print(f"{qcow_info.header}")
        qcow_info.dump_table()
        print(f"clusters allocated: {qcow_info.get_number_of_allocated_clusters()}")
    elif command == "diff":
        if len(sys.argv) < 4:
            print("2 qcow files are expected to compute the diff")
            sys.exit(1)

        qcow_file2 = sys.argv[3]
        qcow_info2 = QcowInfo(qcow_file2)

        print(
            f"Numbers of new clusters in {qcow_file2} compared to {sys.argv[2]}:"
            f" {qcow_info.newly_allocated_clusters(qcow_info2)}"
        )
    elif command == "wipe":
        qcow_info.wipe_data()
    elif command == "set":
        qcow_info.set_hidden(True)
    elif command == "unset":
        qcow_info.set_hidden(False)
    elif command == "get":
        if qcow_info.get_hidden():
            print("Hidden property is set")
        else:
            print("Hidden property is not set")
    else:
        print_help()
