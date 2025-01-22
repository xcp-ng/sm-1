
import unittest
import zlib

import vhdutil
import xs_errors

import testlib

TEST_VHD_PATH = '/test/path/test-par.vhd'

TEST_VHD_NAME = "/test/path/test-vdi.vhd"

VHD_UTIL = '/usr/bin/vhd-util'


class TestVhdUtil(unittest.TestCase):
    def __init__(self):
        self.vhdutil = vhdutil.VhdUtil()

    def test_validate_and_round_min_size(self):
        size = self.vhdutil.validateAndRoundImageSize(2 * 1024 * 1024)
        self.assertTrue(size == 2 * 1024 * 1024)

    def test_validate_and_round_max_size(self):
        size = self.vhdutil.validateAndRoundImageSize(self.vhdutil.getMaxImageSize())
        self.assertTrue(size == self.vhdutil.getMaxImageSize())

    def test_validate_and_round_odd_size_up_to_next_boundary(self):
        size = self.vhdutil.validateAndRoundImageSize(self.vhdutil.getMaxImageSize() - 1)
        self.assertTrue(size == self.vhdutil.getMaxImageSize())

    def test_validate_and_round_negative(self):
        with self.assertRaises(xs_errors.SROSError):
            self.vhdutil.validateAndRoundImageSize(-1)

    def test_validate_and_round_too_large(self):
        with self.assertRaises(xs_errors.SROSError):
            self.vhdutil.validateAndRoundImageSize(self.vhdutil.getMaxImageSize() + 1)

    @testlib.with_context
    def test_calc_overhead_empty_small(self, context):
        virtual_size = 25 * 1024 * 1024
        result = self.vhdutil.calcOverheadEmpty(virtual_size)

        self.assertEqual(4096, result)

    @testlib.with_context
    def test_calc_overhead_empty_max(self, context):
        virtual_size = 2 * 1024 * 1024 * 1024 * 1024  # 2TB
        result = self.vhdutil.calcOverheadEmpty(virtual_size)

        # Footer -> 3 * 1024
        # BAT -> (Size in MB / 2) * 4 = 4194304
        # add footer and round to 512
        # BATMAP -> (Size in MB / 2) / 8 => 131072
        # add together and round to 4096
        self.assertEqual(4329472, result)

    @testlib.with_context
    def test_calc_overhead_bitmap_round_blocks(self, context):
        virtual_size = 24 * 1024 * 1024

        result = self.vhdutil.calcOverheadBitmap(virtual_size)

        self.assertEqual(49152, result)
    @testlib.with_context
    def test_calc_overhead_bitmap_extra_block(self, context):
        virtual_size = 25 * 1024 * 1024

        result = self.vhdutil.calcOverheadBitmap(virtual_size)

        self.assertEqual(53248, result)

    @testlib.with_context
    def test_get_size_virt(self, context):
        # arrange
        call_args = None
        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            return 0, b"25", b""

        context.add_executable(VHD_UTIL, test_function)

        # Act
        result = self.vhdutil.getSizeVirt(TEST_VHD_NAME)

        # Assert
        self.assertEqual(25*1024*1024, result)
        self.assertEqual(
            [VHD_UTIL, "query", "--debug", "-v",
             "-n", TEST_VHD_NAME],
            call_args)

    @testlib.with_context
    def test_set_size_virt(self, context):
        # arrange
        call_args = None
        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            return 0, b"", b""

        context.add_executable(VHD_UTIL, test_function)

        # Act
        self.vhdutil.setSizeVirt(
            TEST_VHD_NAME, 30*1024*1024,
            '/test/path/test-vdi.jrnl')

        # Assert
        self.assertEqual([
            VHD_UTIL, "resize", "--debug", "-s", "30", "-n", TEST_VHD_NAME,
            "-j", "/test/path/test-vdi.jrnl"],
            call_args)

    @testlib.with_context
    def test_set_size_virt_fast(self, context):
        # arrange
        call_args = None
        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            return 0, b"", b""

        context.add_executable(VHD_UTIL, test_function)

        # Act
        self.vhdutil.setSizeVirtFast(
            TEST_VHD_NAME, 30*1024*1024)

        # Assert
        self.assertEqual([
            VHD_UTIL, "resize", "--debug", "-s", "30",
            "-n", TEST_VHD_NAME, '-f'],
            call_args)

    @testlib.with_context
    def test_get_block_bitmap(self, context):
        # arrange
        call_args = None
        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            # Not a real bitmap data
            return 0, b"some dummy text", b""

        context.add_executable(VHD_UTIL, test_function)

        # Act
        result = self.vhdutil.getBlockBitmap(TEST_VHD_NAME)

        # Assert
        self.assertIsNotNone(result)
        self.assertEqual("some dummy text", zlib.decompress(result).decode())
        self.assertEqual([
            VHD_UTIL, "read", "--debug", "-B",
            "-n", TEST_VHD_NAME],
            call_args)

    @testlib.with_context
    def test_create_non_static(self, context):
        # Arrange
        call_args = None

        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            # Not a real bitmap data
            return 0, b"", b""

        context.add_executable(VHD_UTIL,
                               test_function)
        # Act
        self.vhdutil.create(TEST_VHD_NAME, 30 * 1024 * 1024, False)

        # Assert
        self.assertEqual(
            [VHD_UTIL, "create", "--debug",
             "-n", TEST_VHD_NAME, "-s", "30"],
            call_args)

    @testlib.with_context
    def test_create_static(self, context):
        # Arrange
        call_args = None

        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            # Not a real bitmap data
            return 0, b"", b""

        context.add_executable(VHD_UTIL, test_function)
        # Act
        self.vhdutil.create(TEST_VHD_NAME, 30 * 1024 * 1024, True)

        # Assert
        self.assertEqual(
            [VHD_UTIL, "create", "--debug",
             "-n", TEST_VHD_NAME, "-s", "30", "-r"],
            call_args)

    @testlib.with_context
    def test_create_preallocate(self, context):
        # Arrange
        call_args = None

        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            # Not a real bitmap data
            return 0, b"", b""

        context.add_executable(VHD_UTIL, test_function)
        # Act
        self.vhdutil.create(
            TEST_VHD_NAME, 30 * 1024 * 1024, False, msize=self.vhdutil.getDefaultPreallocationSizeVirt()
        )

        # Assert
        self.assertEqual(
            [VHD_UTIL, "create", "--debug",
             "-n", TEST_VHD_NAME, "-s", "30",
             "-S", "2097152"],
            call_args)

    @testlib.with_context
    def test_snapshot_normal(self, context):
        # Arrange
        call_args = None

        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            # Not a real bitmap data
            return 0, b"", b""

        context.add_executable(VHD_UTIL, test_function)

        # Act
        self.vhdutil.snapshot(
            TEST_VHD_NAME,
            TEST_VHD_PATH,
            False)

        # Assert
        self.assertEqual(
            [VHD_UTIL, "snapshot", "--debug",
             "-n", TEST_VHD_NAME,
             "-p", "/test/path/test-par.vhd"],
            call_args)

    @testlib.with_context
    def test_snapshot_raw_parent(self, context):
        # Arrange
        call_args = None

        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            # Not a real bitmap data
            return 0, b"", b""

        context.add_executable(VHD_UTIL, test_function)

        # Act
        self.vhdutil.snapshot(
            TEST_VHD_NAME,
            TEST_VHD_PATH,
            True)

        # Assert
        self.assertEqual(
            [VHD_UTIL, "snapshot", "--debug",
             "-n", TEST_VHD_NAME,
             "-p", "/test/path/test-par.vhd", '-m'],
            call_args)

    @testlib.with_context
    def test_snapshot_preallocate(self, context):
        # Arrange
        call_args = None

        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            # Not a real bitmap data
            return 0, b"", b""

        context.add_executable(VHD_UTIL, test_function)

        # Act
        self.vhdutil.snapshot(
            TEST_VHD_NAME,
            TEST_VHD_PATH,
            False,
            msize=self.vhdutil.getDefaultPreallocationSizeVirt()
        )

        # Assert
        self.assertEqual(
            [VHD_UTIL, "snapshot", "--debug",
             "-n", TEST_VHD_NAME,
             "-p", "/test/path/test-par.vhd",
             '-S',  "2097152"],
            call_args)

    @testlib.with_context
    def test_snapshot_nocheck_empty(self, context):
        # Arrange
        call_args = None

        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            # Not a real bitmap data
            return 0, b"", b""

        context.add_executable(VHD_UTIL, test_function)

        # Act
        self.vhdutil.snapshot(
            TEST_VHD_NAME,
            TEST_VHD_PATH,
            False,
            checkEmpty=False)

        # Assert
        self.assertEqual(
            [VHD_UTIL, "snapshot", "--debug",
             "-n", TEST_VHD_NAME,
             "-p", "/test/path/test-par.vhd", '-e'],
            call_args)

    @testlib.with_context
    def test_coalesce_no_sector_count(self, context):
        """
        Call vhd-util.coalesce and handle no sector count return
        """
        # With a suitably updated blktap/vhd-util package this should not occur
        # Arrange
        def test_function(args, inp):
            return 0, "", ""

        context.add_executable(VHD_UTIL, test_function)

        # Act/Assert
        self.assertEqual(0, self.vhdutil.coalesce(TEST_VHD_PATH))

    @testlib.with_context
    def test_coalesce_with_sector_count(self, context):
        """
        Call vhd-util.coalesce and decode sector count return
        """
        # Arrange
        def test_function(args, inp):
            return 0, "Coalesced 25 sectors", ""

        context.add_executable(VHD_UTIL, test_function)

        # Act/Assert
        self.assertEqual(25 * self.vhdutil.SECTOR_SIZE, vhdutil.coalesce(TEST_VHD_PATH))

    @testlib.with_context
    def test_get_vhd_info_allocated_size(self, context):
        """
        Test that vhdutil.getVHDInfo return the allocated size in byte
        """
        # Arrange
        def test_function(args, inp):
            return 0, "51200\n39621239296\nd90f890c-d173-4eaf-ba09-fc2d6e50f6c0.vhd has no parent\nhidden: 0\n18856", ""

        context.add_executable(VHD_UTIL, test_function)
        import FileSR
        vhdinfo = self.vhdutil.getVHDInfo(TEST_VHD_PATH, FileSR.FileVDI.extractUuid)

        # Act/Assert
        self.assertEqual(18856*2*1024*1024 , vhdinfo.sizeAllocated)

    @testlib.with_context
    def test_get_allocated_size(self, context):
        """
        Test that vhdutil.getAllocatedSize return the size in byte
        """
        # Arrange
        call_args = None
        def test_function(args, inp):
            nonlocal call_args
            call_args = args
            return 0, b"18856", b""

        context.add_executable(VHD_UTIL, test_function)

        # Act
        result = self.vhdutil.getAllocatedSize(TEST_VHD_NAME)

        # Assert
        self.assertEqual(18856*2*1024*1024, result)
        self.assertEqual(
            [VHD_UTIL, "query", "--debug", "-a",
             "-n", TEST_VHD_NAME],
            call_args)
