import FileSR
import mock
import SR
import unittest
import ZFSSR


class FakeZFSSR(ZFSSR.ZFSSR):
    uuid = None
    sr_ref = None
    session = None
    srcmd = None
    other_config = {}
    vdis = {}
    passthrough = True

    def __init__(self, srcmd, none):
        self.dconf = srcmd.dconf
        self.srcmd = srcmd


class TestZFSSR(unittest.TestCase):
    def create_zfs_sr(self, sr_uuid='asr_uuid', location='fake_path'):
        srcmd = mock.Mock()
        srcmd.dconf = {
            'location': location
        }
        srcmd.params = {
            'command': 'some_command',
            'device_config': {}
        }
        sr = FakeZFSSR(srcmd, None)
        sr.load(sr_uuid)
        return sr

    @mock.patch('ZFSSR.is_zfs_available', autospec=True)
    def test_load(self, is_zfs_available):
        self.create_zfs_sr()

    def test_load_with_zfs_unavailable(self):
        failed = False
        try:
            self.create_zfs_sr()
        except SR.SROSError as e:
            # Check SRUnavailable error.
            if e.errno != 47:
                raise
            failed = True
        self.assertTrue(failed)

    @mock.patch('ZFSSR.is_zfs_available', autospec=True)
    @mock.patch('ZFSSR.is_zfs_path', autospec=True)
    def test_create(self, is_zfs_path, is_zfs_available):
        sr = self.create_zfs_sr()
        sr.create(sr.uuid, 42)

    @mock.patch('ZFSSR.is_zfs_available', autospec=True)
    @mock.patch('ZFSSR.is_zfs_path', autospec=True)
    def test_create_with_invalid_zfs_path(self, is_zfs_path, is_zfs_available):
        failed = False

        is_zfs_path.return_value = False
        sr = self.create_zfs_sr()
        try:
            sr.create(sr.uuid, 42)
        except SR.SROSError as e:
            # Check ZFSSRCreate error.
            if e.errno != 5000:
                raise
            failed = True
        self.assertTrue(failed)

    @mock.patch('ZFSSR.is_zfs_available', autospec=True)
    @mock.patch('ZFSSR.is_zfs_path', autospec=True)
    @mock.patch('FileSR.FileSR._checkmount', autospec=True)
    @mock.patch('FileSR.FileSR._loadvdis', autospec=True)
    @mock.patch('SR.SR.scan', autospec=True)
    @mock.patch('os.path.ismount', autospec=True)
    def test_scan(
        self, ismount, scan, _loadvdis, _checkmount, is_zfs_path,
        is_zfs_available
    ):
        sr = self.create_zfs_sr()
        sr.scan(sr.uuid)

    @mock.patch('ZFSSR.is_zfs_available', autospec=True)
    @mock.patch('ZFSSR.is_zfs_path', autospec=True)
    @mock.patch('FileSR.FileSR._checkmount', autospec=True)
    def test_scan_with_invalid_zfs_path(
        self, _checkmount, is_zfs_path, is_zfs_available
    ):
        failed = False

        is_zfs_path.return_value = False
        sr = self.create_zfs_sr()
        try:
            sr.scan(sr.uuid)
        except SR.SROSError as e:
            # Check SRUnavailable error.
            if e.errno != 47:
                raise
            failed = True
        self.assertTrue(failed)
