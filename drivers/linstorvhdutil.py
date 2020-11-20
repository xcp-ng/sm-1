#!/usr/bin/env python3
#
# Copyright (C) 2020  Vates SAS - ronan.abhamon@vates.fr
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

from linstorjournaler import LinstorJournaler
from linstorvolumemanager import LinstorVolumeManager
import base64
import distutils.util
import errno
import json
import socket
import util
import vhdutil
import xs_errors

MANAGER_PLUGIN = 'linstor-manager'

# EMEDIUMTYPE constant (124) is not available in python2.
EMEDIUMTYPE = 124


def call_remote_method(session, host_ref, method, device_path, args):
    try:
        response = session.xenapi.host.call_plugin(
            host_ref, MANAGER_PLUGIN, method, args
        )
    except Exception as e:
        util.SMlog('call-plugin ({} with {}) exception: {}'.format(
            method, args, e
        ))
        raise util.SMException(str(e))

    util.SMlog('call-plugin ({} with {}) returned: {}'.format(
        method, args, response
    ))

    return response


class LinstorCallException(util.SMException):
    def __init__(self, cmd_err):
        self.cmd_err = cmd_err

    def __str__(self):
        return str(self.cmd_err)


class ErofsLinstorCallException(LinstorCallException):
    pass


class NoPathLinstorCallException(LinstorCallException):
    pass


def linstorhostcall(local_method, remote_method):
    def decorated(response_parser):
        def wrapper(*args, **kwargs):
            self = args[0]
            vdi_uuid = args[1]

            device_path = self._linstor.build_device_path(
                self._linstor.get_volume_name(vdi_uuid)
            )

            # A. Try a call using directly the DRBD device to avoid
            # remote request.

            # Try to read locally if the device is not in use or if the device
            # is up to date and not diskless.
            (node_names, in_use_by) = \
                self._linstor.find_up_to_date_diskful_nodes(vdi_uuid)

            local_e = None
            try:
                if not in_use_by or socket.gethostname() in node_names:
                    return self._call_local_method(local_method, device_path, *args[2:], **kwargs)
            except ErofsLinstorCallException as e:
                local_e = e.cmd_err
            except Exception as e:
                local_e = e

            util.SMlog(
                'unable to execute `{}` locally, retry using a readable host... (cause: {})'.format(
                    remote_method, local_e if local_e else 'local diskless + in use or not up to date'
                )
            )

            if in_use_by:
                node_names = {in_use_by}

            # B. Execute the plugin on master or slave.
            remote_args = {
                'devicePath': device_path,
                'groupName': self._linstor.group_name
            }
            remote_args.update(**kwargs)
            remote_args = {str(key): str(value) for key, value in remote_args.iteritems()}

            try:
                def remote_call():
                    host_ref = self._get_readonly_host(vdi_uuid, device_path, node_names)
                    return call_remote_method(self._session, host_ref, remote_method, device_path, remote_args)
                response = util.retry(remote_call, 5, 2)
            except Exception as remote_e:
                self._raise_openers_exception(device_path, local_e or remote_e)

            return response_parser(self, vdi_uuid, response)
        return wrapper
    return decorated


def linstormodifier():
    def decorated(func):
        def wrapper(*args, **kwargs):
            self = args[0]

            ret = func(*args, **kwargs)
            self._linstor.invalidate_resource_cache()
            return ret
        return wrapper
    return decorated


class LinstorVhdUtil:
    MAX_SIZE = 2 * 1024 * 1024 * 1024 * 1024  # Max VHD size.

    def __init__(self, session, linstor):
        self._session = session
        self._linstor = linstor

    # --------------------------------------------------------------------------
    # Getters: read locally and try on another host in case of failure.
    # --------------------------------------------------------------------------

    def check(self, vdi_uuid, ignore_missing_footer=False, fast=False):
        kwargs = {
            'ignoreMissingFooter': ignore_missing_footer,
            'fast': fast
        }
        return self._check(vdi_uuid, **kwargs)  # pylint: disable = E1123

    @linstorhostcall(vhdutil.check, 'check')
    def _check(self, vdi_uuid, response):
        return distutils.util.strtobool(response)

    def get_vhd_info(self, vdi_uuid, include_parent=True):
        kwargs = {
            'includeParent': include_parent,
            'resolveParent': False
        }
        # TODO: Replace pylint comment with this feature when possible:
        # https://github.com/PyCQA/pylint/pull/2926
        return self._get_vhd_info(vdi_uuid, self._extract_uuid, **kwargs)  # pylint: disable = E1123

    @linstorhostcall(vhdutil.getVHDInfo, 'getVHDInfo')
    def _get_vhd_info(self, vdi_uuid, response):
        obj = json.loads(response)

        vhd_info = vhdutil.VHDInfo(vdi_uuid)
        vhd_info.sizeVirt = obj['sizeVirt']
        vhd_info.sizePhys = obj['sizePhys']
        if 'parentPath' in obj:
            vhd_info.parentPath = obj['parentPath']
            vhd_info.parentUuid = obj['parentUuid']
        vhd_info.hidden = obj['hidden']
        vhd_info.path = obj['path']

        return vhd_info

    @linstorhostcall(vhdutil.hasParent, 'hasParent')
    def has_parent(self, vdi_uuid, response):
        return distutils.util.strtobool(response)

    def get_parent(self, vdi_uuid):
        return self._get_parent(vdi_uuid, self._extract_uuid)

    @linstorhostcall(vhdutil.getParent, 'getParent')
    def _get_parent(self, vdi_uuid, response):
        return response

    @linstorhostcall(vhdutil.getSizeVirt, 'getSizeVirt')
    def get_size_virt(self, vdi_uuid, response):
        return int(response)

    @linstorhostcall(vhdutil.getSizePhys, 'getSizePhys')
    def get_size_phys(self, vdi_uuid, response):
        return int(response)

    @linstorhostcall(vhdutil.getAllocatedSize, 'getAllocatedSize')
    def get_allocated_size(self, vdi_uuid, response):
        return int(response)

    @linstorhostcall(vhdutil.getDepth, 'getDepth')
    def get_depth(self, vdi_uuid, response):
        return int(response)

    @linstorhostcall(vhdutil.getKeyHash, 'getKeyHash')
    def get_key_hash(self, vdi_uuid, response):
        return response or None

    @linstorhostcall(vhdutil.getBlockBitmap, 'getBlockBitmap')
    def get_block_bitmap(self, vdi_uuid, response):
        return base64.b64decode(response)

    @linstorhostcall('_get_drbd_size', 'getDrbdSize')
    def get_drbd_size(self, vdi_uuid, response):
        return int(response)

    def _get_drbd_size(self, path):
        (ret, stdout, stderr) = util.doexec(['blockdev', '--getsize64', path])
        if ret == 0:
            return int(stdout.strip())
        raise util.SMException('Failed to get DRBD size: {}'.format(stderr))

    # --------------------------------------------------------------------------
    # Setters: only used locally.
    # --------------------------------------------------------------------------

    @linstormodifier()
    def create(self, path, size, static, msize=0):
        return self._call_local_method_or_fail(vhdutil.create, path, size, static, msize)

    @linstormodifier()
    def set_size_virt(self, path, size, jfile):
        return self._call_local_method_or_fail(vhdutil.setSizeVirt, path, size, jfile)

    @linstormodifier()
    def set_size_virt_fast(self, path, size):
        return self._call_local_method_or_fail(vhdutil.setSizeVirtFast, path, size)

    @linstormodifier()
    def set_size_phys(self, path, size, debug=True):
        return self._call_local_method_or_fail(vhdutil.setSizePhys, path, size, debug)

    @linstormodifier()
    def set_parent(self, path, parentPath, parentRaw=False):
        return self._call_local_method_or_fail(vhdutil.setParent, path, parentPath, parentRaw)

    @linstormodifier()
    def set_hidden(self, path, hidden=True):
        return self._call_local_method_or_fail(vhdutil.setHidden, path, hidden)

    @linstormodifier()
    def set_key(self, path, key_hash):
        return self._call_local_method_or_fail(vhdutil.setKey, path, key_hash)

    @linstormodifier()
    def kill_data(self, path):
        return self._call_local_method_or_fail(vhdutil.killData, path)

    @linstormodifier()
    def snapshot(self, path, parent, parentRaw, msize=0, checkEmpty=True):
        return self._call_local_method_or_fail(vhdutil.snapshot, path, parent, parentRaw, msize, checkEmpty)

    def inflate(self, journaler, vdi_uuid, vdi_path, new_size, old_size):
        # Only inflate if the LINSTOR volume capacity is not enough.
        new_size = LinstorVolumeManager.round_up_volume_size(new_size)
        if new_size <= old_size:
            return

        util.SMlog(
            'Inflate {} (size={}, previous={})'
            .format(vdi_path, new_size, old_size)
        )

        journaler.create(
            LinstorJournaler.INFLATE, vdi_uuid, old_size
        )
        self._linstor.resize_volume(vdi_uuid, new_size)

        # TODO: Replace pylint comment with this feature when possible:
        # https://github.com/PyCQA/pylint/pull/2926
        result_size = self.get_drbd_size(vdi_uuid)  # pylint: disable = E1120
        if result_size < new_size:
            util.SMlog(
                'WARNING: Cannot inflate volume to {}B, result size: {}B'
                .format(new_size, result_size)
            )

        self._zeroize(vdi_path, result_size - vhdutil.VHD_FOOTER_SIZE)
        self.set_size_phys(vdi_path, result_size, False)
        journaler.remove(LinstorJournaler.INFLATE, vdi_uuid)

    def deflate(self, vdi_path, new_size, old_size, zeroize=False):
        if zeroize:
            assert old_size > vhdutil.VHD_FOOTER_SIZE
            self._zeroize(vdi_path, old_size - vhdutil.VHD_FOOTER_SIZE)

        new_size = LinstorVolumeManager.round_up_volume_size(new_size)
        if new_size >= old_size:
            return

        util.SMlog(
            'Deflate {} (new size={}, previous={})'
            .format(vdi_path, new_size, old_size)
        )

        self.set_size_phys(vdi_path, new_size)
        # TODO: Change the LINSTOR volume size using linstor.resize_volume.

    # --------------------------------------------------------------------------
    # Remote setters: write locally and try on another host in case of failure.
    # --------------------------------------------------------------------------

    @linstormodifier()
    def force_parent(self, path, parentPath, parentRaw=False):
        kwargs = {
            'parentPath': str(parentPath),
            'parentRaw': parentRaw
        }
        return self._call_method(vhdutil.setParent, 'setParent', path, use_parent=False, **kwargs)

    @linstormodifier()
    def force_coalesce(self, path):
        return int(self._call_method(vhdutil.coalesce, 'coalesce', path, use_parent=True))

    @linstormodifier()
    def force_repair(self, path):
        return self._call_method(vhdutil.repair, 'repair', path, use_parent=False)

    @linstormodifier()
    def force_deflate(self, path, newSize, oldSize, zeroize):
        kwargs = {
            'newSize': newSize,
            'oldSize': oldSize,
            'zeroize': zeroize
        }
        return self._call_method('_force_deflate', 'deflate', path, use_parent=False, **kwargs)

    def _force_deflate(self, path, newSize, oldSize, zeroize):
        self.deflate(path, newSize, oldSize, zeroize)

    # --------------------------------------------------------------------------
    # Static helpers.
    # --------------------------------------------------------------------------

    @classmethod
    def compute_volume_size(cls, virtual_size, image_type):
        if image_type == vhdutil.VDI_TYPE_VHD:
            # All LINSTOR VDIs have the metadata area preallocated for
            # the maximum possible virtual size (for fast online VDI.resize).
            meta_overhead = vhdutil.calcOverheadEmpty(cls.MAX_SIZE)
            bitmap_overhead = vhdutil.calcOverheadBitmap(virtual_size)
            virtual_size += meta_overhead + bitmap_overhead
        elif image_type != vhdutil.VDI_TYPE_RAW:
            raise Exception('Invalid image type: {}'.format(image_type))

        return LinstorVolumeManager.round_up_volume_size(virtual_size)

    # --------------------------------------------------------------------------
    # Helpers.
    # --------------------------------------------------------------------------

    def _extract_uuid(self, device_path):
        # TODO: Remove new line in the vhdutil module. Not here.
        return self._linstor.get_volume_uuid_from_device_path(
            device_path.rstrip('\n')
        )

    def _get_readonly_host(self, vdi_uuid, device_path, node_names):
        """
        When vhd-util is called to fetch VDI info we must find a
        diskful DRBD disk to read the data. It's the goal of this function.
        Why? Because when a VHD is open in RO mode, the LVM layer is used
        directly to bypass DRBD verifications (we can have only one process
        that reads/writes to disk with DRBD devices).
        """

        if not node_names:
            raise xs_errors.XenError(
                'VDIUnavailable',
                opterr='Unable to find diskful node: {} (path={})'
                .format(vdi_uuid, device_path)
            )

        hosts = self._session.xenapi.host.get_all_records()
        for host_ref, host_record in hosts.items():
            if host_record['hostname'] in node_names:
                return host_ref

        raise xs_errors.XenError(
            'VDIUnavailable',
            opterr='Unable to find a valid host from VDI: {} (path={})'
            .format(vdi_uuid, device_path)
        )

    # --------------------------------------------------------------------------

    def _raise_openers_exception(self, device_path, e):
        if isinstance(e, util.CommandException):
            e_str = 'cmd: `{}`, code: `{}`, reason: `{}`'.format(e.cmd, e.code, e.reason)
        else:
            e_str = str(e)

        try:
            volume_uuid = self._linstor.get_volume_uuid_from_device_path(
                device_path
            )
            e_wrapper = Exception(
                e_str + ' (openers: {})'.format(
                    self._linstor.get_volume_openers(volume_uuid)
                )
            )
        except Exception as illformed_e:
            e_wrapper = Exception(
                e_str + ' (unable to get openers: {})'.format(illformed_e)
            )
        util.SMlog('raise opener exception: {}'.format(e_wrapper))
        raise e_wrapper  # pylint: disable = E0702

    def _call_local_method(self, local_method, device_path, *args, **kwargs):
        if isinstance(local_method, str):
            local_method = getattr(self, local_method)

        try:
            def local_call():
                try:
                    return local_method(device_path, *args, **kwargs)
                except util.CommandException as e:
                    if e.code == errno.EROFS or e.code == EMEDIUMTYPE:
                        raise ErofsLinstorCallException(e)  # Break retry calls.
                    if e.code == errno.ENOENT:
                        raise NoPathLinstorCallException(e)
                    raise e
            # Retry only locally if it's not an EROFS exception.
            return util.retry(local_call, 5, 2, exceptions=[util.CommandException])
        except util.CommandException as e:
            util.SMlog('failed to execute locally vhd-util (sys {})'.format(e.code))
            raise e

    def _call_local_method_or_fail(self, local_method, device_path, *args, **kwargs):
        try:
            return self._call_local_method(local_method, device_path, *args, **kwargs)
        except ErofsLinstorCallException as e:
            # Volume is locked on a host, find openers.
            self._raise_openers_exception(device_path, e.cmd_err)

    def _call_method(self, local_method, remote_method, device_path, use_parent, *args, **kwargs):
        # Note: `use_parent` exists to know if the VHD parent is used by the local/remote method.
        # Normally in case of failure, if the parent is unused we try to execute the method on
        # another host using the DRBD opener list. In the other case, if the parent is required,
        # we must check where this last one is open instead of the child.

        if isinstance(local_method, str):
            local_method = getattr(self, local_method)

        # A. Try to write locally...
        try:
            return self._call_local_method(local_method, device_path, *args, **kwargs)
        except Exception:
            pass

        util.SMlog('unable to execute `{}` locally, retry using a writable host...'.format(remote_method))

        # B. Execute the command on another host.
        # B.1. Get host list.
        try:
            hosts = self._session.xenapi.host.get_all_records()
        except Exception as e:
            raise xs_errors.XenError(
                'VDIUnavailable',
                opterr='Unable to get host list to run vhd-util command `{}` (path={}): {}'
                .format(remote_method, device_path, e)
            )

        # B.2. Prepare remote args.
        remote_args = {
            'devicePath': device_path,
            'groupName': self._linstor.group_name
        }
        remote_args.update(**kwargs)
        remote_args = {str(key): str(value) for key, value in remote_args.iteritems()}

        volume_uuid = self._linstor.get_volume_uuid_from_device_path(
            device_path
        )
        parent_volume_uuid = None
        if use_parent:
            parent_volume_uuid = self.get_parent(volume_uuid)

        openers_uuid = parent_volume_uuid if use_parent else volume_uuid

        # B.3. Call!
        def remote_call():
            try:
                all_openers = self._linstor.get_volume_openers(openers_uuid)
            except Exception as e:
                raise xs_errors.XenError(
                    'VDIUnavailable',
                    opterr='Unable to get DRBD openers to run vhd-util command `{}` (path={}): {}'
                    .format(remote_method, device_path, e)
                )

            no_host_found = True
            for hostname, openers in all_openers.iteritems():
                if not openers:
                    continue

                try:
                    host_ref = next(ref for ref, rec in hosts.iteritems() if rec['hostname'] == hostname)
                except StopIteration:
                    continue

                no_host_found = False
                try:
                    return call_remote_method(self._session, host_ref, remote_method, device_path, remote_args)
                except Exception:
                    pass

            if no_host_found:
                try:
                    return local_method(device_path, *args, **kwargs)
                except Exception as e:
                    self._raise_openers_exception(device_path, e)

            raise xs_errors.XenError(
                'VDIUnavailable',
                opterr='No valid host found to run vhd-util command `{}` (path=`{}`, openers=`{}`)'
                .format(remote_method, device_path, openers)
            )
        return util.retry(remote_call, 5, 2)

    @staticmethod
    def _zeroize(path, size):
        if not util.zeroOut(path, size, vhdutil.VHD_FOOTER_SIZE):
            raise xs_errors.XenError(
                'EIO',
                opterr='Failed to zero out VHD footer {}'.format(path)
            )
