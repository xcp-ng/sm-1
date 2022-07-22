#!/usr/bin/env python
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

import base64
import distutils.util
import errno
import json
import socket
import util
import vhdutil
import xs_errors

MANAGER_PLUGIN = 'linstor-manager'


def call_vhd_util(linstor, func, device_path, *args, **kwargs):
    try:
        return func(device_path, *args, **kwargs)
    except util.CommandException as e:
        # Raise if we don't have a lock on the volume on another host.
        if e.code != errno.EROFS:
            raise

    # Volume is locked on a host, find openers.
    e_with_openers = None
    try:
        volume_uuid = linstor.get_volume_uuid_from_device_path(
            device_path
        )
        e_with_openers = util.CommandException(
            e.code,
            e.cmd,
            e.reason + ' (openers: {})'.format(
                linstor.get_volume_openers(volume_uuid)
            )
        )
    except Exception as illformed_e:
        raise util.CommandException(
            e.code,
            e.cmd,
            e.reason + ' (unable to get openers: {})'.format(illformed_e)
        )
    raise e_with_openers  # pylint: disable = E0702


def linstorhostcall(local_method, remote_method):
    def decorated(func):
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
            (node_names, in_use) = \
                self._linstor.find_up_to_date_diskful_nodes(vdi_uuid)

            try:
                if not in_use or socket.gethostname() in node_names:
                    return call_vhd_util(self._linstor, local_method, device_path, *args[2:], **kwargs)
            except util.CommandException as e:
                # EMEDIUMTYPE constant (124) is not available in python2.
                if e.code != errno.EROFS and e.code != 124:
                    raise

            # B. Execute the plugin on master or slave.
            def exec_remote_method():
                host_ref = self._get_readonly_host(
                    vdi_uuid, device_path, node_names
                )
                args = {
                    'devicePath': device_path,
                    'groupName': self._linstor.group_name
                }
                args.update(**kwargs)

                try:
                    response = self._session.xenapi.host.call_plugin(
                        host_ref, MANAGER_PLUGIN, remote_method, args
                    )
                except Exception as e:
                    util.SMlog('call-plugin ({} with {}) exception: {}'.format(
                        remote_method, args, e
                    ))
                    raise

                util.SMlog('call-plugin ({} with {}) returned: {}'.format(
                    remote_method, args, response
                ))
                if response == 'False':
                    raise xs_errors.XenError(
                        'VDIUnavailable',
                        opterr='Plugin {} failed'.format(MANAGER_PLUGIN)
                    )
                kwargs['response'] = response

            util.retry(exec_remote_method, 5, 3)
            return func(*args, **kwargs)
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
    def __init__(self, session, linstor):
        self._session = session
        self._linstor = linstor

    # --------------------------------------------------------------------------
    # Getters.
    # --------------------------------------------------------------------------

    def check(self, vdi_uuid, ignore_missing_footer=False, fast=False):
        kwargs = {
            'ignoreMissingFooter': str(ignore_missing_footer),
            'fast': str(fast)
        }
        return self._check(vdi_uuid, **kwargs)

    @linstorhostcall(vhdutil.check, 'check')
    def _check(self, vdi_uuid, **kwargs):
        return distutils.util.strtobool(kwargs['response'])

    def get_vhd_info(self, vdi_uuid, include_parent=True):
        kwargs = {'includeParent': str(include_parent)}
        return self._get_vhd_info(vdi_uuid, self._extract_uuid, **kwargs)

    @linstorhostcall(vhdutil.getVHDInfo, 'getVHDInfo')
    def _get_vhd_info(self, vdi_uuid, *args, **kwargs):
        obj = json.loads(kwargs['response'])

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
    def has_parent(self, vdi_uuid, **kwargs):
        return distutils.util.strtobool(kwargs['response'])

    def get_parent(self, vdi_uuid):
        return self._get_parent(vdi_uuid, self._extract_uuid)

    @linstorhostcall(vhdutil.getParent, 'getParent')
    def _get_parent(self, vdi_uuid, *args, **kwargs):
        return kwargs['response']

    @linstorhostcall(vhdutil.getSizeVirt, 'getSizeVirt')
    def get_size_virt(self, vdi_uuid, **kwargs):
        return int(kwargs['response'])

    @linstorhostcall(vhdutil.getSizePhys, 'getSizePhys')
    def get_size_phys(self, vdi_uuid, **kwargs):
        return int(kwargs['response'])

    @linstorhostcall(vhdutil.getDepth, 'getDepth')
    def get_depth(self, vdi_uuid, **kwargs):
        return int(kwargs['response'])

    @linstorhostcall(vhdutil.getKeyHash, 'getKeyHash')
    def get_key_hash(self, vdi_uuid, **kwargs):
        return kwargs['response'] or None

    @linstorhostcall(vhdutil.getBlockBitmap, 'getBlockBitmap')
    def get_block_bitmap(self, vdi_uuid, **kwargs):
        return base64.b64decode(kwargs['response'])

    # --------------------------------------------------------------------------
    # Setters.
    # --------------------------------------------------------------------------

    @linstormodifier()
    def create(self, path, size, static, msize=0):
        return call_vhd_util(self._linstor, vhdutil.create, path, size, static, msize)

    @linstormodifier()
    def set_size_virt_fast(self, path, size):
        return call_vhd_util(self._linstor, vhdutil.setSizeVirtFast, path, size)

    @linstormodifier()
    def set_size_phys(self, path, size, debug=True):
        return call_vhd_util(self._linstor, vhdutil.setSizePhys, path, size, debug)

    @linstormodifier()
    def set_parent(self, path, parentPath, parentRaw):
        return call_vhd_util(self._linstor, vhdutil.setParent, path, parentPath, parentRaw)

    @linstormodifier()
    def set_hidden(self, path, hidden=True):
        return call_vhd_util(self._linstor, vhdutil.setHidden, path, hidden)

    @linstormodifier()
    def set_key(self, path, key_hash):
        return call_vhd_util(self._linstor, vhdutil.setKey, path, key_hash)

    @linstormodifier()
    def kill_data(self, path):
        return call_vhd_util(self._linstor, vhdutil.killData, path)

    @linstormodifier()
    def snapshot(self, path, parent, parentRaw, msize=0, checkEmpty=True):
        return call_vhd_util(self._linstor, vhdutil.snapshot, path, parent, parentRaw, msize, checkEmpty)

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
