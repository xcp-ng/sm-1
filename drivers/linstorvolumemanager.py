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
#


import glob
import json
import linstor
import os.path
import re
import shutil
import socket
import time
import util
import uuid


# Contains the data of the "/var/lib/linstor" directory.
DATABASE_VOLUME_NAME = 'xcp-persistent-database'
DATABASE_SIZE = 1 << 30  # 1GB.
DATABASE_PATH = '/var/lib/linstor'
DATABASE_MKFS = 'mkfs.ext4'

REG_DRBDADM_PRIMARY = re.compile("([^\\s]+)\\s+role:Primary")
REG_DRBDSETUP_IP = re.compile('[^\\s]+\\s+(.*):.*$')


# ==============================================================================

def round_up(value, divisor):
    assert divisor
    divisor = int(divisor)
    return int((int(value) + divisor - 1) / divisor) * divisor


def round_down(value, divisor):
    assert divisor
    value = int(value)
    return value - (value % int(divisor))


# ==============================================================================

def get_remote_host_ip(node_name):
    (ret, stdout, stderr) = util.doexec([
        'drbdsetup', 'show', DATABASE_VOLUME_NAME, '--json'
    ])
    if ret != 0:
        return

    try:
        conf = json.loads(stdout)
        if not conf:
            return

        for connection in conf[0]['connections']:
            if connection['net']['_name'] == node_name:
                value = connection['path']['_remote_host']
                res = REG_DRBDSETUP_IP.match(value)
                if res:
                    return res.groups()[0]
                break
    except Exception:
        pass


def _get_controller_uri():
    (ret, stdout, stderr) = util.doexec([
        'drbdadm', 'status', DATABASE_VOLUME_NAME
    ])
    if ret != 0:
        return

    if stdout.startswith('{} role:Primary'.format(DATABASE_VOLUME_NAME)):
        return 'linstor://localhost'

    res = REG_DRBDADM_PRIMARY.search(stdout)
    if res:
        node_name = res.groups()[0]
        ip = get_remote_host_ip(node_name)
        if ip:
            return 'linstor://' + ip


def get_controller_uri():
    retries = 0
    while True:
        uri = _get_controller_uri()
        if uri:
            return uri

        retries += 1
        if retries >= 10:
            break
        time.sleep(1)


def get_controller_node_name():
    (ret, stdout, stderr) = util.doexec([
        'drbdadm', 'status', DATABASE_VOLUME_NAME
    ])
    if ret != 0:
        return

    if stdout.startswith('{} role:Primary'.format(DATABASE_VOLUME_NAME)):
        return 'localhost'

    res = REG_DRBDADM_PRIMARY.search(stdout)
    if res:
        return res.groups()[0]


# ==============================================================================

class LinstorVolumeManagerError(Exception):
    ERR_GENERIC = 0,
    ERR_VOLUME_EXISTS = 1,
    ERR_VOLUME_NOT_EXISTS = 2

    def __init__(self, message, code=ERR_GENERIC):
        super(LinstorVolumeManagerError, self).__init__(message)
        self._code = code

    @property
    def code(self):
        return self._code


# ==============================================================================

# Note:
# If a storage pool is not accessible after a network change:
# linstor node interface modify <NODE> default --ip <IP>


class LinstorVolumeManager(object):
    """
    API to manager LINSTOR volumes in XCP-ng.
    A volume in this context is a physical part of the storage layer.
    """

    __slots__ = (
        '_linstor', '_logger',
        '_uri', '_base_group_name',
        '_redundancy', '_group_name',
        '_volumes', '_storage_pools',
        '_storage_pools_time',
        '_kv_cache', '_resource_cache', '_volume_info_cache',
        '_kv_cache_dirty', '_resource_cache_dirty', '_volume_info_cache_dirty'
    )

    DEV_ROOT_PATH = '/dev/drbd/by-res/'

    # Default LVM extent size.
    BLOCK_SIZE = 4 * 1024 * 1024

    # List of volume properties.
    PROP_METADATA = 'metadata'
    PROP_NOT_EXISTS = 'not-exists'
    PROP_VOLUME_NAME = 'volume-name'
    PROP_IS_READONLY_TIMESTAMP = 'readonly-timestamp'

    # A volume can only be locked for a limited duration.
    # The goal is to give enough time to slaves to execute some actions on
    # a device before an UUID update or a coalesce for example.
    # Expiration is expressed in seconds.
    LOCKED_EXPIRATION_DELAY = 1 * 60

    # Used when volume uuid is being updated.
    PROP_UPDATING_UUID_SRC = 'updating-uuid-src'

    # States of property PROP_NOT_EXISTS.
    STATE_EXISTS = '0'
    STATE_NOT_EXISTS = '1'
    STATE_CREATING = '2'

    # Property namespaces.
    NAMESPACE_SR = 'xcp/sr'
    NAMESPACE_VOLUME = 'volume'

    # Regex to match properties.
    REG_PROP = '^([^/]+)/{}$'

    REG_METADATA = re.compile(REG_PROP.format(PROP_METADATA))
    REG_NOT_EXISTS = re.compile(REG_PROP.format(PROP_NOT_EXISTS))
    REG_VOLUME_NAME = re.compile(REG_PROP.format(PROP_VOLUME_NAME))
    REG_UPDATING_UUID_SRC = re.compile(REG_PROP.format(PROP_UPDATING_UUID_SRC))

    # Prefixes of SR/VOLUME in the LINSTOR DB.
    # A LINSTOR (resource, group, ...) name cannot start with a number.
    # So we add a prefix behind our SR/VOLUME uuids.
    PREFIX_SR = 'xcp-sr-'
    PREFIX_VOLUME = 'xcp-volume-'

    # Limit request number when storage pool info is asked, we fetch
    # the current pool status after N elapsed seconds.
    STORAGE_POOLS_FETCH_INTERVAL = 15

    @staticmethod
    def default_logger(*args):
        print(args)

    # --------------------------------------------------------------------------
    # API.
    # --------------------------------------------------------------------------

    class VolumeInfo(object):
        __slots__ = (
            'name',
            'allocated_size',  # Allocated size, place count is not used.
            'virtual_size'    # Total virtual available size of this volume
                              # (i.e. the user size at creation).
        )

        def __init__(self, name):
            self.name = name
            self.allocated_size = 0
            self.virtual_size = 0

        def __repr__(self):
            return 'VolumeInfo("{}", {}, {})'.format(
                self.name, self.allocated_size, self.virtual_size
            )

    # --------------------------------------------------------------------------

    def __init__(
        self, uri, group_name, repair=False, logger=default_logger.__func__
    ):
        """
        Create a new LinstorVolumeManager object.
        :param str uri: URI to communicate with the LINSTOR controller.
        :param str group_name: The SR goup name to use.
        :param bool repair: If true we try to remove bad volumes due to a crash
        or unexpected behavior.
        :param function logger: Function to log messages.
        """

        self._linstor = self._create_linstor_instance(uri)
        self._base_group_name = group_name

        # Ensure group exists.
        group_name = self._build_group_name(group_name)
        groups = self._linstor.resource_group_list_raise([group_name])
        groups = groups.resource_groups
        if not groups:
            raise LinstorVolumeManagerError(
                'Unable to find `{}` Linstor SR'.format(group_name)
            )

        # Ok. ;)
        self._logger = logger
        self._redundancy = groups[0].select_filter.place_count
        self._group_name = group_name
        self._volumes = set()
        self._storage_pools_time = 0

        # To increate performance and limit request count to LINSTOR services,
        # we use caches.
        self._kv_cache = self._create_kv_cache()
        self._resource_cache = None
        self._resource_cache_dirty = True
        self._volume_info_cache = None
        self._volume_info_cache_dirty = True
        self._build_volumes(repair=repair)

    @property
    def group_name(self):
        """
        Give the used group name.
        :return: The group name.
        :rtype: str
        """
        return self._base_group_name

    @property
    def volumes(self):
        """
        Give the volumes uuid set.
        :return: The volumes uuid set.
        :rtype: set(str)
        """
        return self._volumes

    @property
    def max_volume_size_allowed(self):
        """
        Give the max volume size currently available in B.
        :return: The current size.
        :rtype: int
        """

        candidates = self._find_best_size_candidates()
        if not candidates:
            raise LinstorVolumeManagerError(
                'Failed to get max volume size allowed'
            )

        size = candidates[0].max_volume_size
        if size < 0:
            raise LinstorVolumeManagerError(
                'Invalid max volume size allowed given: {}'.format(size)
            )
        return self.round_down_volume_size(size * 1024)

    @property
    def physical_size(self):
        """
        Give the total physical size of the SR.
        :return: The physical size.
        :rtype: int
        """
        return self._compute_size('total_capacity')

    @property
    def physical_free_size(self):
        """
        Give the total free physical size of the SR.
        :return: The physical free size.
        :rtype: int
        """
        return self._compute_size('free_capacity')

    @property
    def min_physical_size(self):
        """
        Give the minimum physical size of the SR.
        I.e. the size of the smallest disk.
        :return: The physical min size.
        :rtype: int
        """
        size = None
        for pool in self._get_storage_pools(force=True):
            space = pool.free_space
            if space:
                current_size = space.total_capacity
                if current_size < 0:
                    raise LinstorVolumeManagerError(
                        'Failed to get pool total_capacity attr of `{}`'
                        .format(pool.node_name)
                    )
                if size is None or current_size < size:
                    size = current_size
        return (size or 0) * 1024

    @property
    def total_volume_size(self):
        """
        Give the sum of all created volumes. The place count is used.
        :return: The physical required size to use the volumes.
        :rtype: int
        """

        size = 0
        for resource in self._get_resource_cache().resources:
            for volume in resource.volumes:
                # We ignore diskless pools of the form "DfltDisklessStorPool".
                if volume.storage_pool_name == self._group_name:
                    current_size = volume.usable_size
                    if current_size < 0:
                        raise LinstorVolumeManagerError(
                           'Failed to get usable size of `{}` on `{}`'
                           .format(resource.name, volume.storage_pool_name)
                        )
                    size += current_size
        return size * 1024

    @property
    def allocated_volume_size(self):
        """
        Give the allocated size for all volumes. The place count is not
        used here. When thick lvm is used, the size for one volume should
        be equal to the virtual volume size. With thin lvm, the size is equal
        or lower to the volume size.
        :return: The allocated size of all volumes.
        :rtype: int
        """

        size = 0
        for resource in self._get_resource_cache().resources:
            volume_size = None
            for volume in resource.volumes:
                # We ignore diskless pools of the form "DfltDisklessStorPool".
                if volume.storage_pool_name == self._group_name:
                    current_size = volume.allocated_size
                    if current_size < 0:
                        raise LinstorVolumeManagerError(
                           'Failed to get allocated size of `{}` on `{}`'
                           .format(resource.name, volume.storage_pool_name)
                        )

                    if volume_size is None or current_size > volume_size:
                        volume_size = current_size
            if volume_size is not None:
                size += volume_size

        return size * 1024

    @property
    def metadata(self):
        """
        Get the metadata of the SR.
        :return: Dictionary that contains metadata.
        :rtype: dict(str, dict)
        """

        sr_properties = self._get_sr_properties()
        metadata = sr_properties.get(self.PROP_METADATA)
        if metadata is not None:
            metadata = json.loads(metadata)
            if isinstance(metadata, dict):
                return metadata
            raise LinstorVolumeManagerError(
                'Expected dictionary in SR metadata: {}'.format(
                    self._group_name
                )
            )

        return {}

    @metadata.setter
    def metadata(self, metadata):
        """
        Set the metadata of the SR.
        :param dict metadata: Dictionary that contains metadata.
        """

        assert isinstance(metadata, dict)
        sr_properties = self._get_sr_properties()
        sr_properties[self.PROP_METADATA] = json.dumps(metadata)

    @property
    def disconnected_hosts(self):
        """
        Get the list of disconnected hosts.
        :return: Set that contains disconnected hosts.
        :rtype: set(str)
        """

        disconnected_hosts = set()
        for pool in self._get_storage_pools():
            for report in pool.reports:
                if report.ret_code & linstor.consts.WARN_NOT_CONNECTED == \
                        linstor.consts.WARN_NOT_CONNECTED:
                    disconnected_hosts.add(pool.node_name)
                    break
        return disconnected_hosts

    def check_volume_exists(self, volume_uuid):
        """
        Check if a volume exists in the SR.
        :return: True if volume exists.
        :rtype: bool
        """
        return volume_uuid in self._volumes

    def create_volume(
        self, volume_uuid, size, persistent=True, volume_name=None
    ):
        """
        Create a new volume on the SR.
        :param str volume_uuid: The volume uuid to use.
        :param int size: volume size in B.
        :param bool persistent: If false the volume will be unavailable
        on the next constructor call LinstorSR(...).
        :param str volume_name: If set, this name is used in the LINSTOR
        database instead of a generated name.
        :return: The current device path of the volume.
        :rtype: str
        """

        self._logger('Creating LINSTOR volume {}...'.format(volume_uuid))
        if not volume_name:
            volume_name = self.build_volume_name(util.gen_uuid())
        volume_properties = self._create_volume_with_properties(
            volume_uuid, volume_name, size, place_resources=True
        )

        try:
            self._logger(
                'Find device path of LINSTOR volume {}...'.format(volume_uuid)
            )
            device_path = self._find_device_path(volume_uuid, volume_name)
            if persistent:
                volume_properties[self.PROP_NOT_EXISTS] = self.STATE_EXISTS
            self._volumes.add(volume_uuid)
            self._logger(
                'LINSTOR volume {} created!'.format(volume_uuid)
            )
            return device_path
        except Exception:
            self._force_destroy_volume(volume_uuid)
            raise

    def mark_volume_as_persistent(self, volume_uuid):
        """
        Mark volume as persistent if created with persistent=False.
        :param str volume_uuid: The volume uuid to mark.
        """

        self._ensure_volume_exists(volume_uuid)

        # Mark volume as persistent.
        volume_properties = self._get_volume_properties(volume_uuid)
        volume_properties[self.PROP_NOT_EXISTS] = self.STATE_EXISTS

    def destroy_volume(self, volume_uuid):
        """
        Destroy a volume.
        :param str volume_uuid: The volume uuid to destroy.
        """

        self._ensure_volume_exists(volume_uuid)
        self.ensure_volume_is_not_locked(volume_uuid)

        # Mark volume as destroyed.
        volume_properties = self._get_volume_properties(volume_uuid)
        volume_properties[self.PROP_NOT_EXISTS] = self.STATE_NOT_EXISTS

        self._volumes.remove(volume_uuid)
        self._destroy_volume(volume_uuid)

    def lock_volume(self, volume_uuid, locked=True):
        """
        Prevent modifications of the volume properties during
        "self.LOCKED_EXPIRATION_DELAY" seconds. The SR must be locked
        when used. This method is useful to attach/detach correctly a volume on
        a slave. Without it the GC can rename a volume, in this case the old
        volume path can be used by a slave...
        :param str volume_uuid: The volume uuid to protect/unprotect.
        :param bool locked: Lock/unlock the volume.
        """

        self._ensure_volume_exists(volume_uuid)

        self._logger(
            '{} volume {} as locked'.format(
                'Mark' if locked else 'Unmark',
                volume_uuid
            )
        )

        volume_properties = self._get_volume_properties(volume_uuid)
        if locked:
            volume_properties[
                self.PROP_IS_READONLY_TIMESTAMP
            ] = str(time.time())
        elif self.PROP_IS_READONLY_TIMESTAMP in volume_properties:
            volume_properties.pop(self.PROP_IS_READONLY_TIMESTAMP)

    def ensure_volume_is_not_locked(self, volume_uuid, timeout=None):
        """
        Ensure a volume is not locked. Wait if necessary.
        :param str volume_uuid: The volume uuid to check.
        :param int timeout: If the volume is always locked after the expiration
        of the timeout, an exception is thrown.
        """
        return self.ensure_volume_list_is_not_locked([volume_uuid], timeout)

    def ensure_volume_list_is_not_locked(self, volume_uuids, timeout=None):
        checked = set()
        for volume_uuid in volume_uuids:
            if volume_uuid in self._volumes:
                checked.add(volume_uuid)

        if not checked:
            return

        waiting = False

        volume_properties = self._get_kv_cache()

        start = time.time()
        while True:
            # Can't delete in for loop, use a copy of the list.
            remaining = checked.copy()
            for volume_uuid in checked:
                volume_properties.namespace = \
                    self._build_volume_namespace(volume_uuid)
                timestamp = volume_properties.get(
                    self.PROP_IS_READONLY_TIMESTAMP
                )
                if timestamp is None:
                    remaining.remove(volume_uuid)
                    continue

                now = time.time()
                if now - float(timestamp) > self.LOCKED_EXPIRATION_DELAY:
                    self._logger(
                        'Remove readonly timestamp on {}'.format(volume_uuid)
                    )
                    volume_properties.pop(self.PROP_IS_READONLY_TIMESTAMP)
                    remaining.remove(volume_uuid)
                    continue

                if not waiting:
                    self._logger(
                        'Volume {} is locked, waiting...'.format(volume_uuid)
                    )
                    waiting = True
                break

            if not remaining:
                break
            checked = remaining

            if timeout is not None and now - start > timeout:
                raise LinstorVolumeManagerError(
                    'volume `{}` is locked and timeout has been reached'
                    .format(volume_uuid),
                    LinstorVolumeManagerError.ERR_VOLUME_NOT_EXISTS
                )

            # We must wait to use the volume. After that we can modify it
            # ONLY if the SR is locked to avoid bad reads on the slaves.
            time.sleep(1)
            volume_properties = self._create_kv_cache()

        if waiting:
            self._logger('No volume locked now!')

    def introduce_volume(self, volume_uuid):
        pass  # TODO: Implement me.

    def resize_volume(self, volume_uuid, new_size):
        """
        Resize a volume.
        :param str volume_uuid: The volume uuid to resize.
        :param int new_size: New size in B.
        """

        volume_name = self.get_volume_name(volume_uuid)
        self.ensure_volume_is_not_locked(volume_uuid)
        new_size = self.round_up_volume_size(new_size)

        result = self._linstor.volume_dfn_modify(
            rsc_name=volume_name,
            volume_nr=0,
            size=new_size / 1024
        )

        self._mark_resource_cache_as_dirty()

        error_str = self._get_error_str(result)
        if error_str:
            raise LinstorVolumeManagerError(
                'Could not resize volume `{}` from SR `{}`: {}'
                .format(volume_uuid, self._group_name, error_str)
            )

    def get_volume_name(self, volume_uuid):
        """
        Get the name of a particular volume.
        :param str volume_uuid: The volume uuid of the name to get.
        :return: The volume name.
        :rtype: str
        """

        self._ensure_volume_exists(volume_uuid)
        volume_properties = self._get_volume_properties(volume_uuid)
        volume_name = volume_properties.get(self.PROP_VOLUME_NAME)
        if volume_name:
            return volume_name
        raise LinstorVolumeManagerError(
            'Failed to get volume name of {}'.format(volume_uuid)
        )

    def get_volume_size(self, volume_uuid):
        """
        Get the size of a particular volume.
        :param str volume_uuid: The volume uuid of the size to get.
        :return: The volume size.
        :rtype: int
        """

        volume_name = self.get_volume_name(volume_uuid)
        dfns = self._linstor.resource_dfn_list_raise(
            query_volume_definitions=True,
            filter_by_resource_definitions=[volume_name]
        ).resource_definitions

        size = dfns[0].volume_definitions[0].size
        if size < 0:
            raise LinstorVolumeManagerError(
                'Failed to get volume size of: {}'.format(volume_uuid)
            )
        return size * 1024

    def get_volume_info(self, volume_uuid):
        """
        Get the volume info of a particular volume.
        :param str volume_uuid: The volume uuid of the volume info to get.
        :return: The volume info.
        :rtype: VolumeInfo
        """

        volume_name = self.get_volume_name(volume_uuid)
        return self._get_volumes_info()[volume_name]

    def get_device_path(self, volume_uuid):
        """
        Get the dev path of a volume.
        :param str volume_uuid: The volume uuid to get the dev path.
        :return: The current device path of the volume.
        :rtype: str
        """

        volume_name = self.get_volume_name(volume_uuid)
        return self._find_device_path(volume_uuid, volume_name)

    def get_volume_uuid_from_device_path(self, device_path):
        """
        Get the volume uuid of a device_path.
        :param str device_path: The dev path to find the volume uuid.
        :return: The volume uuid of the local device path.
        :rtype: str
        """

        expected_volume_name = \
            self.get_volume_name_from_device_path(device_path)

        volume_names = self.get_volumes_with_name()
        for volume_uuid, volume_name in volume_names.items():
            if volume_name == expected_volume_name:
                return volume_uuid

        raise LinstorVolumeManagerError(
            'Unable to find volume uuid from dev path `{}`'.format(device_path)
        )

    def get_volume_name_from_device_path(self, device_path):
        """
        Get the volume name of a device_path on the current host.
        :param str device_path: The dev path to find the volume name.
        :return: The volume name of the local device path.
        :rtype: str
        """

        node_name = socket.gethostname()

        resources = filter(
            lambda resource: resource.node_name == node_name,
            self._get_resource_cache().resources
        )

        real_device_path = os.path.realpath(device_path)
        for resource in resources:
            if resource.volumes[0].device_path == real_device_path:
                return resource.name

        raise LinstorVolumeManagerError(
            'Unable to find volume name from dev path `{}`'
            .format(device_path)
        )

    def update_volume_uuid(self, volume_uuid, new_volume_uuid, force=False):
        """
        Change the uuid of a volume.
        :param str volume_uuid: The volume to modify.
        :param str new_volume_uuid: The new volume uuid to use.
        :param bool force: If true we doesn't check if volume_uuid is in the
        volume list. I.e. the volume can be marked as deleted but the volume
        can still be in the LINSTOR KV store if the deletion has failed.
        In specific cases like "undo" after a failed clone we must rename a bad
        deleted VDI.
        """

        assert volume_uuid != new_volume_uuid

        self._logger(
            'Trying to update volume UUID {} to {}...'
            .format(volume_uuid, new_volume_uuid)
        )
        if not force:
            self._ensure_volume_exists(volume_uuid)
        self.ensure_volume_is_not_locked(volume_uuid)

        if new_volume_uuid in self._volumes:
            raise LinstorVolumeManagerError(
                'Volume `{}` already exists'.format(new_volume_uuid),
                LinstorVolumeManagerError.ERR_VOLUME_EXISTS
            )

        volume_properties = self._get_volume_properties(volume_uuid)
        if volume_properties.get(self.PROP_UPDATING_UUID_SRC):
            raise LinstorVolumeManagerError(
                'Cannot update volume uuid {}: invalid state'
                .format(volume_uuid)
            )

        # 1. Copy in temp variables metadata and volume_name.
        metadata = volume_properties.get(self.PROP_METADATA)
        volume_name = volume_properties.get(self.PROP_VOLUME_NAME)

        # 2. Switch to new volume namespace.
        volume_properties.namespace = self._build_volume_namespace(
            new_volume_uuid
        )

        if list(volume_properties.items()):
            raise LinstorVolumeManagerError(
                'Cannot update volume uuid {} to {}: '
                .format(volume_uuid, new_volume_uuid) +
                'this last one is not empty'
            )

        try:
            # 3. Mark new volume properties with PROP_UPDATING_UUID_SRC.
            # If we crash after that, the new properties can be removed
            # properly.
            volume_properties[self.PROP_NOT_EXISTS] = self.STATE_NOT_EXISTS
            volume_properties[self.PROP_UPDATING_UUID_SRC] = volume_uuid

            # 4. Copy the properties.
            volume_properties[self.PROP_METADATA] = metadata
            volume_properties[self.PROP_VOLUME_NAME] = volume_name

            # 5. Ok!
            volume_properties[self.PROP_NOT_EXISTS] = self.STATE_EXISTS
        except Exception as e:
            try:
                # Clear the new volume properties in case of failure.
                assert volume_properties.namespace == \
                    self._build_volume_namespace(new_volume_uuid)
                volume_properties.clear()
            except Exception as e:
                self._logger(
                    'Failed to clear new volume properties: {} (ignoring...)'
                    .format(e)
                )
            raise LinstorVolumeManagerError(
                'Failed to copy volume properties: {}'.format(e)
            )

        try:
            # 6. After this point, it's ok we can remove the
            # PROP_UPDATING_UUID_SRC property and clear the src properties
            # without problems.

            # 7. Switch to old volume namespace.
            volume_properties.namespace = self._build_volume_namespace(
                volume_uuid
            )
            volume_properties.clear()

            # 8. Switch a last time to new volume namespace.
            volume_properties.namespace = self._build_volume_namespace(
                new_volume_uuid
            )
            volume_properties.pop(self.PROP_UPDATING_UUID_SRC)
        except Exception as e:
            raise LinstorVolumeManagerError(
                'Failed to clear volume properties '
                'after volume uuid update: {}'.format(e)
            )

        self._volumes.remove(volume_uuid)
        self._volumes.add(new_volume_uuid)

        self._logger(
            'UUID update succeeded of {} to {}! (properties={})'
            .format(
                volume_uuid, new_volume_uuid,
                self._get_filtered_properties(volume_properties)
            )
        )

    def update_volume_name(self, volume_uuid, volume_name):
        """
        Change the volume name of a volume.
        :param str volume_uuid: The volume to modify.
        :param str volume_name: The volume_name to use.
        """

        self._ensure_volume_exists(volume_uuid)
        self.ensure_volume_is_not_locked(volume_uuid)
        if not volume_name.startswith(self.PREFIX_VOLUME):
            raise LinstorVolumeManagerError(
                'Volume name `{}` must be start with `{}`'
                .format(volume_name, self.PREFIX_VOLUME)
            )

        if volume_name not in self._fetch_resource_names():
            raise LinstorVolumeManagerError(
                'Volume `{}` doesn\'t exist'.format(volume_name)
            )

        volume_properties = self._get_volume_properties(volume_uuid)
        volume_properties[self.PROP_VOLUME_NAME] = volume_name

    def get_usage_states(self, volume_uuid):
        """
        Check if a volume is currently used.
        :param str volume_uuid: The volume uuid to check.
        :return: A dictionnary that contains states.
        :rtype: dict(str, bool or None)
        """

        states = {}

        volume_name = self.get_volume_name(volume_uuid)
        for resource_state in self._linstor.resource_list_raise(
            filter_by_resources=[volume_name]
        ).resource_states:
            states[resource_state.node_name] = resource_state.in_use

        return states

    def get_volumes_with_name(self):
        """
        Give a volume dictionnary that contains names actually owned.
        :return: A volume/name dict.
        :rtype: dict(str, str)
        """
        return self._get_volumes_by_property(self.REG_VOLUME_NAME)

    def get_volumes_with_info(self):
        """
        Give a volume dictionnary that contains VolumeInfos.
        :return: A volume/VolumeInfo dict.
        :rtype: dict(str, VolumeInfo)
        """

        volumes = {}

        all_volume_info = self._get_volumes_info()
        volume_names = self.get_volumes_with_name()
        for volume_uuid, volume_name in volume_names.items():
            if volume_name:
                volume_info = all_volume_info.get(volume_name)
                if volume_info:
                    volumes[volume_uuid] = volume_info
                    continue

            # Well I suppose if this volume is not available,
            # LINSTOR has been used directly without using this API.
            volumes[volume_uuid] = self.VolumeInfo('')

        return volumes

    def get_volumes_with_metadata(self):
        """
        Give a volume dictionnary that contains metadata.
        :return: A volume/metadata dict.
        :rtype: dict(str, dict)
        """

        volumes = {}

        metadata = self._get_volumes_by_property(self.REG_METADATA)
        for volume_uuid, volume_metadata in metadata.items():
            if volume_metadata:
                volume_metadata = json.loads(volume_metadata)
                if isinstance(volume_metadata, dict):
                    volumes[volume_uuid] = volume_metadata
                    continue
                raise LinstorVolumeManagerError(
                    'Expected dictionary in volume metadata: {}'
                    .format(volume_uuid)
                )

            volumes[volume_uuid] = {}

        return volumes

    def get_volume_metadata(self, volume_uuid):
        """
        Get the metadata of a volume.
        :return: Dictionary that contains metadata.
        :rtype: dict
        """

        self._ensure_volume_exists(volume_uuid)
        volume_properties = self._get_volume_properties(volume_uuid)
        metadata = volume_properties.get(self.PROP_METADATA)
        if metadata:
            metadata = json.loads(metadata)
            if isinstance(metadata, dict):
                return metadata
            raise LinstorVolumeManagerError(
                'Expected dictionary in volume metadata: {}'
                .format(volume_uuid)
            )
        return {}

    def set_volume_metadata(self, volume_uuid, metadata):
        """
        Set the metadata of a volume.
        :param dict metadata: Dictionary that contains metadata.
        """

        self._ensure_volume_exists(volume_uuid)
        self.ensure_volume_is_not_locked(volume_uuid)

        assert isinstance(metadata, dict)
        volume_properties = self._get_volume_properties(volume_uuid)
        volume_properties[self.PROP_METADATA] = json.dumps(metadata)

    def update_volume_metadata(self, volume_uuid, metadata):
        """
        Update the metadata of a volume. It modify only the given keys.
        It doesn't remove unreferenced key instead of set_volume_metadata.
        :param dict metadata: Dictionary that contains metadata.
        """

        self._ensure_volume_exists(volume_uuid)
        self.ensure_volume_is_not_locked(volume_uuid)

        assert isinstance(metadata, dict)
        volume_properties = self._get_volume_properties(volume_uuid)

        current_metadata = json.loads(
            volume_properties.get(self.PROP_METADATA, '{}')
        )
        if not isinstance(metadata, dict):
            raise LinstorVolumeManagerError(
                'Expected dictionary in volume metadata: {}'
                .format(volume_uuid)
            )

        for key, value in metadata.items():
            current_metadata[key] = value
        volume_properties[self.PROP_METADATA] = json.dumps(current_metadata)

    def shallow_clone_volume(self, volume_uuid, clone_uuid, persistent=True):
        """
        Clone a volume. Do not copy the data, this method creates a new volume
        with the same size. It tries to create the volume on the same host
        than volume source.
        :param str volume_uuid: The volume to clone.
        :param str clone_uuid: The cloned volume.
        :param bool persistent: If false the volume will be unavailable
        on the next constructor call LinstorSR(...).
        :return: The current device path of the cloned volume.
        :rtype: str
        """

        volume_name = self.get_volume_name(volume_uuid)
        self.ensure_volume_is_not_locked(volume_uuid)

        # 1. Find ideal nodes + size to use.
        ideal_node_names, size = self._get_volume_node_names_and_size(
            volume_name
        )
        if size <= 0:
            raise LinstorVolumeManagerError(
                'Invalid size of {} for volume `{}`'.format(size, volume_name)
            )

        # 2. Find the node(s) with the maximum space.
        candidates = self._find_best_size_candidates()
        if not candidates:
            raise LinstorVolumeManagerError(
                'Unable to shallow clone volume `{}`, no free space found.'
            )

        # 3. Compute node names and search if we can try to clone
        # on the same nodes than volume.
        def find_best_nodes():
            for candidate in candidates:
                for node_name in candidate.node_names:
                    if node_name in ideal_node_names:
                        return candidate.node_names

        node_names = find_best_nodes()
        if not node_names:
            node_names = candidates[0].node_names

        if len(node_names) < self._redundancy:
            raise LinstorVolumeManagerError(
                'Unable to shallow clone volume `{}`, '.format(volume_uuid) +
                '{} are required to clone, found: {}'.format(
                    self._redundancy, len(node_names)
                )
            )

        # 4. Compute resources to create.
        clone_volume_name = self.build_volume_name(util.gen_uuid())
        diskless_node_names = self._get_node_names()
        resources = []
        for node_name in node_names:
            diskless_node_names.remove(node_name)
            resources.append(linstor.ResourceData(
                node_name=node_name,
                rsc_name=clone_volume_name,
                storage_pool=self._group_name
            ))
        for node_name in diskless_node_names:
            resources.append(linstor.ResourceData(
                node_name=node_name,
                rsc_name=clone_volume_name,
                diskless=True
            ))

        # 5. Create resources!
        def clean():
            try:
                self._destroy_volume(clone_uuid)
            except Exception as e:
                self._logger(
                    'Unable to destroy volume {} after shallow clone fail: {}'
                    .format(clone_uuid, e)
                )

        def create():
            try:
                volume_properties = self._create_volume_with_properties(
                    clone_uuid, clone_volume_name, size,
                    place_resources=False
                )

                result = self._linstor.resource_create(resources)
                error_str = self._get_error_str(result)
                if error_str:
                    raise LinstorVolumeManagerError(
                        'Could not create cloned volume `{}` of `{}` from '
                        'SR `{}`: {}'.format(
                            clone_uuid, volume_uuid, self._group_name,
                            error_str
                        )
                    )
                return volume_properties
            except Exception:
                clean()
                raise

        # Retry because we can get errors like this:
        # "Resource disappeared while waiting for it to be ready" or
        # "Resource did not became ready on node 'XXX' within reasonable time, check Satellite for errors."
        # in the LINSTOR server.
        volume_properties = util.retry(create, maxretry=5)

        try:
            device_path = self._find_device_path(clone_uuid, clone_volume_name)
            if persistent:
                volume_properties[self.PROP_NOT_EXISTS] = self.STATE_EXISTS
            self._volumes.add(clone_uuid)
            return device_path
        except Exception as e:
            clean()
            raise

    def remove_resourceless_volumes(self):
        """
        Remove all volumes without valid or non-empty name
        (i.e. without LINSTOR resource). It's different than
        LinstorVolumeManager constructor that takes a `repair` param that
        removes volumes with `PROP_NOT_EXISTS` to 1.
        """

        resource_names = self._fetch_resource_names()
        for volume_uuid, volume_name in self.get_volumes_with_name().items():
            if not volume_name or volume_name not in resource_names:
                self.destroy_volume(volume_uuid)

    def destroy(self):
        """
        Destroy this SR. Object should not be used after that.
        :param bool force: Try to destroy volumes before if true.
        """

        if self._volumes:
            raise LinstorVolumeManagerError(
                'Cannot destroy LINSTOR volume manager: '
                'It exists remaining volumes'
            )

        uri = 'linstor://localhost'
        try:
            self._start_controller(start=False)

            # 1. Umount LINSTOR database.
            self._mount_database_volume(
                self.build_device_path(DATABASE_VOLUME_NAME),
                mount=False,
                force=True
            )

            # 2. Refresh instance.
            self._start_controller(start=True)
            self._linstor = self._create_linstor_instance(
                uri, keep_uri_unmodified=True
            )

            # 3. Destroy database volume.
            self._destroy_resource(DATABASE_VOLUME_NAME)

            # 4. Destroy group and storage pools.
            self._destroy_resource_group(self._linstor, self._group_name)
            for pool in self._get_storage_pools(force=True):
                self._destroy_storage_pool(
                    self._linstor, pool.name, pool.node_name
                )
        except Exception as e:
            self._start_controller(start=True)
            raise e

        try:
            self._start_controller(start=False)
            for file in glob.glob(DATABASE_PATH + '/'):
                os.remove(file)
        except Exception as e:
            util.SMlog(
                'Ignoring failure after LINSTOR SR destruction: {}'
                .format(e)
            )

    def find_up_to_date_diskfull_nodes(self, volume_uuid):
        """
        Find all nodes that contain a specific volume using diskfull disks.
        The disk must be up to data to be used.
        :param str volume_uuid: The volume to use.
        :return: The available nodes.
        :rtype: tuple(set(str), bool)
        """

        volume_name = self.get_volume_name(volume_uuid)

        in_use = False
        node_names = set()

        resource_states = filter(
            lambda resource_state: resource_state.name == volume_name,
            self._get_resource_cache().resource_states
        )

        for resource_state in resource_states:
            volume_state = resource_state.volume_states[0]
            if volume_state.disk_state == 'UpToDate':
                node_names.add(resource_state.node_name)
            if resource_state.in_use:
                in_use = True

        return (node_names, in_use)

    def invalidate_resource_cache(self):
        """
        If resources are impacted by external commands like vhdutil,
        it's necessary to call this function to invalidate current resource
        cache.
        """
        self._mark_resource_cache_as_dirty()

    @classmethod
    def create_sr(
        cls, group_name, node_names, ips, redundancy,
        thin_provisioning=False,
        logger=default_logger.__func__
    ):
        """
        Create a new SR on the given nodes.
        :param str group_name: The SR group_name to use.
        :param list[str] node_names: String list of nodes.
        :param int redundancy: How many copy of volumes should we store?
        :param set(str) ips: Node ips
        :param function logger: Function to log messages.
        :return: A new LinstorSr instance.
        :rtype: LinstorSr
        """

        try:
            cls._start_controller(start=True)
            sr = cls._create_sr(
                group_name,
                node_names,
                ips,
                redundancy,
                thin_provisioning,
                logger
            )
        finally:
            # Controller must be stopped and volume unmounted because
            # it is the role of the minidrbdcluster daemon to do the right
            # actions.
            cls._start_controller(start=False)
            cls._mount_volume(
                cls.build_device_path(DATABASE_VOLUME_NAME),
                DATABASE_PATH,
                mount=False
            )
        return sr

    @classmethod
    def _create_sr(
        cls, group_name, node_names, ips, redundancy,
        thin_provisioning=False,
        logger=default_logger.__func__
    ):
        # 1. Check if SR already exists.
        uri = 'linstor://localhost'

        lin = cls._create_linstor_instance(uri, keep_uri_unmodified=True)

        for node_name in node_names:
            ip = ips[node_name]
            result = lin.node_create(
                node_name,
                linstor.consts.VAL_NODE_TYPE_CMBD,
                ip
            )
            errors = cls._filter_errors(result)
            if cls._check_errors(errors, [linstor.consts.FAIL_EXISTS_NODE]):
                continue

            if errors:
                raise LinstorVolumeManagerError(
                    'Failed to create node `{}` with ip `{}`: {}'.format(
                        node_name, ip, cls._get_error_str(errors)
                    )
                )

        driver_pool_name = group_name
        group_name = cls._build_group_name(group_name)
        pools = lin.storage_pool_list_raise(filter_by_stor_pools=[group_name])
        pools = pools.storage_pools
        if pools:
            existing_node_names = map(lambda pool: pool.node_name, pools)
            raise LinstorVolumeManagerError(
                'Unable to create SR `{}`. It already exists on node(s): {}'
                .format(group_name, existing_node_names)
            )

        if lin.resource_group_list_raise(
            [group_name]
        ).resource_groups:
            raise LinstorVolumeManagerError(
                'Unable to create SR `{}`: The group name already exists'
                .format(group_name)
            )

        if thin_provisioning:
            driver_pool_parts = driver_pool_name.split('/')
            if not len(driver_pool_parts) == 2:
                raise LinstorVolumeManagerError(
                    'Invalid group name using thin provisioning. '
                    'Expected format: \'VG/LV`\''
                )

        # 2. Create storage pool on each node + resource group.
        i = 0
        try:
            # 2.a. Create storage pools.
            while i < len(node_names):
                node_name = node_names[i]

                result = lin.storage_pool_create(
                    node_name=node_name,
                    storage_pool_name=group_name,
                    storage_driver='LVM_THIN' if thin_provisioning else 'LVM',
                    driver_pool_name=driver_pool_name
                )

                error_str = cls._get_error_str(result)
                if error_str:
                    raise LinstorVolumeManagerError(
                        'Could not create SP `{}` on node `{}`: {}'.format(
                            group_name,
                            node_name,
                            error_str
                        )
                    )
                i += 1

            # 2.b. Create resource group.
            result = lin.resource_group_create(
                name=group_name,
                place_count=redundancy,
                storage_pool=group_name,
                diskless_on_remaining=True
            )
            error_str = cls._get_error_str(result)
            if error_str:
                raise LinstorVolumeManagerError(
                    'Could not create RG `{}`: {}'.format(
                        group_name, error_str
                    )
                )

            # 2.c. Create volume group.
            result = lin.volume_group_create(group_name)
            error_str = cls._get_error_str(result)
            if error_str:
                raise LinstorVolumeManagerError(
                    'Could not create VG `{}`: {}'.format(
                        group_name, error_str
                    )
                )

            # 3. Create the LINSTOR database volume and mount it.
            try:
                logger('Creating database volume...')
                volume_path = cls._create_database_volume(lin, group_name)
            except LinstorVolumeManagerError as e:
                if e.code != LinstorVolumeManagerError.ERR_VOLUME_EXISTS:
                    logger('Destroying database volume after creation fail...')
                    cls._force_destroy_database_volume(lin, group_name)
                raise

            try:
                logger('Mounting database volume...')

                # First we must disable the controller to move safely the
                # LINSTOR config.
                cls._start_controller(start=False)

                cls._mount_database_volume(volume_path)
            except Exception as e:
                # Ensure we are connected because controller has been
                # restarted during mount call.
                logger('Destroying database volume after mount fail...')

                try:
                    cls._start_controller(start=True)
                except Exception:
                    pass

                lin = cls._create_linstor_instance(
                    uri, keep_uri_unmodified=True
                )
                cls._force_destroy_database_volume(lin, group_name)
                raise e

            cls._start_controller(start=True)
            lin = cls._create_linstor_instance(uri, keep_uri_unmodified=True)

        # 4. Remove storage pools/resource/volume group in the case of errors.
        except Exception as e:
            logger('Destroying resource group and storage pools after fail...')
            try:
                cls._destroy_resource_group(lin, group_name)
            except Exception as e2:
                logger('Failed to destroy resource group: {}'.format(e2))
                pass
            j = 0
            i = min(i, len(node_names) - 1)
            while j <= i:
                try:
                    cls._destroy_storage_pool(lin, group_name, node_names[j])
                except Exception as e2:
                    logger('Failed to destroy resource group: {}'.format(e2))
                    pass
                j += 1
            raise e

        # 5. Return new instance.
        instance = cls.__new__(cls)
        instance._linstor = lin
        instance._logger = logger
        instance._redundancy = redundancy
        instance._group_name = group_name
        instance._volumes = set()
        instance._storage_pools_time = 0
        instance._kv_cache = instance._create_kv_cache()
        instance._resource_cache = None
        instance._resource_cache_dirty = True
        instance._volume_info_cache = None
        instance._volume_info_cache_dirty = True
        return instance

    @classmethod
    def build_device_path(cls, volume_name):
        """
        Build a device path given a volume name.
        :param str volume_name: The volume name to use.
        :return: A valid or not device path.
        :rtype: str
        """

        return '{}{}/0'.format(cls.DEV_ROOT_PATH, volume_name)

    @classmethod
    def build_volume_name(cls, base_name):
        """
        Build a volume name given a base name (i.e. a UUID).
        :param str volume_name: The volume name to use.
        :return: A valid or not device path.
        :rtype: str
        """
        return '{}{}'.format(cls.PREFIX_VOLUME, base_name)

    @classmethod
    def round_up_volume_size(cls, volume_size):
        """
        Align volume size on higher multiple of BLOCK_SIZE.
        :param int volume_size: The volume size to align.
        :return: An aligned volume size.
        :rtype: int
        """
        return round_up(volume_size, cls.BLOCK_SIZE)

    @classmethod
    def round_down_volume_size(cls, volume_size):
        """
        Align volume size on lower multiple of BLOCK_SIZE.
        :param int volume_size: The volume size to align.
        :return: An aligned volume size.
        :rtype: int
        """
        return round_down(volume_size, cls.BLOCK_SIZE)

    # --------------------------------------------------------------------------
    # Private helpers.
    # --------------------------------------------------------------------------

    def _create_kv_cache(self):
        self._kv_cache = self._create_linstor_kv('/')
        self._kv_cache_dirty = False
        return self._kv_cache

    def _get_kv_cache(self):
        if self._kv_cache_dirty:
            self._kv_cache = self._create_kv_cache()
        return self._kv_cache

    def _create_resource_cache(self):
        self._resource_cache = self._linstor.resource_list_raise()
        self._resource_cache_dirty = False
        return self._resource_cache

    def _get_resource_cache(self):
        if self._resource_cache_dirty:
            self._resource_cache = self._create_resource_cache()
        return self._resource_cache

    def _mark_resource_cache_as_dirty(self):
        self._resource_cache_dirty = True
        self._volume_info_cache_dirty = True

    # --------------------------------------------------------------------------

    def _ensure_volume_exists(self, volume_uuid):
        if volume_uuid not in self._volumes:
            raise LinstorVolumeManagerError(
                'volume `{}` doesn\'t exist'.format(volume_uuid),
                LinstorVolumeManagerError.ERR_VOLUME_NOT_EXISTS
            )

    def _find_best_size_candidates(self):
        result = self._linstor.resource_group_qmvs(self._group_name)
        error_str = self._get_error_str(result)
        if error_str:
            raise LinstorVolumeManagerError(
                'Failed to get max volume size allowed of SR `{}`: {}'.format(
                    self._group_name,
                    error_str
                )
            )
        return result[0].candidates

    def _fetch_resource_names(self):
        resource_names = set()
        dfns = self._linstor.resource_dfn_list_raise().resource_definitions
        for dfn in dfns:
            if dfn.resource_group_name == self._group_name and \
                    linstor.consts.FLAG_DELETE not in dfn.flags:
                resource_names.add(dfn.name)
        return resource_names

    def _get_volumes_info(self, volume_name=None):
        all_volume_info = {}

        if not self._volume_info_cache_dirty:
            return self._volume_info_cache

        for resource in self._get_resource_cache().resources:
            if resource.name not in all_volume_info:
                current = all_volume_info[resource.name] = self.VolumeInfo(
                    resource.name
                )
            else:
                current = all_volume_info[resource.name]

            for volume in resource.volumes:
                # We ignore diskless pools of the form "DfltDisklessStorPool".
                if volume.storage_pool_name == self._group_name:
                    if volume.allocated_size < 0:
                        raise LinstorVolumeManagerError(
                           'Failed to get allocated size of `{}` on `{}`'
                           .format(resource.name, volume.storage_pool_name)
                        )
                    allocated_size = volume.allocated_size

                    current.allocated_size = current.allocated_size and \
                        max(current.allocated_size, allocated_size) or \
                        allocated_size

                    if volume.usable_size < 0:
                        raise LinstorVolumeManagerError(
                           'Failed to get usable size of `{}` on `{}`'
                           .format(resource.name, volume.storage_pool_name)
                        )
                    virtual_size = volume.usable_size

                    current.virtual_size = current.virtual_size and \
                        min(current.virtual_size, virtual_size) or virtual_size

        for current in all_volume_info.values():
            current.allocated_size *= 1024
            current.virtual_size *= 1024

        self._volume_info_cache_dirty = False
        self._volume_info_cache = all_volume_info

        return all_volume_info

    def _get_volume_node_names_and_size(self, volume_name):
        node_names = set()
        size = -1
        for resource in self._linstor.resource_list_raise(
            filter_by_resources=[volume_name]
        ).resources:
            for volume in resource.volumes:
                # We ignore diskless pools of the form "DfltDisklessStorPool".
                if volume.storage_pool_name == self._group_name:
                    node_names.add(resource.node_name)

                    current_size = volume.usable_size
                    if current_size < 0:
                        raise LinstorVolumeManagerError(
                           'Failed to get usable size of `{}` on `{}`'
                           .format(resource.name, volume.storage_pool_name)
                        )

                    if size < 0:
                        size = current_size
                    else:
                        size = min(size, current_size)

        return (node_names, size * 1024)

    def _compute_size(self, attr):
        capacity = 0
        for pool in self._get_storage_pools(force=True):
            space = pool.free_space
            if space:
                size = getattr(space, attr)
                if size < 0:
                    raise LinstorVolumeManagerError(
                        'Failed to get pool {} attr of `{}`'
                        .format(attr, pool.node_name)
                    )
                capacity += size
        return capacity * 1024

    def _get_node_names(self):
        node_names = set()
        for pool in self._get_storage_pools():
            node_names.add(pool.node_name)
        return node_names

    def _get_storage_pools(self, force=False):
        cur_time = time.time()
        elsaped_time = cur_time - self._storage_pools_time

        if force or elsaped_time >= self.STORAGE_POOLS_FETCH_INTERVAL:
            self._storage_pools = self._linstor.storage_pool_list_raise(
                filter_by_stor_pools=[self._group_name]
            ).storage_pools
            self._storage_pools_time = time.time()

        return self._storage_pools

    def _create_volume(self, volume_uuid, volume_name, size, place_resources):
        size = self.round_up_volume_size(size)

        self._mark_resource_cache_as_dirty()
        self._check_volume_creation_errors(self._linstor.resource_group_spawn(
            rsc_grp_name=self._group_name,
            rsc_dfn_name=volume_name,
            vlm_sizes=['{}B'.format(size)],
            definitions_only=not place_resources
        ), volume_uuid, self._group_name)

    def _create_volume_with_properties(
        self, volume_uuid, volume_name, size, place_resources
    ):
        if self.check_volume_exists(volume_uuid):
            raise LinstorVolumeManagerError(
                'Could not create volume `{}` from SR `{}`, it already exists'
                .format(volume_uuid, self._group_name) + ' in properties',
                LinstorVolumeManagerError.ERR_VOLUME_EXISTS
            )

        if volume_name in self._fetch_resource_names():
            raise LinstorVolumeManagerError(
                'Could not create volume `{}` from SR `{}`, '.format(
                    volume_uuid, self._group_name
                ) + 'resource of the same name already exists in LINSTOR'
            )

        # I am paranoid.
        volume_properties = self._get_volume_properties(volume_uuid)
        if (volume_properties.get(self.PROP_NOT_EXISTS) is not None):
            raise LinstorVolumeManagerError(
                'Could not create volume `{}`, '.format(volume_uuid) +
                'properties already exist'
            )

        try:
            volume_properties[self.PROP_NOT_EXISTS] = self.STATE_CREATING
            volume_properties[self.PROP_VOLUME_NAME] = volume_name

            self._create_volume(
                volume_uuid, volume_name, size, place_resources
            )

            assert volume_properties.namespace == \
                self._build_volume_namespace(volume_uuid)
            return volume_properties
        except LinstorVolumeManagerError as e:
            # Do not destroy existing resource!
            # In theory we can't get this error because we check this event
            # before the `self._create_volume` case.
            # It can only happen if the same volume uuid is used in the same
            # call in another host.
            if e.code != LinstorVolumeManagerError.ERR_VOLUME_EXISTS:
                self._force_destroy_volume(volume_uuid)
            raise

    def _find_device_path(self, volume_uuid, volume_name):
        current_device_path = self._request_device_path(
            volume_uuid, volume_name, activate=True
        )

        # We use realpath here to get the /dev/drbd<id> path instead of
        # /dev/drbd/by-res/<resource_name>.
        expected_device_path = self.build_device_path(volume_name)
        util.wait_for_path(expected_device_path, 5)

        device_realpath = os.path.realpath(expected_device_path)
        if current_device_path != device_realpath:
            raise LinstorVolumeManagerError(
                'Invalid path, current={}, expected={} (realpath={})'
                .format(
                    current_device_path,
                    expected_device_path,
                    device_realpath
                )
            )
        return expected_device_path

    def _request_device_path(self, volume_uuid, volume_name, activate=False):
        node_name = socket.gethostname()

        resources = filter(
            lambda resource: resource.node_name == node_name and
            resource.name == volume_name,
            self._get_resource_cache().resources
        )

        if not resources:
            if activate:
                self._mark_resource_cache_as_dirty()
                self._activate_device_path(
                    self._linstor, node_name, volume_name
                )
                return self._request_device_path(volume_uuid, volume_name)
            raise LinstorVolumeManagerError(
                'Empty dev path for `{}`, but definition "seems" to exist'
                .format(volume_uuid)
            )
        # Contains a path of the /dev/drbd<id> form.
        return resources[0].volumes[0].device_path

    def _destroy_resource(self, resource_name):
        self._mark_resource_cache_as_dirty()
        result = self._linstor.resource_dfn_delete(resource_name)
        error_str = self._get_error_str(result)
        if error_str:
            raise LinstorVolumeManagerError(
                'Could not destroy resource `{}` from SR `{}`: {}'
                .format(resource_name, self._group_name, error_str)
            )

    def _destroy_volume(self, volume_uuid):
        volume_properties = self._get_volume_properties(volume_uuid)
        try:
            volume_name = volume_properties.get(self.PROP_VOLUME_NAME)
            if volume_name in self._fetch_resource_names():
                self._destroy_resource(volume_name)

            # Assume this call is atomic.
            volume_properties.clear()
        except Exception as e:
            raise LinstorVolumeManagerError(
                'Cannot destroy volume `{}`: {}'.format(volume_uuid, e)
            )

    def _force_destroy_volume(self, volume_uuid):
        try:
            self._destroy_volume(volume_uuid)
        except Exception as e:
            self._logger('Ignore fail: {}'.format(e))

    def _build_volumes(self, repair):
        properties = self._kv_cache
        resource_names = self._fetch_resource_names()

        self._volumes = set()

        updating_uuid_volumes = self._get_volumes_by_property(
            self.REG_UPDATING_UUID_SRC, ignore_inexisting_volumes=False
        )
        if updating_uuid_volumes and not repair:
            raise LinstorVolumeManagerError(
                'Cannot build LINSTOR volume list: '
                'It exists invalid "updating uuid volumes", repair is required'
            )

        existing_volumes = self._get_volumes_by_property(
            self.REG_NOT_EXISTS, ignore_inexisting_volumes=False
        )
        for volume_uuid, not_exists in existing_volumes.items():
            properties.namespace = self._build_volume_namespace(volume_uuid)

            src_uuid = properties.get(self.PROP_UPDATING_UUID_SRC)
            if src_uuid:
                self._logger(
                    'Ignoring volume during manager initialization with prop '
                    ' PROP_UPDATING_UUID_SRC: {} (properties={})'
                    .format(
                        volume_uuid,
                        self._get_filtered_properties(properties)
                    )
                )
                continue

            # Insert volume in list if the volume exists. Or if the volume
            # is being created and a slave wants to use it (repair = False).
            #
            # If we are on the master and if repair is True and state is
            # Creating, it's probably a bug or crash: the creation process has
            # been stopped.
            if not_exists == self.STATE_EXISTS or (
                not repair and not_exists == self.STATE_CREATING
            ):
                self._volumes.add(volume_uuid)
                continue

            if not repair:
                self._logger(
                    'Ignoring bad volume during manager initialization: {} '
                    '(properties={})'.format(
                        volume_uuid,
                        self._get_filtered_properties(properties)
                    )
                )
                continue

            # Remove bad volume.
            try:
                self._logger(
                    'Removing bad volume during manager initialization: {} '
                    '(properties={})'.format(
                        volume_uuid,
                        self._get_filtered_properties(properties)
                    )
                )
                volume_name = properties.get(self.PROP_VOLUME_NAME)

                # Little optimization, don't call `self._destroy_volume`,
                # we already have resource name list.
                if volume_name in resource_names:
                    self._destroy_resource(volume_name)

                # Assume this call is atomic.
                properties.clear()
            except Exception as e:
                # Do not raise, we don't want to block user action.
                self._logger(
                    'Cannot clean volume {}: {}'.format(volume_uuid, e)
                )

        for dest_uuid, src_uuid in updating_uuid_volumes.items():
            dest_namespace = self._build_volume_namespace(dest_uuid)

            properties.namespace = dest_namespace
            if int(properties.get(self.PROP_NOT_EXISTS)):
                properties.clear()
                continue

            properties.namespace = self._build_volume_namespace(src_uuid)
            properties.clear()

            properties.namespace = dest_namespace
            properties.pop(self.PROP_UPDATING_UUID_SRC)

            if src_uuid in self._volumes:
                self._volumes.remove(src_uuid)
            self._volumes.add(dest_uuid)

    def _get_sr_properties(self):
        return self._create_linstor_kv(self._build_sr_namespace())

    def _get_volumes_by_property(
        self, reg_prop, ignore_inexisting_volumes=True
    ):
        base_properties = self._get_kv_cache()
        base_properties.namespace = self._build_volume_namespace()

        volume_properties = {}
        for volume_uuid in self._volumes:
            volume_properties[volume_uuid] = ''

        for key, value in base_properties.items():
            res = reg_prop.match(key)
            if res:
                volume_uuid = res.groups()[0]
                if not ignore_inexisting_volumes or \
                        volume_uuid in self._volumes:
                    volume_properties[volume_uuid] = value

        return volume_properties

    def _create_linstor_kv(self, namespace):
        return linstor.KV(
            self._get_store_name(),
            uri=self._linstor.controller_host(),
            namespace=namespace
        )

    def _get_volume_properties(self, volume_uuid):
        properties = self._get_kv_cache()
        properties.namespace = self._build_volume_namespace(volume_uuid)
        return properties

    def _get_store_name(self):
        return 'xcp-sr-{}'.format(self._group_name)

    @classmethod
    def _build_sr_namespace(cls):
        return '/{}/'.format(cls.NAMESPACE_SR)

    @classmethod
    def _build_volume_namespace(cls, volume_uuid=None):
        # Return a path to all volumes if `volume_uuid` is not given.
        if volume_uuid is None:
            return '/{}/'.format(cls.NAMESPACE_VOLUME)
        return '/{}/{}/'.format(cls.NAMESPACE_VOLUME, volume_uuid)

    @classmethod
    def _get_error_str(cls, result):
        return ', '.join([
            err.message for err in cls._filter_errors(result)
        ])

    @classmethod
    def _create_linstor_instance(cls, uri, keep_uri_unmodified=False):
        retry = False

        def connect(uri):
            if not uri:
                uri = get_controller_uri()
                if not uri:
                    raise LinstorVolumeManagerError(
                        'Unable to find controller uri...'
                    )
            instance = linstor.Linstor(uri, keep_alive=True)
            instance.connect()
            return instance

        try:
            return connect(uri)
        except (linstor.errors.LinstorNetworkError, LinstorVolumeManagerError):
            pass

        if not keep_uri_unmodified:
            uri = None

        return util.retry(
            lambda: connect(uri),
            maxretry=10,
            exceptions=[
                linstor.errors.LinstorNetworkError,
                LinstorVolumeManagerError
            ]
        )

    @classmethod
    def _activate_device_path(cls, lin, node_name, volume_name):
        result = lin.resource_create([
            linstor.ResourceData(node_name, volume_name, diskless=True)
        ])
        if linstor.Linstor.all_api_responses_no_error(result):
            return
        errors = linstor.Linstor.filter_api_call_response_errors(result)
        if len(errors) == 1 and errors[0].is_error(
            linstor.consts.FAIL_EXISTS_RSC
        ):
            return

        raise LinstorVolumeManagerError(
            'Unable to activate device path of `{}` on node `{}`: {}'
            .format(volume_name, node_name, ', '.join(
                [str(x) for x in result]))
            )

    @classmethod
    def _request_database_path(cls, lin, activate=False):
        node_name = socket.gethostname()

        try:
            resources = filter(
                lambda resource: resource.node_name == node_name and
                resource.name == DATABASE_VOLUME_NAME,
                lin.resource_list_raise().resources
            )
        except Exception as e:
            raise LinstorVolumeManagerError(
                'Unable to get resources during database creation: {}'
                .format(e)
            )

        if not resources:
            if activate:
                cls._activate_device_path(
                    lin, node_name, DATABASE_VOLUME_NAME
                )
                return cls._request_database_path(
                    DATABASE_VOLUME_NAME, DATABASE_VOLUME_NAME
                )
            raise LinstorVolumeManagerError(
                'Empty dev path for `{}`, but definition "seems" to exist'
                .format(DATABASE_PATH)
            )
        # Contains a path of the /dev/drbd<id> form.
        return resources[0].volumes[0].device_path

    @classmethod
    def _create_database_volume(cls, lin, group_name):
        try:
            dfns = lin.resource_dfn_list_raise().resource_definitions
        except Exception as e:
            raise LinstorVolumeManagerError(
                'Unable to get definitions during database creation: {}'
                .format(e)
            )

        if dfns:
            raise LinstorVolumeManagerError(
                'Could not create volume `{}` from SR `{}`, '.format(
                    DATABASE_VOLUME_NAME, group_name
                ) + 'LINSTOR volume list must be empty.'
            )

        size = cls.round_up_volume_size(DATABASE_SIZE)
        cls._check_volume_creation_errors(lin.resource_group_spawn(
            rsc_grp_name=group_name,
            rsc_dfn_name=DATABASE_VOLUME_NAME,
            vlm_sizes=['{}B'.format(size)],
            definitions_only=False
        ), DATABASE_VOLUME_NAME, group_name)

        # We must modify the quorum. Otherwise we can't use correctly the
        # minidrbdcluster daemon.
        result = lin.resource_dfn_modify(DATABASE_VOLUME_NAME, {
            'DrbdOptions/auto-quorum': 'disabled',
            'DrbdOptions/Resource/quorum': 'majority'
        })
        error_str = cls._get_error_str(result)
        if error_str:
            raise LinstorVolumeManagerError(
                'Could not activate quorum on database volume: {}'
                .format(error_str)
            )

        current_device_path = cls._request_database_path(lin, activate=True)

        # We use realpath here to get the /dev/drbd<id> path instead of
        # /dev/drbd/by-res/<resource_name>.
        expected_device_path = cls.build_device_path(DATABASE_VOLUME_NAME)
        util.wait_for_path(expected_device_path, 5)

        device_realpath = os.path.realpath(expected_device_path)
        if current_device_path != device_realpath:
            raise LinstorVolumeManagerError(
                'Invalid path, current={}, expected={} (realpath={})'
                .format(
                    current_device_path,
                    expected_device_path,
                    device_realpath
                )
            )

        try:
            util.pread2([DATABASE_MKFS, expected_device_path])
        except Exception as e:
            raise LinstorVolumeManagerError(
               'Failed to execute {} on database volume: {}'
               .format(DATABASE_MKFS, e)
            )

        return expected_device_path

    @classmethod
    def _destroy_database_volume(cls, lin, group_name):
        error_str = cls._get_error_str(
            lin.resource_dfn_delete(DATABASE_VOLUME_NAME)
        )
        if error_str:
            raise LinstorVolumeManagerError(
                'Could not destroy resource `{}` from SR `{}`: {}'
                .format(DATABASE_VOLUME_NAME, group_name, error_str)
            )

    @classmethod
    def _mount_database_volume(cls, volume_path, mount=True, force=False):
        backup_path = DATABASE_PATH + '-' + str(uuid.uuid4())

        try:
            # 1. Create a backup config folder.
            database_not_empty = bool(os.listdir(DATABASE_PATH))
            if database_not_empty:
                try:
                    os.mkdir(backup_path)
                except Exception as e:
                    raise LinstorVolumeManagerError(
                        'Failed to create backup path {} of LINSTOR config: {}'
                        .format(backup_path, e)
                    )

            # 2. Move the config in the mounted volume.
            if database_not_empty:
                cls._move_files(DATABASE_PATH, backup_path)

            cls._mount_volume(volume_path, DATABASE_PATH, mount)

            if database_not_empty:
                cls._move_files(backup_path, DATABASE_PATH, force)

                # 3. Remove useless backup directory.
                try:
                    os.rmdir(backup_path)
                except Exception:
                    raise LinstorVolumeManagerError(
                        'Failed to remove backup path {} of LINSTOR config {}'
                        .format(backup_path, e)
                    )
        except Exception as e:
            def force_exec(fn):
                try:
                    fn()
                except Exception:
                    pass

            if mount == cls._is_mounted(DATABASE_PATH):
                force_exec(lambda: cls._move_files(
                    DATABASE_PATH, backup_path
                ))
                force_exec(lambda: cls._mount_volume(
                    volume_path, DATABASE_PATH, not mount
                ))

            if mount != cls._is_mounted(DATABASE_PATH):
                force_exec(lambda: cls._move_files(
                    backup_path, DATABASE_PATH
                ))

            force_exec(lambda: os.rmdir(backup_path))
            raise e

    @classmethod
    def _force_destroy_database_volume(cls, lin, group_name):
        try:
            cls._destroy_database_volume(lin, group_name)
        except Exception:
            pass

    @classmethod
    def _destroy_storage_pool(cls, lin, group_name, node_name):
        def destroy():
            result = lin.storage_pool_delete(node_name, group_name)
            errors = cls._filter_errors(result)
            if cls._check_errors(errors, [
                linstor.consts.FAIL_NOT_FOUND_STOR_POOL,
                linstor.consts.FAIL_NOT_FOUND_STOR_POOL_DFN
            ]):
                return

            if errors:
                raise LinstorVolumeManagerError(
                    'Failed to destroy SP `{}` on node `{}`: {}'.format(
                        group_name,
                        node_name,
                        cls._get_error_str(errors)
                    )
                )

        # We must retry to avoid errors like:
        # "can not be deleted as volumes / snapshot-volumes are still using it"
        # after LINSTOR database volume destruction.
        return util.retry(destroy, maxretry=10)

    @classmethod
    def _destroy_resource_group(cls, lin, group_name):
        def destroy():
            result = lin.resource_group_delete(group_name)
            errors = cls._filter_errors(result)
            if cls._check_errors(errors, [
                linstor.consts.FAIL_NOT_FOUND_RSC_GRP
            ]):
                return

            if errors:
                raise LinstorVolumeManagerError(
                    'Failed to destroy RG `{}`: {}'
                    .format(group_name, cls._get_error_str(errors))
                )

        return util.retry(destroy, maxretry=10)

    @classmethod
    def _build_group_name(cls, base_name):
        # If thin provisioning is used we have a path like this:
        # `VG/LV`. "/" is not accepted by LINSTOR.
        return '{}{}'.format(cls.PREFIX_SR, base_name.replace('/', '_'))

    @classmethod
    def _check_volume_creation_errors(cls, result, volume_uuid, group_name):
        errors = cls._filter_errors(result)
        if cls._check_errors(errors, [
            linstor.consts.FAIL_EXISTS_RSC, linstor.consts.FAIL_EXISTS_RSC_DFN
        ]):
            raise LinstorVolumeManagerError(
                'Failed to create volume `{}` from SR `{}`, it already exists'
                .format(volume_uuid, group_name),
                LinstorVolumeManagerError.ERR_VOLUME_EXISTS
            )

        if errors:
            raise LinstorVolumeManagerError(
                'Failed to create volume `{}` from SR `{}`: {}'.format(
                    volume_uuid,
                    group_name,
                    cls._get_error_str(errors)
                )
            )

    @classmethod
    def _move_files(cls, src_dir, dest_dir, force=False):
        def listdir(dir):
            ignored = ['lost+found']
            return filter(lambda file: file not in ignored, os.listdir(dir))

        try:
            if not force:
                files = listdir(dest_dir)
                if files:
                    raise LinstorVolumeManagerError(
                        'Cannot move files from {} to {} because destination '
                        'contains: {}'.format(src_dir, dest_dir, files)
                    )
        except LinstorVolumeManagerError:
            raise
        except Exception as e:
            raise LinstorVolumeManagerError(
                'Cannot list dir {}: {}'.format(dest_dir, e)
            )

        try:
            for file in listdir(src_dir):
                try:
                    dest_file = os.path.join(dest_dir, file)
                    if not force and os.path.exists(dest_file):
                        raise LinstorVolumeManagerError(
                            'Cannot move {} because it already exists in the '
                            'destination'.format(file)
                        )
                    shutil.move(os.path.join(src_dir, file), dest_file)
                except LinstorVolumeManagerError:
                    raise
                except Exception as e:
                    raise LinstorVolumeManagerError(
                        'Cannot move {}: {}'.format(file, e)
                    )
        except Exception as e:
            if not force:
                try:
                    cls._move_files(dest_dir, src_dir, force=True)
                except Exception:
                    pass

            raise LinstorVolumeManagerError(
                'Failed to move files from {} to {}: {}'.format(
                    src_dir, dest_dir, e
                )
            )

    @staticmethod
    def _get_filtered_properties(properties):
        return dict(properties.items())

    @staticmethod
    def _filter_errors(result):
        return [
            err for err in result
            if hasattr(err, 'is_error') and err.is_error()
        ]

    @staticmethod
    def _check_errors(result, codes):
        for err in result:
            for code in codes:
                if err.is_error(code):
                    return True
        return False

    @classmethod
    def _start_controller(cls, start=True):
        return cls._start_service('linstor-controller', start)

    @staticmethod
    def _start_service(name, start=True):
        action = 'start' if start else 'stop'
        (ret, out, err) = util.doexec([
            'systemctl', action, name
        ])
        if ret != 0:
            raise LinstorVolumeManagerError(
                'Failed to {} {}: {} {}'
                .format(action, name, out, err)
            )

    @staticmethod
    def _is_mounted(mountpoint):
        (ret, out, err) = util.doexec(['mountpoint', '-q', mountpoint])
        return ret == 0

    @classmethod
    def _mount_volume(cls, volume_path, mountpoint, mount=True):
        if mount:
            try:
                util.pread(['mount', volume_path, mountpoint])
            except Exception as e:
                raise LinstorVolumeManagerError(
                    'Failed to mount volume {} on {}: {}'
                    .format(volume_path, mountpoint, e)
                )
        else:
            try:
                if cls._is_mounted(mountpoint):
                    util.pread(['umount', mountpoint])
            except Exception as e:
                raise LinstorVolumeManagerError(
                    'Failed to umount volume {} on {}: {}'
                    .format(volume_path, mountpoint, e)
                )
