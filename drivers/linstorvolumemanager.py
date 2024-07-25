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


import distutils.util
import errno
import json
import linstor
import os.path
import re
import shutil
import socket
import stat
import time
import util
import uuid

# Persistent prefix to add to RAW persistent volumes.
PERSISTENT_PREFIX = 'xcp-persistent-'

# Contains the data of the "/var/lib/linstor" directory.
DATABASE_VOLUME_NAME = PERSISTENT_PREFIX + 'database'
DATABASE_SIZE = 1 << 30  # 1GB.
DATABASE_PATH = '/var/lib/linstor'
DATABASE_MKFS = 'mkfs.ext4'

REG_DRBDADM_PRIMARY = re.compile("([^\\s]+)\\s+role:Primary")
REG_DRBDSETUP_IP = re.compile('[^\\s]+\\s+(.*):.*$')

DRBD_BY_RES_PATH = '/dev/drbd/by-res/'

PLUGIN = 'linstor-manager'


# ==============================================================================

def get_local_volume_openers(resource_name, volume):
    if not resource_name or volume is None:
        raise Exception('Cannot get DRBD openers without resource name and/or volume.')

    path = '/sys/kernel/debug/drbd/resources/{}/volumes/{}/openers'.format(
        resource_name, volume
    )

    with open(path, 'r') as openers:
        # Not a big cost, so read all lines directly.
        lines = openers.readlines()

    result = {}

    opener_re = re.compile('(.*)\\s+([0-9]+)\\s+([0-9]+)')
    for line in lines:
        match = opener_re.match(line)
        assert match

        groups = match.groups()
        process_name = groups[0]
        pid = groups[1]
        open_duration_ms = groups[2]
        result[pid] = {
            'process-name': process_name,
            'open-duration': open_duration_ms
        }

    return json.dumps(result)

def get_all_volume_openers(resource_name, volume):
    PLUGIN_CMD = 'getDrbdOpeners'

    volume = str(volume)
    openers = {}

    # Make sure this call never stucks because this function can be called
    # during HA init and in this case we can wait forever.
    session = util.timeout_call(10, util.get_localAPI_session)

    hosts = session.xenapi.host.get_all_records()
    for host_ref, host_record in hosts.items():
        node_name = host_record['hostname']
        try:
            if not session.xenapi.host_metrics.get_record(
                host_record['metrics']
            )['live']:
                # Ensure we call plugin on online hosts only.
                continue

            openers[node_name] = json.loads(
                session.xenapi.host.call_plugin(host_ref, PLUGIN, PLUGIN_CMD, {
                    'resourceName': resource_name,
                    'volume': volume
                })
            )
        except Exception as e:
            util.SMlog('Failed to get openers of `{}` on `{}`: {}'.format(
                resource_name, node_name, e
            ))

    return openers


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
    PLUGIN_CMD = 'hasControllerRunning'

    # Try to find controller using drbdadm.
    (ret, stdout, stderr) = util.doexec([
        'drbdadm', 'status', DATABASE_VOLUME_NAME
    ])
    if ret == 0:
        # If we are here, the database device exists locally.

        if stdout.startswith('{} role:Primary'.format(DATABASE_VOLUME_NAME)):
            # Nice case, we have the controller running on this local host.
            return 'linstor://localhost'

        # Try to find the host using DRBD connections.
        res = REG_DRBDADM_PRIMARY.search(stdout)
        if res:
            node_name = res.groups()[0]
            ip = get_remote_host_ip(node_name)
            if ip:
                return 'linstor://' + ip

    # Worst case: we use many hosts in the pool (>= 4), so we can't find the
    # primary using drbdadm because we don't have all connections to the
    # replicated volume. `drbdadm status xcp-persistent-database` returns
    # 3 connections by default.
    try:
        session = util.timeout_call(10, util.get_localAPI_session)

        for host_ref, host_record in session.xenapi.host.get_all_records().items():
            node_name = host_record['hostname']
            try:
                if distutils.util.strtobool(
                    session.xenapi.host.call_plugin(host_ref, PLUGIN, PLUGIN_CMD, {})
                ):
                    return 'linstor://' + host_record['address']
            except Exception as e:
                # Can throw and exception if a host is offline. So catch it.
                util.SMlog('Unable to search controller on `{}`: {}'.format(
                    node_name, e
                ))
    except:
        # Not found, maybe we are trying to create the SR...
        pass

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
    PLUGIN_CMD = 'hasControllerRunning'

    (ret, stdout, stderr) = util.doexec([
        'drbdadm', 'status', DATABASE_VOLUME_NAME
    ])

    if ret == 0:
        if stdout.startswith('{} role:Primary'.format(DATABASE_VOLUME_NAME)):
            return 'localhost'

        res = REG_DRBDADM_PRIMARY.search(stdout)
        if res:
            return res.groups()[0]

    session = util.timeout_call(5, util.get_localAPI_session)

    for host_ref, host_record in session.xenapi.host.get_all_records().items():
        node_name = host_record['hostname']
        try:
            if not session.xenapi.host_metrics.get_record(
                host_record['metrics']
            )['live']:
                continue

            if distutils.util.strtobool(session.xenapi.host.call_plugin(
                host_ref, PLUGIN, PLUGIN_CMD, {}
            )):
                return node_name
        except Exception as e:
            util.SMlog('Failed to call plugin to get controller on `{}`: {}'.format(
                node_name, e
            ))


def demote_drbd_resource(node_name, resource_name):
    PLUGIN_CMD = 'demoteDrbdResource'

    session = util.timeout_call(5, util.get_localAPI_session)

    for host_ref, host_record in session.xenapi.host.get_all_records().items():
        if host_record['hostname'] != node_name:
            continue

        try:
            session.xenapi.host.call_plugin(
                host_ref, PLUGIN, PLUGIN_CMD, {'resource_name': resource_name}
            )
        except Exception as e:
            util.SMlog('Failed to demote resource `{}` on `{}`: {}'.format(
                resource_name, node_name, e
            ))
    raise Exception(
        'Can\'t demote resource `{}`, unable to find node `{}`'
        .format(resource_name, node_name)
    )

# ==============================================================================

class LinstorVolumeManagerError(Exception):
    ERR_GENERIC = 0,
    ERR_VOLUME_EXISTS = 1,
    ERR_VOLUME_NOT_EXISTS = 2,
    ERR_VOLUME_DESTROY = 3,
    ERR_GROUP_NOT_EXISTS = 4

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
        '_linstor', '_logger', '_redundancy',
        '_base_group_name', '_group_name', '_ha_group_name',
        '_volumes', '_storage_pools', '_storage_pools_time',
        '_kv_cache', '_resource_cache', '_volume_info_cache',
        '_kv_cache_dirty', '_resource_cache_dirty', '_volume_info_cache_dirty'
    )

    DEV_ROOT_PATH = DRBD_BY_RES_PATH

    # Default sector size.
    BLOCK_SIZE = 512

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
    NAMESPACE_VOLUME = 'xcp/volume'

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
    PREFIX_HA = 'xcp-ha-'
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
            'virtual_size',    # Total virtual available size of this volume
                               # (i.e. the user size at creation).
            'diskful'          # Array of nodes that have a diskful volume.
        )

        def __init__(self, name):
            self.name = name
            self.allocated_size = 0
            self.virtual_size = 0
            self.diskful = []

        def __repr__(self):
            return 'VolumeInfo("{}", {}, {}, {})'.format(
                self.name, self.allocated_size, self.virtual_size,
                self.diskful
            )

    # --------------------------------------------------------------------------

    def __init__(
        self, uri, group_name, repair=False, logger=default_logger.__func__,
        attempt_count=30
    ):
        """
        Create a new LinstorVolumeManager object.
        :param str uri: URI to communicate with the LINSTOR controller.
        :param str group_name: The SR goup name to use.
        :param bool repair: If true we try to remove bad volumes due to a crash
        or unexpected behavior.
        :param function logger: Function to log messages.
        :param int attempt_count: Number of attempts to join the controller.
        """

        self._linstor = self._create_linstor_instance(
            uri, attempt_count=attempt_count
        )
        self._base_group_name = group_name

        # Ensure group exists.
        group_name = self._build_group_name(group_name)
        groups = self._linstor.resource_group_list_raise([group_name]).resource_groups
        if not groups:
            raise LinstorVolumeManagerError(
                'Unable to find `{}` Linstor SR'.format(group_name)
            )

        # Ok. ;)
        self._logger = logger
        self._redundancy = groups[0].select_filter.place_count
        self._group_name = group_name
        self._ha_group_name = self._build_ha_group_name(self._base_group_name)
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
    def redundancy(self):
        """
        Give the used redundancy.
        :return: The redundancy.
        :rtype: int
        """
        return self._redundancy

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
    def allocated_volume_size(self):
        """
        Give the allocated size for all volumes. The place count is not
        used here. When thick lvm is used, the size for one volume should
        be equal to the virtual volume size. With thin lvm, the size is equal
        or lower to the volume size.
        :return: The allocated size of all volumes.
        :rtype: int
        """

        # Paths: /res_name/vol_number/size
        sizes = {}

        for resource in self._get_resource_cache().resources:
            if resource.name not in sizes:
                current = sizes[resource.name] = {}
            else:
                current = sizes[resource.name]

            for volume in resource.volumes:
                # We ignore diskless pools of the form "DfltDisklessStorPool".
                if volume.storage_pool_name != self._group_name:
                    continue

                current_size = volume.allocated_size
                if current_size < 0:
                    raise LinstorVolumeManagerError(
                       'Failed to get allocated size of `{}` on `{}`'
                       .format(resource.name, volume.storage_pool_name)
                    )
                current[volume.number] = max(current_size, current.get(volume.number) or 0)

        total_size = 0
        for volumes in sizes.itervalues():
            for size in volumes.itervalues():
                total_size += size

        return total_size * 1024

    def get_min_physical_size(self):
        """
        Give the minimum physical size of the SR.
        I.e. the size of the smallest disk + the number of pools.
        :return: The physical min size.
        :rtype: tuple(int, int)
        """
        size = None
        pool_count = 0
        for pool in self._get_storage_pools(force=True):
            space = pool.free_space
            if space:
                pool_count += 1
                current_size = space.total_capacity
                if current_size < 0:
                    raise LinstorVolumeManagerError(
                        'Failed to get pool total_capacity attr of `{}`'
                        .format(pool.node_name)
                    )
                if size is None or current_size < size:
                    size = current_size
        return (pool_count, (size or 0) * 1024)

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
        self,
        volume_uuid,
        size,
        persistent=True,
        volume_name=None,
        high_availability=False
    ):
        """
        Create a new volume on the SR.
        :param str volume_uuid: The volume uuid to use.
        :param int size: volume size in B.
        :param bool persistent: If false the volume will be unavailable
        on the next constructor call LinstorSR(...).
        :param str volume_name: If set, this name is used in the LINSTOR
        database instead of a generated name.
        :param bool high_availability: If set, the volume is created in
        the HA group.
        :return: The current device path of the volume.
        :rtype: str
        """

        self._logger('Creating LINSTOR volume {}...'.format(volume_uuid))
        if not volume_name:
            volume_name = self.build_volume_name(util.gen_uuid())
        volume_properties = self._create_volume_with_properties(
            volume_uuid,
            volume_name,
            size,
            True,  # place_resources
            high_availability
        )

        # Volume created! Now try to find the device path.
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
            # There is an issue to find the path.
            # At this point the volume has just been created, so force flag can be used.
            self._destroy_volume(volume_uuid, force=True)
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

        try:
            self._volumes.remove(volume_uuid)
            self._destroy_volume(volume_uuid)
        except Exception as e:
            raise LinstorVolumeManagerError(
                str(e),
                LinstorVolumeManagerError.ERR_VOLUME_DESTROY
            )

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

    def remove_volume_if_diskless(self, volume_uuid):
        """
        Remove disless path from local node.
        :param str volume_uuid: The volume uuid to remove.
        """

        self._ensure_volume_exists(volume_uuid)

        volume_properties = self._get_volume_properties(volume_uuid)
        volume_name = volume_properties.get(self.PROP_VOLUME_NAME)

        node_name = socket.gethostname()

        for resource in self._get_resource_cache().resources:
            if resource.name == volume_name and resource.node_name == node_name:
                if linstor.consts.FLAG_TIE_BREAKER in resource.flags:
                    return
                break

        result = self._linstor.resource_delete_if_diskless(
            node_name=node_name, rsc_name=volume_name
        )
        if not linstor.Linstor.all_api_responses_no_error(result):
            raise LinstorVolumeManagerError(
                'Unable to delete diskless path of `{}` on node `{}`: {}'
                .format(volume_name, node_name, ', '.join(
                    [str(x) for x in result]))
                )

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
        new_size = self.round_up_volume_size(new_size) / 1024

        retry_count = 30
        while True:
            result = self._linstor.volume_dfn_modify(
                rsc_name=volume_name,
                volume_nr=0,
                size=new_size
            )

            self._mark_resource_cache_as_dirty()

            error_str = self._get_error_str(result)
            if not error_str:
                break

            # After volume creation, DRBD volume can be unusable during many seconds.
            # So we must retry the definition change if the device is not up to date.
            # Often the case for thick provisioning.
            if retry_count and error_str.find('non-UpToDate DRBD device') >= 0:
                time.sleep(2)
                retry_count -= 1
                continue

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

    def set_auto_promote_timeout(self, volume_uuid, timeout):
        """
        Define the blocking time of open calls when a DRBD
        is already open on another host.
        :param str volume_uuid: The volume uuid to modify.
        """

        volume_name = self.get_volume_name(volume_uuid)
        result = self._linstor.resource_dfn_modify(volume_name, {
            'DrbdOptions/Resource/auto-promote-timeout': timeout
        })
        error_str = self._get_error_str(result)
        if error_str:
            raise LinstorVolumeManagerError(
                'Could not change the auto promote timeout of `{}`: {}'
                .format(volume_uuid, error_str)
            )

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
        Get the dev path of a volume, create a diskless if necessary.
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
        Get the volume name of a device_path.
        :param str device_path: The dev path to find the volume name.
        :return: The volume name of the device path.
        :rtype: str
        """

        # Assume that we have a path like this:
        # - "/dev/drbd/by-res/xcp-volume-<UUID>/0"
        # - "../xcp-volume-<UUID>/0"
        if device_path.startswith(DRBD_BY_RES_PATH):
            prefix_len = len(DRBD_BY_RES_PATH)
        else:
            assert device_path.startswith('../')
            prefix_len = 3

        res_name_end = device_path.find('/', prefix_len)
        assert res_name_end != -1
        return device_path[prefix_len:res_name_end]

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

        self._logger(
            'Trying to update volume UUID {} to {}...'
            .format(volume_uuid, new_volume_uuid)
        )
        assert volume_uuid != new_volume_uuid, 'can\'t update volume UUID, same value'

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
            # Note: On new volumes, during clone for example, the metadata
            # may be missing. So we must test it to avoid this error:
            # "None has to be a str/unicode, but is <type 'NoneType'>"
            if metadata:
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

    def get_volume_openers(self, volume_uuid):
        """
        Get openers of a volume.
        :param str volume_uuid: The volume uuid to monitor.
        :return: A dictionnary that contains openers.
        :rtype: dict(str, obj)
        """
        return get_all_volume_openers(self.get_volume_name(volume_uuid), '0')

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
        with the same size.
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

        # 2. Create clone!
        return self.create_volume(clone_uuid, size, persistent)

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
                # Don't force, we can be sure of what's happening.
                self.destroy_volume(volume_uuid)

    def destroy(self):
        """
        Destroy this SR. Object should not be used after that.
        :param bool force: Try to destroy volumes before if true.
        """

        # 1. Ensure volume list is empty. No cost.
        if self._volumes:
            raise LinstorVolumeManagerError(
                'Cannot destroy LINSTOR volume manager: '
                'It exists remaining volumes'
            )

        # 2. Fetch ALL resource names.
        # This list may therefore contain volumes created outside
        # the scope of the driver.
        resource_names = self._fetch_resource_names(ignore_deleted=False)
        try:
            resource_names.remove(DATABASE_VOLUME_NAME)
        except KeyError:
            # Really strange to reach that point.
            # Normally we always have the database volume in the list.
            pass

        # 3. Ensure the resource name list is entirely empty...
        if resource_names:
            raise LinstorVolumeManagerError(
                'Cannot destroy LINSTOR volume manager: '
                'It exists remaining volumes (created externally or being deleted)'
            )

        # 4. Destroying...
        controller_is_running = self._controller_is_running()
        uri = 'linstor://localhost'
        try:
            if controller_is_running:
                self._start_controller(start=False)

            # 4.1. Umount LINSTOR database.
            self._mount_database_volume(
                self.build_device_path(DATABASE_VOLUME_NAME),
                mount=False,
                force=True
            )

            # 4.2. Refresh instance.
            self._start_controller(start=True)
            self._linstor = self._create_linstor_instance(
                uri, keep_uri_unmodified=True
            )

            # 4.3. Destroy database volume.
            self._destroy_resource(DATABASE_VOLUME_NAME)

            # 4.4. Refresh linstor connection.
            # Without we get this error:
            # "Cannot delete resource group 'xcp-sr-linstor_group_thin_device' because it has existing resource definitions.."
            # Because the deletion of the databse was not seen by Linstor for some reason.
            # It seems a simple refresh of the Linstor connection make it aware of the deletion.
            self._linstor.disconnect()
            self._linstor.connect()

            # 4.5. Destroy remaining drbd nodes on hosts.
            # We check if there is a DRBD node on hosts that could mean blocking when destroying resource groups.
            # It needs to be done locally by each host so we go through the linstor-manager plugin.
            # If we don't do this sometimes, the destroy will fail when trying to destroy the resource groups with:
            # "linstor-manager:destroy error: Failed to destroy SP `xcp-sr-linstor_group_thin_device` on node `r620-s2`: The specified storage pool 'xcp-sr-linstor_group_thin_device' on node 'r620-s2' can not be deleted as volumes / snapshot-volumes are still using it."
            session = util.timeout_call(5, util.get_localAPI_session)
            for host_ref in session.xenapi.host.get_all():
                try:
                    response = session.xenapi.host.call_plugin(
                        host_ref, 'linstor-manager', 'destroyDrbdVolumes', {'volume_group': self._group_name}
                    )
                except Exception as e:
                    util.SMlog('Calling destroyDrbdVolumes on host {} failed with error {}'.format(host_ref, e))

            # 4.6. Destroy group and storage pools.
            self._destroy_resource_group(self._linstor, self._group_name)
            self._destroy_resource_group(self._linstor, self._ha_group_name)
            for pool in self._get_storage_pools(force=True):
                self._destroy_storage_pool(
                    self._linstor, pool.name, pool.node_name
                )
        except Exception as e:
            self._start_controller(start=controller_is_running)
            raise e

        try:
            self._start_controller(start=False)
            for file in os.listdir(DATABASE_PATH):
                if file != 'lost+found':
                    os.remove(DATABASE_PATH + '/' + file)
        except Exception as e:
            util.SMlog(
                'Ignoring failure after LINSTOR SR destruction: {}'
                .format(e)
            )

    def find_up_to_date_diskful_nodes(self, volume_uuid):
        """
        Find all nodes that contain a specific volume using diskful disks.
        The disk must be up to data to be used.
        :param str volume_uuid: The volume to use.
        :return: The available nodes.
        :rtype: tuple(set(str), str)
        """

        volume_name = self.get_volume_name(volume_uuid)

        in_use_by = None
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
                in_use_by = resource_state.node_name

        return (node_names, in_use_by)

    def get_primary(self, volume_uuid):
        """
        Find the node that opened a volume, i.e. the primary.
        :rtype: str
        """
        volume_name = self.get_volume_name(volume_uuid)

        resource_states = filter(
            lambda resource_state: resource_state.name == volume_name,
            self._get_resource_cache().resource_states
        )

        for resource_state in resource_states:
            if resource_state.in_use:
                return resource_state.node_name

        return None

    def invalidate_resource_cache(self):
        """
        If resources are impacted by external commands like vhdutil,
        it's necessary to call this function to invalidate current resource
        cache.
        """
        self._mark_resource_cache_as_dirty()

    def has_node(self, node_name):
        """
        Check if a node exists in the LINSTOR database.
        :rtype: bool
        """
        result = self._linstor.node_list()
        error_str = self._get_error_str(result)
        if error_str:
            raise LinstorVolumeManagerError(
                'Failed to list nodes using `{}`: {}'
                .format(node_name, error_str)
            )
        return bool(result[0].node(node_name))

    def create_node(self, node_name, ip):
        """
        Create a new node in the LINSTOR database.
        :param str node_name: Node name to use.
        :param str ip: Host IP to communicate.
        """
        result = self._linstor.node_create(
            node_name,
            linstor.consts.VAL_NODE_TYPE_CMBD,
            ip
        )
        errors = self._filter_errors(result)
        if errors:
            error_str = self._get_error_str(errors)
            raise LinstorVolumeManagerError(
                'Failed to create node `{}`: {}'.format(node_name, error_str)
            )

    def destroy_node(self, node_name):
        """
        Destroy a node in the LINSTOR database.
        :param str node_name: Node name to remove.
        """
        result = self._linstor.node_delete(node_name)
        errors = self._filter_errors(result)
        if errors:
            error_str = self._get_error_str(errors)
            raise LinstorVolumeManagerError(
                'Failed to destroy node `{}`: {}'.format(node_name, error_str)
            )

    def create_node_interface(self, node_name, name, ip):
        """
        Create a new node interface in the LINSTOR database.
        :param str node_name: Node name of the interface to use.
        :param str name: Interface to create.
        :param str ip: IP of the interface.
        """
        result = self._linstor.netinterface_create(node_name, name, ip)
        errors = self._filter_errors(result)
        if errors:
            error_str = self._get_error_str(errors)
            raise LinstorVolumeManagerError(
                'Failed to create node interface on `{}`: {}'.format(node_name, error_str)
            )

    def destroy_node_interface(self, node_name, name):
        """
        Destroy a node interface in the LINSTOR database.
        :param str node_name: Node name of the interface to remove.
        :param str name: Interface to remove.
        """

        if name == 'default':
            raise LinstorVolumeManagerError(
                'Unable to delete the default interface of a node!'
            )

        result = self._linstor.netinterface_delete(node_name, name)
        errors = self._filter_errors(result)
        if errors:
            error_str = self._get_error_str(errors)
            raise LinstorVolumeManagerError(
                'Failed to destroy node interface on `{}`: {}'.format(node_name, error_str)
            )

    def modify_node_interface(self, node_name, name, ip):
        """
        Modify a node interface in the LINSTOR database. Create it if necessary.
        :param str node_name: Node name of the interface to use.
        :param str name: Interface to modify or create.
        :param str ip: IP of the interface.
        """
        result = self._linstor.netinterface_create(node_name, name, ip)
        errors = self._filter_errors(result)
        if not errors:
            return

        if self._check_errors(errors, [linstor.consts.FAIL_EXISTS_NET_IF]):
            result = self._linstor.netinterface_modify(node_name, name, ip)
            errors = self._filter_errors(result)
            if not errors:
                return

        error_str = self._get_error_str(errors)
        raise LinstorVolumeManagerError(
            'Unable to modify interface on `{}`: {}'.format(node_name, error_str)
        )

    def list_node_interfaces(self, node_name):
        """
        List all node interfaces.
        :param str node_name: Node name to use to list interfaces.
        :rtype: list
        :
        """
        result = self._linstor.net_interface_list(node_name)
        if not result:
            raise LinstorVolumeManagerError(
                'Unable to list interfaces on `{}`: no list received'.format(node_name)
            )

        interfaces = {}
        for interface in result:
            interface = interface._rest_data
            interfaces[interface['name']] = {
                'address': interface['address'],
                'active': interface['is_active']
            }
        return interfaces

    def get_node_preferred_interface(self, node_name):
        """
        Get the preferred interface used by a node.
        :param str node_name: Node name of the interface to get.
        :rtype: str
        """
        try:
            nodes = self._linstor.node_list_raise([node_name]).nodes
            if nodes:
                properties = nodes[0].props
                return properties.get('PrefNic', 'default')
            return nodes
        except Exception as e:
            raise LinstorVolumeManagerError(
                'Failed to get preferred interface: `{}`'.format(e)
            )

    def set_node_preferred_interface(self, node_name, name):
        """
        Set the preferred interface to use on a node.
        :param str node_name: Node name of the interface.
        :param str name: Preferred interface to use.
        """
        result = self._linstor.node_modify(node_name, property_dict={'PrefNic': name})
        errors = self._filter_errors(result)
        if errors:
            error_str = self._get_error_str(errors)
            raise LinstorVolumeManagerError(
                'Failed to set preferred node interface on `{}`: {}'.format(node_name, error_str)
            )

    def get_nodes_info(self):
        """
        Get all nodes + statuses, used or not by the pool.
        :rtype: dict(str, dict)
        """
        try:
            nodes = {}
            for node in self._linstor.node_list_raise().nodes:
                nodes[node.name] = node.connection_status
            return nodes
        except Exception as e:
            raise LinstorVolumeManagerError(
                'Failed to get all nodes: `{}`'.format(e)
            )

    def get_storage_pools_info(self):
        """
        Give all storage pools of current group name.
        :rtype: dict(str, list)
        """
        storage_pools = {}
        for pool in self._get_storage_pools(force=True):
            if pool.node_name not in storage_pools:
                storage_pools[pool.node_name] = []

            size = -1
            capacity = -1

            space = pool.free_space
            if space:
                size = space.free_capacity
                if size < 0:
                    size = -1
                else:
                    size *= 1024
                capacity = space.total_capacity
                if capacity <= 0:
                    capacity = -1
                else:
                    capacity *= 1024

            storage_pools[pool.node_name].append({
                'name': pool.name,
                'linstor-uuid': pool.uuid,
                'free-size': size,
                'capacity': capacity
            })

        return storage_pools

    def get_resources_info(self):
        """
        Give all resources of current group name.
        :rtype: dict(str, list)
        """
        resources = {}
        resource_list = self._get_resource_cache()
        volume_names = self.get_volumes_with_name()
        for resource in resource_list.resources:
            if resource.name not in resources:
                resources[resource.name] = { 'nodes': {}, 'uuid': '' }
            resource_nodes = resources[resource.name]['nodes']

            resource_nodes[resource.node_name] = {
                'volumes': [],
                'diskful': linstor.consts.FLAG_DISKLESS not in resource.flags,
                'tie-breaker': linstor.consts.FLAG_TIE_BREAKER in resource.flags
            }
            resource_volumes = resource_nodes[resource.node_name]['volumes']

            for volume in resource.volumes:
                # We ignore diskless pools of the form "DfltDisklessStorPool".
                if volume.storage_pool_name != self._group_name:
                    continue

                usable_size = volume.usable_size
                if usable_size < 0:
                    usable_size = -1
                else:
                    usable_size *= 1024

                allocated_size = volume.allocated_size
                if allocated_size < 0:
                    allocated_size = -1
                else:
                    allocated_size *= 1024

                resource_volumes.append({
                    'storage-pool-name': volume.storage_pool_name,
                    'linstor-uuid': volume.uuid,
                    'number': volume.number,
                    'device-path': volume.device_path,
                    'usable-size': usable_size,
                    'allocated-size': allocated_size
                })

        for resource_state in resource_list.resource_states:
            resource = resources[resource_state.rsc_name]['nodes'][resource_state.node_name]
            resource['in-use'] = resource_state.in_use

            volumes = resource['volumes']
            for volume_state in resource_state.volume_states:
                volume = next((x for x in volumes if x['number'] == volume_state.number), None)
                if volume:
                    volume['disk-state'] = volume_state.disk_state

        for volume_uuid, volume_name in volume_names.items():
            resource = resources.get(volume_name)
            if resource:
                resource['uuid'] = volume_uuid

        return resources

    def get_database_path(self):
        """
        Get the database path.
        :return: The current database path.
        :rtype: str
        """
        return self._request_database_path(self._linstor)

    @classmethod
    def get_all_group_names(cls, base_name):
        """
        Get all group names. I.e. list of current group + HA.
        :param str base_name: The SR group_name to use.
        :return: List of group names.
        :rtype: list
        """
        return [cls._build_group_name(base_name), cls._build_ha_group_name(base_name)]

    @classmethod
    def create_sr(
        cls, group_name, ips, redundancy,
        thin_provisioning, auto_quorum,
        logger=default_logger.__func__
    ):
        """
        Create a new SR on the given nodes.
        :param str group_name: The SR group_name to use.
        :param set(str) ips: Node ips.
        :param int redundancy: How many copy of volumes should we store?
        :param bool thin_provisioning: Use thin or thick provisioning.
        :param bool auto_quorum: DB quorum is monitored by LINSTOR.
        :param function logger: Function to log messages.
        :return: A new LinstorSr instance.
        :rtype: LinstorSr
        """

        try:
            cls._start_controller(start=True)
            sr = cls._create_sr(
                group_name,
                ips,
                redundancy,
                thin_provisioning,
                auto_quorum,
                logger
            )
        finally:
            # Controller must be stopped and volume unmounted because
            # it is the role of the drbd-reactor daemon to do the right
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
        cls, group_name, ips, redundancy,
        thin_provisioning, auto_quorum,
        logger=default_logger.__func__
    ):
        # 1. Check if SR already exists.
        uri = 'linstor://localhost'

        lin = cls._create_linstor_instance(uri, keep_uri_unmodified=True)

        node_names = ips.keys()
        for node_name, ip in ips.iteritems():
            while True:
                # Try to create node.
                result = lin.node_create(
                    node_name,
                    linstor.consts.VAL_NODE_TYPE_CMBD,
                    ip
                )

                errors = cls._filter_errors(result)
                if cls._check_errors(
                    errors, [linstor.consts.FAIL_EXISTS_NODE]
                ):
                    # If it already exists, remove, then recreate.
                    result = lin.node_delete(node_name)
                    error_str = cls._get_error_str(result)
                    if error_str:
                        raise LinstorVolumeManagerError(
                            'Failed to remove old node `{}`: {}'
                            .format(node_name, error_str)
                        )
                elif not errors:
                    break  # Created!
                else:
                    raise LinstorVolumeManagerError(
                        'Failed to create node `{}` with ip `{}`: {}'.format(
                            node_name, ip, cls._get_error_str(errors)
                        )
                    )

        driver_pool_name = group_name
        base_group_name = group_name
        group_name = cls._build_group_name(group_name)
        storage_pool_name = group_name
        pools = lin.storage_pool_list_raise(filter_by_stor_pools=[storage_pool_name]).storage_pools
        if pools:
            existing_node_names = map(lambda pool: pool.node_name, pools)
            raise LinstorVolumeManagerError(
                'Unable to create SR `{}`. It already exists on node(s): {}'
                .format(group_name, existing_node_names)
            )

        if lin.resource_group_list_raise(
            cls.get_all_group_names(base_group_name)
        ).resource_groups:
            if not lin.resource_dfn_list_raise().resource_definitions:
                backup_path = cls._create_database_backup_path()
                logger(
                    'Group name already exists `{}` without LVs. '
                    'Ignoring and moving the config files in {}'.format(group_name, backup_path)
                )
                cls._move_files(DATABASE_PATH, backup_path)
            else:
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
        reg_volume_group_not_found = re.compile(
            ".*Volume group '.*' not found$"
        )

        i = 0
        try:
            # 2.a. Create storage pools.
            storage_pool_count = 0
            while i < len(node_names):
                node_name = node_names[i]

                result = lin.storage_pool_create(
                    node_name=node_name,
                    storage_pool_name=storage_pool_name,
                    storage_driver='LVM_THIN' if thin_provisioning else 'LVM',
                    driver_pool_name=driver_pool_name
                )

                errors = linstor.Linstor.filter_api_call_response_errors(
                    result
                )
                if errors:
                    if len(errors) == 1 and errors[0].is_error(
                        linstor.consts.FAIL_STOR_POOL_CONFIGURATION_ERROR
                    ) and reg_volume_group_not_found.match(errors[0].message):
                        logger(
                            'Volume group `{}` not found on `{}`. Ignoring...'
                            .format(group_name, node_name)
                        )
                        cls._destroy_storage_pool(lin, storage_pool_name, node_name)
                    else:
                        error_str = cls._get_error_str(result)
                        raise LinstorVolumeManagerError(
                            'Could not create SP `{}` on node `{}`: {}'
                            .format(group_name, node_name, error_str)
                        )
                else:
                    storage_pool_count += 1
                i += 1

            if not storage_pool_count:
                raise LinstorVolumeManagerError(
                    'Unable to create SR `{}`: No VG group found'.format(
                        group_name,
                    )
                )

            # 2.b. Create resource groups.
            ha_group_name = cls._build_ha_group_name(base_group_name)
            cls._create_resource_group(
              lin,
              group_name,
              storage_pool_name,
              redundancy,
              True
            )
            cls._create_resource_group(
              lin,
              ha_group_name,
              storage_pool_name,
              3,
              True
            )

            # 3. Create the LINSTOR database volume and mount it.
            try:
                logger('Creating database volume...')
                volume_path = cls._create_database_volume(
                    lin, ha_group_name, storage_pool_name, node_names, redundancy, auto_quorum
                )
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
                cls._destroy_resource_group(lin, ha_group_name)
            except Exception as e2:
                logger('Failed to destroy resource group: {}'.format(e2))
                pass
            j = 0
            i = min(i, len(node_names) - 1)
            while j <= i:
                try:
                    cls._destroy_storage_pool(lin, storage_pool_name, node_names[j])
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
        instance._base_group_name = base_group_name
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
        :param str base_name: The volume name to use.
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

    def _fetch_resource_names(self, ignore_deleted=True):
        resource_names = set()
        dfns = self._linstor.resource_dfn_list_raise().resource_definitions
        for dfn in dfns:
            if dfn.resource_group_name in self.get_all_group_names(self._base_group_name) and (
                ignore_deleted or
                linstor.consts.FLAG_DELETE not in dfn.flags
            ):
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

            if linstor.consts.FLAG_DISKLESS not in resource.flags:
                current.diskful.append(resource.node_name)

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

                    usable_size = volume.usable_size
                    if usable_size > 0 and (
                        usable_size < current.virtual_size or
                        not current.virtual_size
                    ):
                        current.virtual_size = usable_size

        if current.virtual_size <= 0:
            raise LinstorVolumeManagerError(
               'Failed to get usable size of `{}` on `{}`'
               .format(resource.name, volume.storage_pool_name)
            )

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

    def _create_volume(
        self,
        volume_uuid,
        volume_name,
        size,
        place_resources,
        high_availability
    ):
        size = self.round_up_volume_size(size)
        self._mark_resource_cache_as_dirty()

        group_name = self._ha_group_name if high_availability else self._group_name
        def create_definition():
            first_attempt = True
            while True:
                try:
                    self._check_volume_creation_errors(
                        self._linstor.resource_group_spawn(
                            rsc_grp_name=group_name,
                            rsc_dfn_name=volume_name,
                            vlm_sizes=['{}B'.format(size)],
                            definitions_only=True
                        ),
                        volume_uuid,
                        self._group_name
                    )
                    break
                except LinstorVolumeManagerError as e:
                    if (
                        not first_attempt or
                        not high_availability or
                        e.code != LinstorVolumeManagerError.ERR_GROUP_NOT_EXISTS
                    ):
                        raise

                    first_attempt = False
                    self._create_resource_group(
                        self._linstor,
                        group_name,
                        self._group_name,
                        3,
                        True
                    )

            self._configure_volume_peer_slots(self._linstor, volume_name)

        def clean():
            try:
                self._destroy_volume(volume_uuid, force=True, preserve_properties=True)
            except Exception as e:
                self._logger(
                    'Unable to destroy volume {} after creation fail: {}'
                    .format(volume_uuid, e)
                )

        def create():
            try:
                create_definition()
                if place_resources:
                    # Basic case when we use the default redundancy of the group.
                    self._check_volume_creation_errors(
                        self._linstor.resource_auto_place(
                            rsc_name=volume_name,
                            place_count=self._redundancy,
                            diskless_on_remaining=False
                        ),
                        volume_uuid,
                        self._group_name
                    )
            except LinstorVolumeManagerError as e:
                if e.code != LinstorVolumeManagerError.ERR_VOLUME_EXISTS:
                    clean()
                raise
            except Exception:
                clean()
                raise

        util.retry(create, maxretry=5)

    def _create_volume_with_properties(
        self,
        volume_uuid,
        volume_name,
        size,
        place_resources,
        high_availability
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
                volume_uuid,
                volume_name,
                size,
                place_resources,
                high_availability
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
                self._destroy_volume(volume_uuid, force=True)
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

    def _destroy_resource(self, resource_name, force=False):
        result = self._linstor.resource_dfn_delete(resource_name)
        error_str = self._get_error_str(result)
        if not error_str:
            self._mark_resource_cache_as_dirty()
            return

        if not force:
            self._mark_resource_cache_as_dirty()
            raise LinstorVolumeManagerError(
               'Could not destroy resource `{}` from SR `{}`: {}'
                .format(resource_name, self._group_name, error_str)
            )

        # If force is used, ensure there is no opener.
        all_openers = get_all_volume_openers(resource_name, '0')
        for openers in all_openers.itervalues():
            if openers:
                self._mark_resource_cache_as_dirty()
                raise LinstorVolumeManagerError(
                    'Could not force destroy resource `{}` from SR `{}`: {} (openers=`{}`)'
                    .format(resource_name, self._group_name, error_str, all_openers)
                )

        # Maybe the resource is blocked in primary mode. DRBD/LINSTOR issue?
        resource_states = filter(
            lambda resource_state: resource_state.name == resource_name,
            self._get_resource_cache().resource_states
        )

        # Mark only after computation of states.
        self._mark_resource_cache_as_dirty()

        for resource_state in resource_states:
            volume_state = resource_state.volume_states[0]
            if resource_state.in_use:
                demote_drbd_resource(resource_state.node_name, resource_name)
                break
        self._destroy_resource(resource_name)

    def _destroy_volume(self, volume_uuid, force=False, preserve_properties=False):
        volume_properties = self._get_volume_properties(volume_uuid)
        try:
            volume_name = volume_properties.get(self.PROP_VOLUME_NAME)
            if volume_name in self._fetch_resource_names():
                self._destroy_resource(volume_name, force)

            # Assume this call is atomic.
            if not preserve_properties:
                volume_properties.clear()
        except Exception as e:
            raise LinstorVolumeManagerError(
                'Cannot destroy volume `{}`: {}'.format(volume_uuid, e)
            )

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
                    self._destroy_resource(volume_name, force=True)

                # Assume this call is atomic.
                properties.clear()
            except Exception as e:
                # Do not raise, we don't want to block user action.
                self._logger(
                    'Cannot clean volume {}: {}'.format(volume_uuid, e)
                )

                # The volume can't be removed, maybe it's still in use,
                # in this case rename it with the "DELETED_" prefix.
                # This prefix is mandatory if it exists a snap transaction to
                # rollback because the original VDI UUID can try to be renamed
                # with the UUID we are trying to delete...
                if not volume_uuid.startswith('DELETED_'):
                    self.update_volume_uuid(
                        volume_uuid, 'DELETED_' + volume_uuid, force=True
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
            self._group_name,
            uri=self._linstor.controller_host(),
            namespace=namespace
        )

    def _get_volume_properties(self, volume_uuid):
        properties = self._get_kv_cache()
        properties.namespace = self._build_volume_namespace(volume_uuid)
        return properties

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
    def _create_linstor_instance(
        cls, uri, keep_uri_unmodified=False, attempt_count=30
    ):
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
            maxretry=attempt_count,
            period=1,
            exceptions=[
                linstor.errors.LinstorNetworkError,
                LinstorVolumeManagerError
            ]
        )

    @classmethod
    def _configure_volume_peer_slots(cls, lin, volume_name):
        result = lin.resource_dfn_modify(volume_name, {}, peer_slots=3)
        error_str = cls._get_error_str(result)
        if error_str:
            raise LinstorVolumeManagerError(
                'Could not configure volume peer slots of {}: {}'
                .format(volume_name, error_str)
            )

    @classmethod
    def _activate_device_path(cls, lin, node_name, volume_name):
        result = lin.resource_make_available(node_name, volume_name, diskful=False)
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
                'Unable to fetch database resource: {}'
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
    def _create_database_volume(
        cls, lin, group_name, storage_pool_name, node_names, redundancy, auto_quorum
    ):
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

        # Workaround to use thin lvm. Without this line an error is returned:
        # "Not enough available nodes"
        # I don't understand why but this command protect against this bug.
        try:
            pools = lin.storage_pool_list_raise(
                filter_by_stor_pools=[storage_pool_name]
            )
        except Exception as e:
            raise LinstorVolumeManagerError(
                'Failed to get storage pool list before database creation: {}'
                .format(e)
            )

        # Ensure we have a correct list of storage pools.
        nodes_with_pool = map(lambda pool: pool.node_name, pools.storage_pools)
        assert nodes_with_pool  # We must have at least one storage pool!
        for node_name in nodes_with_pool:
            assert node_name in node_names
        util.SMlog('Nodes with storage pool: {}'.format(nodes_with_pool))

        # Create the database definition.
        size = cls.round_up_volume_size(DATABASE_SIZE)
        cls._check_volume_creation_errors(lin.resource_group_spawn(
            rsc_grp_name=group_name,
            rsc_dfn_name=DATABASE_VOLUME_NAME,
            vlm_sizes=['{}B'.format(size)],
            definitions_only=True
        ), DATABASE_VOLUME_NAME, group_name)
        cls._configure_volume_peer_slots(lin, DATABASE_VOLUME_NAME)

        # Create real resources on the first nodes.
        resources = []

        diskful_nodes = []
        diskless_nodes = []
        for node_name in node_names:
            if node_name in nodes_with_pool:
                diskful_nodes.append(node_name)
            else:
                diskless_nodes.append(node_name)

        assert diskful_nodes
        for node_name in diskful_nodes[:redundancy]:
            util.SMlog('Create database diskful on {}'.format(node_name))
            resources.append(linstor.ResourceData(
                node_name=node_name,
                rsc_name=DATABASE_VOLUME_NAME,
                storage_pool=storage_pool_name
            ))
        # Create diskless resources on the remaining set.
        for node_name in diskful_nodes[redundancy:] + diskless_nodes:
            util.SMlog('Create database diskless on {}'.format(node_name))
            resources.append(linstor.ResourceData(
                node_name=node_name,
                rsc_name=DATABASE_VOLUME_NAME,
                diskless=True
            ))

        result = lin.resource_create(resources)
        error_str = cls._get_error_str(result)
        if error_str:
            raise LinstorVolumeManagerError(
                'Could not create database volume from SR `{}`: {}'.format(
                    group_name, error_str
                )
            )

        # We must modify the quorum. Otherwise we can't use correctly the
        # drbd-reactor daemon.
        if auto_quorum:
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

        # Create database and ensure path exists locally and
        # on replicated devices.
        current_device_path = cls._request_database_path(lin, activate=True)

        # Ensure diskless paths exist on other hosts. Otherwise PBDs can't be
        # plugged.
        for node_name in node_names:
            cls._activate_device_path(lin, node_name, DATABASE_VOLUME_NAME)

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
            util.retry(
                lambda: util.pread2([DATABASE_MKFS, expected_device_path]),
                maxretry=5
            )
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
        try:
            # 1. Create a backup config folder.
            database_not_empty = bool(os.listdir(DATABASE_PATH))
            backup_path = cls._create_database_backup_path()

            # 2. Move the config in the mounted volume.
            if database_not_empty:
                cls._move_files(DATABASE_PATH, backup_path)

            cls._mount_volume(volume_path, DATABASE_PATH, mount)

            if database_not_empty:
                cls._move_files(backup_path, DATABASE_PATH, force)

                # 3. Remove useless backup directory.
                try:
                    os.rmdir(backup_path)
                except Exception as e:
                    raise LinstorVolumeManagerError(
                        'Failed to remove backup path {} of LINSTOR config: {}'
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
    def _create_resource_group(
        cls,
        lin,
        group_name,
        storage_pool_name,
        redundancy,
        destroy_old_group
    ):
        rg_creation_attempt = 0
        while True:
            result = lin.resource_group_create(
                name=group_name,
                place_count=redundancy,
                storage_pool=storage_pool_name,
                diskless_on_remaining=False
            )
            error_str = cls._get_error_str(result)
            if not error_str:
                break

            errors = cls._filter_errors(result)
            if destroy_old_group and cls._check_errors(errors, [
                linstor.consts.FAIL_EXISTS_RSC_GRP
            ]):
                rg_creation_attempt += 1
                if rg_creation_attempt < 2:
                    try:
                        cls._destroy_resource_group(lin, group_name)
                    except Exception as e:
                        error_str = 'Failed to destroy old and empty RG: {}'.format(e)
                    else:
                        continue

            raise LinstorVolumeManagerError(
                'Could not create RG `{}`: {}'.format(
                    group_name, error_str
                )
            )

        result = lin.volume_group_create(group_name)
        error_str = cls._get_error_str(result)
        if error_str:
            raise LinstorVolumeManagerError(
                'Could not create VG `{}`: {}'.format(
                    group_name, error_str
                )
            )

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

    # Used to store important data in a HA context,
    # i.e. a replication count of 3.
    @classmethod
    def _build_ha_group_name(cls, base_name):
        return '{}{}'.format(cls.PREFIX_HA, base_name.replace('/', '_'))

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

        if cls._check_errors(errors, [linstor.consts.FAIL_NOT_FOUND_RSC_GRP]):
            raise LinstorVolumeManagerError(
                'Failed to create volume `{}` from SR `{}`, resource group doesn\'t exist'
                .format(volume_uuid, group_name),
                LinstorVolumeManagerError.ERR_GROUP_NOT_EXISTS
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
    def _create_database_backup_path():
        path = DATABASE_PATH + '-' + str(uuid.uuid4())
        try:
            os.mkdir(path)
            return path
        except Exception as e:
            raise LinstorVolumeManagerError(
                'Failed to create backup path {} of LINSTOR config: {}'
                .format(path, e)
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
    def _controller_is_running(cls):
        return cls._service_is_running('linstor-controller')

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
    def _service_is_running(name):
        (ret, out, err) = util.doexec([
            'systemctl', 'is-active', '--quiet', name
        ])
        return not ret

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


# ==============================================================================

# Check if a path is a DRBD resource and log the process name/pid
# that opened it.
def log_drbd_openers(path):
    # Ignore if it's not a symlink to DRBD resource.
    if not path.startswith(DRBD_BY_RES_PATH):
        return

    # Compute resource name.
    res_name_end = path.find('/', len(DRBD_BY_RES_PATH))
    if res_name_end == -1:
        return
    res_name = path[len(DRBD_BY_RES_PATH):res_name_end]

    volume_end = path.rfind('/')
    if volume_end == res_name_end:
        return
    volume = path[volume_end + 1:]

    try:
        # Ensure path is a DRBD.
        drbd_path = os.path.realpath(path)
        stats = os.stat(drbd_path)
        if not stat.S_ISBLK(stats.st_mode) or os.major(stats.st_rdev) != 147:
            return

        # Find where the device is open.
        (ret, stdout, stderr) = util.doexec(['drbdadm', 'status', res_name])
        if ret != 0:
            util.SMlog('Failed to execute `drbdadm status` on `{}`: {}'.format(
                res_name, stderr
            ))
            return

        # Is it a local device?
        if stdout.startswith('{} role:Primary'.format(res_name)):
            util.SMlog(
                'DRBD resource `{}` is open on local host: {}'
                .format(path, get_local_volume_openers(res_name, volume))
            )
            return

        # Is it a remote device?
        util.SMlog(
            'DRBD resource `{}` is open on hosts: {}'
            .format(path, get_all_volume_openers(res_name, volume))
        )
    except Exception as e:
        util.SMlog(
            'Got exception while trying to determine where DRBD resource ' +
            '`{}` is open: {}'.format(path, e)
        )
