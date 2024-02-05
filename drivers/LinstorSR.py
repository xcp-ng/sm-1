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

from constants import CBTLOG_TAG

try:
    from linstorjournaler import LinstorJournaler
    from linstorvhdutil import LinstorVhdUtil
    from linstorvolumemanager import get_controller_uri
    from linstorvolumemanager import get_controller_node_name
    from linstorvolumemanager import LinstorVolumeManager
    from linstorvolumemanager import LinstorVolumeManagerError
    from linstorvolumemanager import PERSISTENT_PREFIX

    LINSTOR_AVAILABLE = True
except ImportError:
    PERSISTENT_PREFIX = 'unknown'

    LINSTOR_AVAILABLE = False

from lock import Lock, LOCK_TYPE_GC_RUNNING
import blktap2
import cleanup
import distutils
import errno
import functools
import lvutil
import os
import re
import scsiutil
import signal
import socket
import SR
import SRCommand
import subprocess
import time
import traceback
import util
import VDI
import vhdutil
import xml.etree.ElementTree as xml_parser
import xmlrpc.client
import xs_errors

from srmetadata import \
    NAME_LABEL_TAG, NAME_DESCRIPTION_TAG, IS_A_SNAPSHOT_TAG, SNAPSHOT_OF_TAG, \
    TYPE_TAG, VDI_TYPE_TAG, READ_ONLY_TAG, SNAPSHOT_TIME_TAG, \
    METADATA_OF_POOL_TAG

HIDDEN_TAG = 'hidden'

XHA_CONFIG_PATH = '/etc/xensource/xhad.conf'

FORK_LOG_DAEMON = '/opt/xensource/libexec/fork-log-daemon'

# This flag can be disabled to debug the DRBD layer.
# When this config var is False, the HA can only be used under
# specific conditions:
# - Only one heartbeat diskless VDI is present in the pool.
# - The other hearbeat volumes must be diskful and limited to a maximum of 3.
USE_HTTP_NBD_SERVERS = True

# Useful flag to trace calls using cProfile.
TRACE_PERFS = False

# Enable/Disable VHD key hash support.
USE_KEY_HASH = False

# Special volumes.
HA_VOLUME_NAME = PERSISTENT_PREFIX + 'ha-statefile'
REDO_LOG_VOLUME_NAME = PERSISTENT_PREFIX + 'redo-log'

# ==============================================================================

# TODO: Supports 'VDI_INTRODUCE', 'VDI_RESET_ON_BOOT/2', 'SR_TRIM',
# 'VDI_CONFIG_CBT', 'SR_PROBE'

CAPABILITIES = [
    'ATOMIC_PAUSE',
    'SR_UPDATE',
    'VDI_CREATE',
    'VDI_DELETE',
    'VDI_UPDATE',
    'VDI_ATTACH',
    'VDI_DETACH',
    'VDI_ACTIVATE',
    'VDI_DEACTIVATE',
    'VDI_CLONE',
    'VDI_MIRROR',
    'VDI_RESIZE',
    'VDI_SNAPSHOT',
    'VDI_GENERATE_CONFIG'
]

CONFIGURATION = [
    ['group-name', 'LVM group name'],
    ['redundancy', 'replication count'],
    ['provisioning', '"thin" or "thick" are accepted (optional, defaults to thin)'],
    ['monitor-db-quorum', 'disable controller when only one host is online (optional, defaults to true)']
]

DRIVER_INFO = {
    'name': 'LINSTOR resources on XCP-ng',
    'description': 'SR plugin which uses Linstor to manage VDIs',
    'vendor': 'Vates',
    'copyright': '(C) 2020 Vates',
    'driver_version': '1.0',
    'required_api_version': '1.0',
    'capabilities': CAPABILITIES,
    'configuration': CONFIGURATION
}

DRIVER_CONFIG = {'ATTACH_FROM_CONFIG_WITH_TAPDISK': False}

OPS_EXCLUSIVE = [
    'sr_create', 'sr_delete', 'sr_attach', 'sr_detach', 'sr_scan',
    'sr_update', 'sr_probe', 'vdi_init', 'vdi_create', 'vdi_delete',
    'vdi_attach', 'vdi_detach', 'vdi_clone', 'vdi_snapshot',
]

# ==============================================================================
# Misc helpers used by LinstorSR and linstor-thin plugin.
# ==============================================================================


def attach_thin(session, journaler, linstor, sr_uuid, vdi_uuid):
    volume_metadata = linstor.get_volume_metadata(vdi_uuid)
    image_type = volume_metadata.get(VDI_TYPE_TAG)
    if image_type == vhdutil.VDI_TYPE_RAW:
        return

    device_path = linstor.get_device_path(vdi_uuid)

    # If the virtual VHD size is lower than the LINSTOR volume size,
    # there is nothing to do.
    vhd_size = LinstorVhdUtil.compute_volume_size(
        # TODO: Replace pylint comment with this feature when possible:
        # https://github.com/PyCQA/pylint/pull/2926
        LinstorVhdUtil(session, linstor).get_size_virt(vdi_uuid),  # pylint: disable = E1120
        image_type
    )

    volume_info = linstor.get_volume_info(vdi_uuid)
    volume_size = volume_info.virtual_size

    if vhd_size > volume_size:
        LinstorVhdUtil(session, linstor).inflate(
            journaler, vdi_uuid, device_path, vhd_size, volume_size
        )


def detach_thin_impl(session, linstor, sr_uuid, vdi_uuid):
    volume_metadata = linstor.get_volume_metadata(vdi_uuid)
    image_type = volume_metadata.get(VDI_TYPE_TAG)
    if image_type == vhdutil.VDI_TYPE_RAW:
        return

    def check_vbd_count():
        vdi_ref = session.xenapi.VDI.get_by_uuid(vdi_uuid)
        vbds = session.xenapi.VBD.get_all_records_where(
            'field "VDI" = "{}"'.format(vdi_ref)
        )

        num_plugged = 0
        for vbd_rec in vbds.values():
            if vbd_rec['currently_attached']:
                num_plugged += 1
                if num_plugged > 1:
                    raise xs_errors.XenError(
                        'VDIUnavailable',
                        opterr='Cannot deflate VDI {}, already used by '
                        'at least 2 VBDs'.format(vdi_uuid)
                    )

    # We can have multiple VBDs attached to a VDI during a VM-template clone.
    # So we use a timeout to ensure that we can detach the volume properly.
    util.retry(check_vbd_count, maxretry=10, period=1)

    device_path = linstor.get_device_path(vdi_uuid)
    vhdutil_inst = LinstorVhdUtil(session, linstor)
    new_volume_size = LinstorVolumeManager.round_up_volume_size(
        # TODO: Replace pylint comment with this feature when possible:
        # https://github.com/PyCQA/pylint/pull/2926
        vhdutil_inst.get_size_phys(vdi_uuid)  # pylint: disable = E1120
    )

    volume_info = linstor.get_volume_info(vdi_uuid)
    old_volume_size = volume_info.virtual_size
    vhdutil_inst.deflate(device_path, new_volume_size, old_volume_size)


def detach_thin(session, linstor, sr_uuid, vdi_uuid):
    # This function must always return without errors.
    # Otherwise it could cause errors in the XAPI regarding the state of the VDI.
    # It's why we use this `try` block.
    try:
        detach_thin_impl(session, linstor, sr_uuid, vdi_uuid)
    except Exception as e:
        util.SMlog('Failed to detach properly VDI {}: {}'.format(vdi_uuid, e))


def get_ips_from_xha_config_file():
    ips = dict()
    host_id = None
    try:
        # Ensure there is no dirty read problem.
        # For example if the HA is reloaded.
        tree = util.retry(
            lambda: xml_parser.parse(XHA_CONFIG_PATH),
            maxretry=10,
            period=1
        )
    except:
        return (None, ips)

    def parse_host_nodes(ips, node):
        current_id = None
        current_ip = None

        for sub_node in node:
            if sub_node.tag == 'IPaddress':
                current_ip = sub_node.text
            elif sub_node.tag == 'HostID':
                current_id = sub_node.text
            else:
                continue

            if current_id and current_ip:
                ips[current_id] = current_ip
                return
        util.SMlog('Ill-formed XHA file, missing IPaddress or/and HostID')

    def parse_common_config(ips, node):
        for sub_node in node:
            if sub_node.tag == 'host':
                parse_host_nodes(ips, sub_node)

    def parse_local_config(ips, node):
        for sub_node in node:
            if sub_node.tag == 'localhost':
                for host_node in sub_node:
                    if host_node.tag == 'HostID':
                        return host_node.text

    for node in tree.getroot():
        if node.tag == 'common-config':
            parse_common_config(ips, node)
        elif node.tag == 'local-config':
            host_id = parse_local_config(ips, node)
        else:
            continue

        if ips and host_id:
            break

    return (host_id and ips.get(host_id), ips)


def activate_lvm_group(group_name):
    path = group_name.split('/')
    assert path and len(path) <= 2
    try:
        lvutil.setActiveVG(path[0], True)
    except Exception as e:
        util.SMlog('Cannot active VG `{}`: {}'.format(path[0], e))

# ==============================================================================

# Usage example:
# xe sr-create type=linstor name-label=linstor-sr
# host-uuid=d2deba7a-c5ad-4de1-9a20-5c8df3343e93
# device-config:group-name=vg_loop device-config:redundancy=2


class LinstorSR(SR.SR):
    DRIVER_TYPE = 'linstor'

    PROVISIONING_TYPES = ['thin', 'thick']
    PROVISIONING_DEFAULT = 'thin'

    MANAGER_PLUGIN = 'linstor-manager'

    INIT_STATUS_NOT_SET = 0
    INIT_STATUS_IN_PROGRESS = 1
    INIT_STATUS_OK = 2
    INIT_STATUS_FAIL = 3

    # --------------------------------------------------------------------------
    # SR methods.
    # --------------------------------------------------------------------------

    @staticmethod
    def handles(type):
        return type == LinstorSR.DRIVER_TYPE

    def load(self, sr_uuid):
        if not LINSTOR_AVAILABLE:
            raise util.SMException(
                'Can\'t load LinstorSR: LINSTOR libraries are missing'
            )

        # Check parameters.
        if 'group-name' not in self.dconf or not self.dconf['group-name']:
            raise xs_errors.XenError('LinstorConfigGroupNameMissing')
        if 'redundancy' not in self.dconf or not self.dconf['redundancy']:
            raise xs_errors.XenError('LinstorConfigRedundancyMissing')

        self.driver_config = DRIVER_CONFIG

        # Check provisioning config.
        provisioning = self.dconf.get('provisioning')
        if provisioning:
            if provisioning in self.PROVISIONING_TYPES:
                self._provisioning = provisioning
            else:
                raise xs_errors.XenError(
                    'InvalidArg',
                    opterr='Provisioning parameter must be one of {}'.format(
                        self.PROVISIONING_TYPES
                    )
                )
        else:
            self._provisioning = self.PROVISIONING_DEFAULT

        monitor_db_quorum = self.dconf.get('monitor-db-quorum')
        self._monitor_db_quorum = (monitor_db_quorum is None) or \
            distutils.util.strtobool(monitor_db_quorum)

        # Note: We don't have access to the session field if the
        # 'vdi_attach_from_config' command is executed.
        self._has_session = self.sr_ref and self.session is not None
        if self._has_session:
            self.sm_config = self.session.xenapi.SR.get_sm_config(self.sr_ref)
        else:
            self.sm_config = self.srcmd.params.get('sr_sm_config') or {}

        provisioning = self.sm_config.get('provisioning')
        if provisioning in self.PROVISIONING_TYPES:
            self._provisioning = provisioning

        # Define properties for SR parent class.
        self.ops_exclusive = OPS_EXCLUSIVE
        self.path = LinstorVolumeManager.DEV_ROOT_PATH
        self.lock = Lock(vhdutil.LOCK_TYPE_SR, self.uuid)
        self.sr_vditype = SR.DEFAULT_TAP

        if self.cmd == 'sr_create':
            self._redundancy = int(self.dconf['redundancy']) or 1
        self._linstor = None  # Ensure that LINSTOR attribute exists.
        self._journaler = None

        self._group_name = self.dconf['group-name']

        self._vdi_shared_time = 0

        self._init_status = self.INIT_STATUS_NOT_SET

        self._vdis_loaded = False
        self._all_volume_info_cache = None
        self._all_volume_metadata_cache = None

    def _locked_load(method):
        def wrapped_method(self, *args, **kwargs):
            self._init_status = self.INIT_STATUS_OK
            return method(self, *args, **kwargs)

        def load(self, *args, **kwargs):
            # Activate all LVMs to make drbd-reactor happy.
            if self.srcmd.cmd in ('sr_attach', 'vdi_attach_from_config'):
                activate_lvm_group(self._group_name)

            if not self._has_session:
                if self.srcmd.cmd in (
                    'vdi_attach_from_config',
                    'vdi_detach_from_config',
                    # When on-slave (is_open) is executed we have an
                    # empty command.
                    None
                ):
                    def create_linstor(uri, attempt_count=30):
                        self._linstor = LinstorVolumeManager(
                            uri,
                            self._group_name,
                            logger=util.SMlog,
                            attempt_count=attempt_count
                        )
                        # Only required if we are attaching from config using a non-special VDI.
                        # I.e. not an HA volume.
                        self._vhdutil = LinstorVhdUtil(self.session, self._linstor)

                    controller_uri = get_controller_uri()
                    if controller_uri:
                        create_linstor(controller_uri)
                    else:
                        def connect():
                            # We must have a valid LINSTOR instance here without using
                            # the XAPI. Fallback with the HA config file.
                            for ip in get_ips_from_xha_config_file()[1].values():
                                controller_uri = 'linstor://' + ip
                                try:
                                    util.SMlog('Connecting from config to LINSTOR controller using: {}'.format(ip))
                                    create_linstor(controller_uri, attempt_count=0)
                                    return controller_uri
                                except:
                                    pass

                        controller_uri = util.retry(connect, maxretry=30, period=1)
                        if not controller_uri:
                            raise xs_errors.XenError(
                                'SRUnavailable',
                                opterr='No valid controller URI to attach/detach from config'
                            )

                    self._journaler = LinstorJournaler(
                        controller_uri, self._group_name, logger=util.SMlog
                    )

                if self.srcmd.cmd is None:
                    # Only useful on on-slave plugin (is_open).
                    self._vhdutil = LinstorVhdUtil(self.session, self._linstor)

                return wrapped_method(self, *args, **kwargs)

            if not self.is_master():
                if self.cmd in [
                    'sr_create', 'sr_delete', 'sr_update', 'sr_probe',
                    'sr_scan', 'vdi_create', 'vdi_delete', 'vdi_resize',
                    'vdi_snapshot', 'vdi_clone'
                ]:
                    util.SMlog('{} blocked for non-master'.format(self.cmd))
                    raise xs_errors.XenError('LinstorMaster')

                # Because the LINSTOR KV objects cache all values, we must lock
                # the VDI before the LinstorJournaler/LinstorVolumeManager
                # instantiation and before any action on the master to avoid a
                # bad read. The lock is also necessary to avoid strange
                # behaviors if the GC is executed during an action on a slave.
                if self.cmd.startswith('vdi_'):
                    self._shared_lock_vdi(self.srcmd.params['vdi_uuid'])
                    self._vdi_shared_time = time.time()

            if self.srcmd.cmd != 'sr_create' and self.srcmd.cmd != 'sr_detach':
                try:
                    self._reconnect()
                except Exception as e:
                    raise xs_errors.XenError('SRUnavailable', opterr=str(e))

            if self._linstor:
                try:
                    hosts = self._linstor.disconnected_hosts
                except Exception as e:
                    raise xs_errors.XenError('SRUnavailable', opterr=str(e))

                if hosts:
                    util.SMlog('Failed to join node(s): {}'.format(hosts))

                # Ensure we use a non-locked volume when vhdutil is called.
                if (
                    self.is_master() and self.cmd.startswith('vdi_') and
                    self.cmd != 'vdi_create'
                ):
                    self._linstor.ensure_volume_is_not_locked(
                        self.srcmd.params['vdi_uuid']
                    )

                try:
                    # If the command is a SR scan command on the master,
                    # we must load all VDIs and clean journal transactions.
                    # We must load the VDIs in the snapshot case too only if
                    # there is at least one entry in the journal.
                    #
                    # If the command is a SR command we want at least to remove
                    # resourceless volumes.
                    if self.is_master() and self.cmd not in [
                        'vdi_attach', 'vdi_detach',
                        'vdi_activate', 'vdi_deactivate',
                        'vdi_epoch_begin', 'vdi_epoch_end',
                        'vdi_update', 'vdi_destroy'
                    ]:
                        load_vdis = (
                            self.cmd == 'sr_scan' or
                            self.cmd == 'sr_attach'
                        ) or len(
                            self._journaler.get_all(LinstorJournaler.INFLATE)
                        ) or len(
                            self._journaler.get_all(LinstorJournaler.CLONE)
                        )

                        if load_vdis:
                            self._load_vdis()

                        self._linstor.remove_resourceless_volumes()

                    self._synchronize_metadata()
                except Exception as e:
                    if self.cmd == 'sr_scan' or self.cmd == 'sr_attach':
                        # Always raise, we don't want to remove VDIs
                        # from the XAPI database otherwise.
                        raise e
                    util.SMlog(
                        'Ignoring exception in LinstorSR.load: {}'.format(e)
                    )
                    util.SMlog(traceback.format_exc())

            return wrapped_method(self, *args, **kwargs)

        @functools.wraps(wrapped_method)
        def wrap(self, *args, **kwargs):
            if self._init_status in \
                    (self.INIT_STATUS_OK, self.INIT_STATUS_IN_PROGRESS):
                return wrapped_method(self, *args, **kwargs)
            if self._init_status == self.INIT_STATUS_FAIL:
                util.SMlog(
                    'Can\'t call method {} because initialization failed'
                    .format(method)
                )
            else:
                try:
                    self._init_status = self.INIT_STATUS_IN_PROGRESS
                    return load(self, *args, **kwargs)
                except Exception:
                    if self._init_status != self.INIT_STATUS_OK:
                        self._init_status = self.INIT_STATUS_FAIL
                    raise

        return wrap

    def cleanup(self):
        if self._vdi_shared_time:
            self._shared_lock_vdi(self.srcmd.params['vdi_uuid'], locked=False)

    @_locked_load
    def create(self, uuid, size):
        util.SMlog('LinstorSR.create for {}'.format(self.uuid))

        host_adresses = util.get_host_addresses(self.session)
        if self._redundancy > len(host_adresses):
            raise xs_errors.XenError(
                'LinstorSRCreate',
                opterr='Redundancy greater than host count'
            )

        xenapi = self.session.xenapi
        srs = xenapi.SR.get_all_records_where(
            'field "type" = "{}"'.format(self.DRIVER_TYPE)
        )
        srs = dict([e for e in srs.items() if e[1]['uuid'] != self.uuid])

        for sr in srs.values():
            for pbd in sr['PBDs']:
                device_config = xenapi.PBD.get_device_config(pbd)
                group_name = device_config.get('group-name')
                if group_name and group_name == self._group_name:
                    raise xs_errors.XenError(
                        'LinstorSRCreate',
                        opterr='group name must be unique, already used by PBD {}'.format(
                            xenapi.PBD.get_uuid(pbd)
                        )
                    )

        if srs:
            raise xs_errors.XenError(
                'LinstorSRCreate',
                opterr='LINSTOR SR must be unique in a pool'
            )

        online_hosts = util.get_online_hosts(self.session)
        if len(online_hosts) < len(host_adresses):
            raise xs_errors.XenError(
                'LinstorSRCreate',
                opterr='Not enough online hosts'
            )

        ips = {}
        for host_ref in online_hosts:
            record = self.session.xenapi.host.get_record(host_ref)
            hostname = record['hostname']
            ips[hostname] = record['address']

        if len(ips) != len(online_hosts):
            raise xs_errors.XenError(
                'LinstorSRCreate',
                opterr='Multiple hosts with same hostname'
            )

        # Ensure ports are opened and LINSTOR satellites
        # are activated. In the same time the drbd-reactor instances
        # must be stopped.
        self._prepare_sr_on_all_hosts(self._group_name, enabled=True)

        # Create SR.
        # Throw if the SR already exists.
        try:
            self._linstor = LinstorVolumeManager.create_sr(
                self._group_name,
                ips,
                self._redundancy,
                thin_provisioning=self._provisioning == 'thin',
                auto_quorum=self._monitor_db_quorum,
                logger=util.SMlog
            )
            self._vhdutil = LinstorVhdUtil(self.session, self._linstor)
        except Exception as e:
            util.SMlog('Failed to create LINSTOR SR: {}'.format(e))
            raise xs_errors.XenError('LinstorSRCreate', opterr=str(e))

        try:
            util.SMlog(
                "Finishing SR creation, enable drbd-reactor on all hosts..."
            )
            self._update_drbd_reactor_on_all_hosts(enabled=True)
        except Exception as e:
            try:
                self._linstor.destroy()
            except Exception as e2:
                util.SMlog(
                    'Failed to destroy LINSTOR SR after creation fail: {}'
                    .format(e2)
                )
            raise e

    @_locked_load
    def delete(self, uuid):
        util.SMlog('LinstorSR.delete for {}'.format(self.uuid))
        cleanup.gc_force(self.session, self.uuid)

        if self.vdis or self._linstor._volumes:
            raise xs_errors.XenError('SRNotEmpty')

        node_name = get_controller_node_name()
        if not node_name:
            raise xs_errors.XenError(
                'LinstorSRDelete',
                opterr='Cannot get controller node name'
            )

        host_ref = None
        if node_name == 'localhost':
            host_ref = util.get_this_host_ref(self.session)
        else:
            for slave in util.get_all_slaves(self.session):
                r_name = self.session.xenapi.host.get_record(slave)['hostname']
                if r_name == node_name:
                    host_ref = slave
                    break

        if not host_ref:
            raise xs_errors.XenError(
                'LinstorSRDelete',
                opterr='Failed to find host with hostname: {}'.format(
                    node_name
                )
            )

        try:
            self._update_drbd_reactor_on_all_hosts(
                controller_node_name=node_name, enabled=False
            )

            args = {
                'groupName': self._group_name,
            }
            self._exec_manager_command(
                host_ref, 'destroy', args, 'LinstorSRDelete'
            )
        except Exception as e:
            try:
                self._update_drbd_reactor_on_all_hosts(
                    controller_node_name=node_name, enabled=True
                )
            except Exception as e2:
                util.SMlog(
                    'Failed to restart drbd-reactor after destroy fail: {}'
                    .format(e2)
                )
            util.SMlog('Failed to delete LINSTOR SR: {}'.format(e))
            raise xs_errors.XenError(
                'LinstorSRDelete',
                opterr=str(e)
            )

        Lock.cleanupAll(self.uuid)

    @_locked_load
    def update(self, uuid):
        util.SMlog('LinstorSR.update for {}'.format(self.uuid))

        # Well, how can we update a SR if it doesn't exist? :thinking:
        if not self._linstor:
            raise xs_errors.XenError(
                'SRUnavailable',
                opterr='no such volume group: {}'.format(self._group_name)
            )

        self._update_stats(0)

        # Update the SR name and description only in LINSTOR metadata.
        xenapi = self.session.xenapi
        self._linstor.metadata = {
            NAME_LABEL_TAG: util.to_plain_string(
                xenapi.SR.get_name_label(self.sr_ref)
            ),
            NAME_DESCRIPTION_TAG: util.to_plain_string(
                xenapi.SR.get_name_description(self.sr_ref)
            )
        }

    @_locked_load
    def attach(self, uuid):
        util.SMlog('LinstorSR.attach for {}'.format(self.uuid))

        if not self._linstor:
            raise xs_errors.XenError(
                'SRUnavailable',
                opterr='no such group: {}'.format(self._group_name)
            )

    @_locked_load
    def detach(self, uuid):
        util.SMlog('LinstorSR.detach for {}'.format(self.uuid))
        cleanup.abort(self.uuid)

    @_locked_load
    def probe(self):
        util.SMlog('LinstorSR.probe for {}'.format(self.uuid))
        # TODO

    @_locked_load
    def scan(self, uuid):
        if self._init_status == self.INIT_STATUS_FAIL:
            return

        util.SMlog('LinstorSR.scan for {}'.format(self.uuid))
        if not self._linstor:
            raise xs_errors.XenError(
                'SRUnavailable',
                opterr='no such volume group: {}'.format(self._group_name)
            )

        # Note: `scan` can be called outside this module, so ensure the VDIs
        # are loaded.
        self._load_vdis()
        self._update_physical_size()

        for vdi_uuid in list(self.vdis.keys()):
            if self.vdis[vdi_uuid].deleted:
                del self.vdis[vdi_uuid]

        # Security to prevent VDIs from being forgotten if the controller
        # is started without a shared and mounted /var/lib/linstor path.
        try:
            self._linstor.get_database_path()
        except Exception as e:
            # Failed to get database path, ensure we don't have
            # VDIs in the XAPI database...
            if self.session.xenapi.SR.get_VDIs(
                self.session.xenapi.SR.get_by_uuid(self.uuid)
            ):
                raise xs_errors.XenError(
                    'SRUnavailable',
                    opterr='Database is not mounted or node name is invalid ({})'.format(e)
                )

        # Update the database before the restart of the GC to avoid
        # bad sync in the process if new VDIs have been introduced.
        super(LinstorSR, self).scan(self.uuid)
        self._kick_gc()

    def is_master(self):
        if not hasattr(self, '_is_master'):
            if 'SRmaster' not in self.dconf:
                self._is_master = self.session is not None and util.is_master(self.session)
            else:
                self._is_master = self.dconf['SRmaster'] == 'true'

        return self._is_master

    @_locked_load
    def vdi(self, uuid):
        return LinstorVDI(self, uuid)

    _locked_load = staticmethod(_locked_load)

    # --------------------------------------------------------------------------
    # Lock.
    # --------------------------------------------------------------------------

    def _shared_lock_vdi(self, vdi_uuid, locked=True):
        master = util.get_master_ref(self.session)

        command = 'lockVdi'
        args = {
            'groupName': self._group_name,
            'srUuid': self.uuid,
            'vdiUuid': vdi_uuid,
            'locked': str(locked)
        }

        # Note: We must avoid to unlock the volume if the timeout is reached
        # because during volume unlock, the SR lock is not used. Otherwise
        # we could destroy a valid lock acquired from another host...
        #
        # This code is not very clean, the ideal solution would be to acquire
        # the SR lock during volume unlock (like lock) but it's not easy
        # to implement without impacting performance.
        if not locked:
            elapsed_time = time.time() - self._vdi_shared_time
            timeout = LinstorVolumeManager.LOCKED_EXPIRATION_DELAY * 0.7
            if elapsed_time >= timeout:
                util.SMlog(
                    'Avoid unlock call of {} because timeout has been reached'
                    .format(vdi_uuid)
                )
                return

        self._exec_manager_command(master, command, args, 'VDIUnavailable')

    # --------------------------------------------------------------------------
    # Network.
    # --------------------------------------------------------------------------

    def _exec_manager_command(self, host_ref, command, args, error):
        host_rec = self.session.xenapi.host.get_record(host_ref)
        host_uuid = host_rec['uuid']

        try:
            ret = self.session.xenapi.host.call_plugin(
                host_ref, self.MANAGER_PLUGIN, command, args
            )
        except Exception as e:
            util.SMlog(
                'call-plugin on {} ({}:{} with {}) raised'.format(
                    host_uuid, self.MANAGER_PLUGIN, command, args
                )
            )
            raise e

        util.SMlog(
            'call-plugin on {} ({}:{} with {}) returned: {}'.format(
                host_uuid, self.MANAGER_PLUGIN, command, args, ret
            )
        )
        if ret == 'False':
            raise xs_errors.XenError(
                error,
                opterr='Plugin {} failed'.format(self.MANAGER_PLUGIN)
            )

    def _prepare_sr(self, host, group_name, enabled):
        self._exec_manager_command(
            host,
            'prepareSr' if enabled else 'releaseSr',
            {'groupName': group_name},
            'SRUnavailable'
        )

    def _prepare_sr_on_all_hosts(self, group_name, enabled):
        master = util.get_master_ref(self.session)
        self._prepare_sr(master, group_name, enabled)

        for slave in util.get_all_slaves(self.session):
            self._prepare_sr(slave, group_name, enabled)

    def _update_drbd_reactor(self, host, enabled):
        self._exec_manager_command(
            host,
            'updateDrbdReactor',
            {'enabled': str(enabled)},
            'SRUnavailable'
        )

    def _update_drbd_reactor_on_all_hosts(
        self, enabled, controller_node_name=None
    ):
        if controller_node_name == 'localhost':
            controller_node_name = self.session.xenapi.host.get_record(
                util.get_this_host_ref(self.session)
            )['hostname']
            assert controller_node_name
            assert controller_node_name != 'localhost'

        controller_host = None
        secondary_hosts = []

        hosts = self.session.xenapi.host.get_all_records()
        for host_ref, host_rec in hosts.items():
            hostname = host_rec['hostname']
            if controller_node_name == hostname:
                controller_host = host_ref
            else:
                secondary_hosts.append((host_ref, hostname))

        action_name = 'Starting' if enabled else 'Stopping'
        if controller_node_name and not controller_host:
            util.SMlog('Failed to find controller host: `{}`'.format(
                controller_node_name
            ))

        if enabled and controller_host:
            util.SMlog('{} drbd-reactor on controller host `{}`...'.format(
                action_name, controller_node_name
            ))
            # If enabled is true, we try to start the controller on the desired
            # node name first.
            self._update_drbd_reactor(controller_host, enabled)

        for host_ref, hostname in secondary_hosts:
            util.SMlog('{} drbd-reactor on host {}...'.format(
                action_name, hostname
            ))
            self._update_drbd_reactor(host_ref, enabled)

        if not enabled and controller_host:
            util.SMlog('{} drbd-reactor on controller host `{}`...'.format(
                action_name, controller_node_name
            ))
            # If enabled is false, we disable the drbd-reactor service of
            # the controller host last. Why? Otherwise the linstor-controller
            # of other nodes can be started, and we don't want that.
            self._update_drbd_reactor(controller_host, enabled)

    # --------------------------------------------------------------------------
    # Metadata.
    # --------------------------------------------------------------------------

    def _synchronize_metadata_and_xapi(self):
        try:
            # First synch SR parameters.
            self.update(self.uuid)

            # Now update the VDI information in the metadata if required.
            xenapi = self.session.xenapi
            volumes_metadata = self._linstor.get_volumes_with_metadata()
            for vdi_uuid, volume_metadata in volumes_metadata.items():
                try:
                    vdi_ref = xenapi.VDI.get_by_uuid(vdi_uuid)
                except Exception:
                    # May be the VDI is not in XAPI yet dont bother.
                    continue

                label = util.to_plain_string(
                    xenapi.VDI.get_name_label(vdi_ref)
                )
                description = util.to_plain_string(
                    xenapi.VDI.get_name_description(vdi_ref)
                )

                if (
                    volume_metadata.get(NAME_LABEL_TAG) != label or
                    volume_metadata.get(NAME_DESCRIPTION_TAG) != description
                ):
                    self._linstor.update_volume_metadata(vdi_uuid, {
                        NAME_LABEL_TAG: label,
                        NAME_DESCRIPTION_TAG: description
                    })
        except Exception as e:
            raise xs_errors.XenError(
                'MetadataError',
                opterr='Error synching SR Metadata and XAPI: {}'.format(e)
            )

    def _synchronize_metadata(self):
        if not self.is_master():
            return

        util.SMlog('Synchronize metadata...')
        if self.cmd == 'sr_attach':
            try:
                util.SMlog(
                    'Synchronize SR metadata and the state on the storage.'
                )
                self._synchronize_metadata_and_xapi()
            except Exception as e:
                util.SMlog('Failed to synchronize metadata: {}'.format(e))

    # --------------------------------------------------------------------------
    # Stats.
    # --------------------------------------------------------------------------

    def _update_stats(self, virt_alloc_delta):
        valloc = int(self.session.xenapi.SR.get_virtual_allocation(
            self.sr_ref
        ))

        # Update size attributes of the SR parent class.
        self.virtual_allocation = valloc + virt_alloc_delta

        self._update_physical_size()

        # Notify SR parent class.
        self._db_update()

    def _update_physical_size(self):
        # We use the size of the smallest disk, this is an approximation that
        # ensures the displayed physical size is reachable by the user.
        (min_physical_size, pool_count) = self._linstor.get_min_physical_size()
        self.physical_size = min_physical_size * pool_count // \
            self._linstor.redundancy

        self.physical_utilisation = self._linstor.allocated_volume_size

    # --------------------------------------------------------------------------
    # VDIs.
    # --------------------------------------------------------------------------

    def _load_vdis(self):
        if self._vdis_loaded:
            return

        assert self.is_master()

        # We use a cache to avoid repeated JSON parsing.
        # The performance gain is not big but we can still
        # enjoy it with a few lines.
        self._create_linstor_cache()
        self._load_vdis_ex()
        self._destroy_linstor_cache()

        # We must mark VDIs as loaded only if the load is a success.
        self._vdis_loaded = True

        self._undo_all_journal_transactions()

    def _load_vdis_ex(self):
        # 1. Get existing VDIs in XAPI.
        xenapi = self.session.xenapi
        xapi_vdi_uuids = set()
        for vdi in xenapi.SR.get_VDIs(self.sr_ref):
            xapi_vdi_uuids.add(xenapi.VDI.get_uuid(vdi))

        # 2. Get volumes info.
        all_volume_info = self._all_volume_info_cache
        volumes_metadata = self._all_volume_metadata_cache

        # 3. Get CBT vdis.
        # See: https://support.citrix.com/article/CTX230619
        cbt_vdis = set()
        for volume_metadata in volumes_metadata.values():
            cbt_uuid = volume_metadata.get(CBTLOG_TAG)
            if cbt_uuid:
                cbt_vdis.add(cbt_uuid)

        introduce = False

        # Try to introduce VDIs only during scan/attach.
        if self.cmd == 'sr_scan' or self.cmd == 'sr_attach':
            has_clone_entries = list(self._journaler.get_all(
                LinstorJournaler.CLONE
            ).items())

            if has_clone_entries:
                util.SMlog(
                    'Cannot introduce VDIs during scan because it exists '
                    'CLONE entries in journaler on SR {}'.format(self.uuid)
                )
            else:
                introduce = True

        # 4. Now check all volume info.
        vdi_to_snaps = {}
        for vdi_uuid, volume_info in all_volume_info.items():
            if vdi_uuid.startswith(cleanup.SR.TMP_RENAME_PREFIX):
                continue

            # 4.a. Check if the VDI in LINSTOR is in XAPI VDIs.
            if vdi_uuid not in xapi_vdi_uuids:
                if not introduce:
                    continue

                if vdi_uuid.startswith('DELETED_'):
                    continue

                volume_metadata = volumes_metadata.get(vdi_uuid)
                if not volume_metadata:
                    util.SMlog(
                        'Skipping volume {} because no metadata could be found'
                        .format(vdi_uuid)
                    )
                    continue

                util.SMlog(
                    'Trying to introduce VDI {} as it is present in '
                    'LINSTOR and not in XAPI...'
                    .format(vdi_uuid)
                )

                try:
                    self._linstor.get_device_path(vdi_uuid)
                except Exception as e:
                    util.SMlog(
                        'Cannot introduce {}, unable to get path: {}'
                        .format(vdi_uuid, e)
                    )
                    continue

                name_label = volume_metadata.get(NAME_LABEL_TAG) or ''
                type = volume_metadata.get(TYPE_TAG) or 'user'
                vdi_type = volume_metadata.get(VDI_TYPE_TAG)

                if not vdi_type:
                    util.SMlog(
                        'Cannot introduce {} '.format(vdi_uuid) +
                        'without vdi_type'
                    )
                    continue

                sm_config = {
                    'vdi_type': vdi_type
                }

                if vdi_type == vhdutil.VDI_TYPE_RAW:
                    managed = not volume_metadata.get(HIDDEN_TAG)
                elif vdi_type == vhdutil.VDI_TYPE_VHD:
                    vhd_info = self._vhdutil.get_vhd_info(vdi_uuid)
                    managed = not vhd_info.hidden
                    if vhd_info.parentUuid:
                        sm_config['vhd-parent'] = vhd_info.parentUuid
                else:
                    util.SMlog(
                        'Cannot introduce {} with invalid VDI type {}'
                        .format(vdi_uuid, vdi_type)
                    )
                    continue

                util.SMlog(
                    'Introducing VDI {} '.format(vdi_uuid) +
                    ' (name={}, virtual_size={}, allocated_size={})'.format(
                        name_label,
                        volume_info.virtual_size,
                        volume_info.allocated_size
                    )
                )

                vdi_ref = xenapi.VDI.db_introduce(
                    vdi_uuid,
                    name_label,
                    volume_metadata.get(NAME_DESCRIPTION_TAG) or '',
                    self.sr_ref,
                    type,
                    False,  # sharable
                    bool(volume_metadata.get(READ_ONLY_TAG)),
                    {},  # other_config
                    vdi_uuid,  # location
                    {},  # xenstore_data
                    sm_config,
                    managed,
                    str(volume_info.virtual_size),
                    str(volume_info.allocated_size)
                )

                is_a_snapshot = volume_metadata.get(IS_A_SNAPSHOT_TAG)
                xenapi.VDI.set_is_a_snapshot(vdi_ref, bool(is_a_snapshot))
                if is_a_snapshot:
                    xenapi.VDI.set_snapshot_time(
                        vdi_ref,
                        xmlrpc.client.DateTime(
                            volume_metadata[SNAPSHOT_TIME_TAG] or
                            '19700101T00:00:00Z'
                        )
                    )

                    snap_uuid = volume_metadata[SNAPSHOT_OF_TAG]
                    if snap_uuid in vdi_to_snaps:
                        vdi_to_snaps[snap_uuid].append(vdi_uuid)
                    else:
                        vdi_to_snaps[snap_uuid] = [vdi_uuid]

            # 4.b. Add the VDI in the list.
            vdi = self.vdi(vdi_uuid)
            self.vdis[vdi_uuid] = vdi

            if USE_KEY_HASH and vdi.vdi_type == vhdutil.VDI_TYPE_VHD:
                # TODO: Replace pylint comment with this feature when possible:
                # https://github.com/PyCQA/pylint/pull/2926
                vdi.sm_config_override['key_hash'] = \
                    self._vhdutil.get_key_hash(vdi_uuid)  # pylint: disable = E1120

            # 4.c. Update CBT status of disks either just added
            # or already in XAPI.
            cbt_uuid = volume_metadata.get(CBTLOG_TAG)
            if cbt_uuid in cbt_vdis:
                vdi_ref = xenapi.VDI.get_by_uuid(vdi_uuid)
                xenapi.VDI.set_cbt_enabled(vdi_ref, True)
                # For existing VDIs, update local state too.
                # Scan in base class SR updates existing VDIs
                # again based on local states.
                self.vdis[vdi_uuid].cbt_enabled = True
                cbt_vdis.remove(cbt_uuid)

        # 5. Now set the snapshot statuses correctly in XAPI.
        for src_uuid in vdi_to_snaps:
            try:
                src_ref = xenapi.VDI.get_by_uuid(src_uuid)
            except Exception:
                # The source VDI no longer exists, continue.
                continue

            for snap_uuid in vdi_to_snaps[src_uuid]:
                try:
                    # This might fail in cases where its already set.
                    snap_ref = xenapi.VDI.get_by_uuid(snap_uuid)
                    xenapi.VDI.set_snapshot_of(snap_ref, src_ref)
                except Exception as e:
                    util.SMlog('Setting snapshot failed: {}'.format(e))

        # TODO: Check correctly how to use CBT.
        # Update cbt_enabled on the right VDI, check LVM/FileSR code.

        # 6. If we have items remaining in this list,
        # they are cbt_metadata VDI that XAPI doesn't know about.
        # Add them to self.vdis and they'll get added to the DB.
        for cbt_uuid in cbt_vdis:
            new_vdi = self.vdi(cbt_uuid)
            new_vdi.ty = 'cbt_metadata'
            new_vdi.cbt_enabled = True
            self.vdis[cbt_uuid] = new_vdi

        # 7. Update virtual allocation, build geneology and remove useless VDIs
        self.virtual_allocation = 0

        # 8. Build geneology.
        geneology = {}

        for vdi_uuid, vdi in self.vdis.items():
            if vdi.parent:
                if vdi.parent in self.vdis:
                    self.vdis[vdi.parent].read_only = True
                if vdi.parent in geneology:
                    geneology[vdi.parent].append(vdi_uuid)
                else:
                    geneology[vdi.parent] = [vdi_uuid]
            if not vdi.hidden:
                self.virtual_allocation += vdi.size

        # 9. Remove all hidden leaf nodes to avoid introducing records that
        # will be GC'ed.
        for vdi_uuid in list(self.vdis.keys()):
            if vdi_uuid not in geneology and self.vdis[vdi_uuid].hidden:
                util.SMlog(
                    'Scan found hidden leaf ({}), ignoring'.format(vdi_uuid)
                )
                del self.vdis[vdi_uuid]

    # --------------------------------------------------------------------------
    # Journals.
    # --------------------------------------------------------------------------

    def _get_vdi_path_and_parent(self, vdi_uuid, volume_name):
        try:
            device_path = self._linstor.build_device_path(volume_name)
            if not util.pathexists(device_path):
                return (None, None)

            # If it's a RAW VDI, there is no parent.
            volume_metadata = self._linstor.get_volume_metadata(vdi_uuid)
            vdi_type = volume_metadata[VDI_TYPE_TAG]
            if vdi_type == vhdutil.VDI_TYPE_RAW:
                return (device_path, None)

            # Otherwise it's a VHD and a parent can exist.
            if not self._vhdutil.check(vdi_uuid):
                return (None, None)

            vhd_info = self._vhdutil.get_vhd_info(vdi_uuid)
            if vhd_info:
                return (device_path, vhd_info.parentUuid)
        except Exception as e:
            util.SMlog(
                'Failed to get VDI path and parent, ignoring: {}'
                .format(e)
            )
        return (None, None)

    def _undo_all_journal_transactions(self):
        util.SMlog('Undoing all journal transactions...')
        self.lock.acquire()
        try:
            self._handle_interrupted_inflate_ops()
            self._handle_interrupted_clone_ops()
            pass
        finally:
            self.lock.release()

    def _handle_interrupted_inflate_ops(self):
        transactions = self._journaler.get_all(LinstorJournaler.INFLATE)
        for vdi_uuid, old_size in transactions.items():
            self._handle_interrupted_inflate(vdi_uuid, old_size)
            self._journaler.remove(LinstorJournaler.INFLATE, vdi_uuid)

    def _handle_interrupted_clone_ops(self):
        transactions = self._journaler.get_all(LinstorJournaler.CLONE)
        for vdi_uuid, old_size in transactions.items():
            self._handle_interrupted_clone(vdi_uuid, old_size)
            self._journaler.remove(LinstorJournaler.CLONE, vdi_uuid)

    def _handle_interrupted_inflate(self, vdi_uuid, old_size):
        util.SMlog(
            '*** INTERRUPTED INFLATE OP: for {} ({})'
            .format(vdi_uuid, old_size)
        )

        vdi = self.vdis.get(vdi_uuid)
        if not vdi:
            util.SMlog('Cannot deflate missing VDI {}'.format(vdi_uuid))
            return

        assert not self._all_volume_info_cache
        volume_info = self._linstor.get_volume_info(vdi_uuid)

        current_size = volume_info.virtual_size
        assert current_size > 0
        self._vhdutil.force_deflate(vdi.path, old_size, current_size, zeroize=True)

    def _handle_interrupted_clone(
        self, vdi_uuid, clone_info, force_undo=False
    ):
        util.SMlog(
            '*** INTERRUPTED CLONE OP: for {} ({})'
            .format(vdi_uuid, clone_info)
        )

        base_uuid, snap_uuid = clone_info.split('_')

        # Use LINSTOR data because new VDIs may not be in the XAPI.
        volume_names = self._linstor.get_volumes_with_name()

        # Check if we don't have a base VDI. (If clone failed at startup.)
        if base_uuid not in volume_names:
            if vdi_uuid in volume_names:
                util.SMlog('*** INTERRUPTED CLONE OP: nothing to do')
                return
            raise util.SMException(
                'Base copy {} not present, but no original {} found'
                .format(base_uuid, vdi_uuid)
            )

        if force_undo:
            util.SMlog('Explicit revert')
            self._undo_clone(
                 volume_names, vdi_uuid, base_uuid, snap_uuid
            )
            return

        # If VDI or snap uuid is missing...
        if vdi_uuid not in volume_names or \
                (snap_uuid and snap_uuid not in volume_names):
            util.SMlog('One or both leaves missing => revert')
            self._undo_clone(volume_names, vdi_uuid, base_uuid, snap_uuid)
            return

        vdi_path, vdi_parent_uuid = self._get_vdi_path_and_parent(
            vdi_uuid, volume_names[vdi_uuid]
        )
        snap_path, snap_parent_uuid = self._get_vdi_path_and_parent(
            snap_uuid, volume_names[snap_uuid]
        )

        if not vdi_path or (snap_uuid and not snap_path):
            util.SMlog('One or both leaves invalid (and path(s)) => revert')
            self._undo_clone(volume_names, vdi_uuid, base_uuid, snap_uuid)
            return

        util.SMlog('Leaves valid but => revert')
        self._undo_clone(volume_names, vdi_uuid, base_uuid, snap_uuid)

    def _undo_clone(self, volume_names, vdi_uuid, base_uuid, snap_uuid):
        base_path = self._linstor.build_device_path(volume_names[base_uuid])
        base_metadata = self._linstor.get_volume_metadata(base_uuid)
        base_type = base_metadata[VDI_TYPE_TAG]

        if not util.pathexists(base_path):
            util.SMlog('Base not found! Exit...')
            util.SMlog('*** INTERRUPTED CLONE OP: rollback fail')
            return

        # Un-hide the parent.
        self._linstor.update_volume_metadata(base_uuid, {READ_ONLY_TAG: False})
        if base_type == vhdutil.VDI_TYPE_VHD:
            vhd_info = self._vhdutil.get_vhd_info(base_uuid, False)
            if vhd_info.hidden:
                self._vhdutil.set_hidden(base_path, False)
        elif base_type == vhdutil.VDI_TYPE_RAW and \
                base_metadata.get(HIDDEN_TAG):
            self._linstor.update_volume_metadata(
                base_uuid, {HIDDEN_TAG: False}
            )

        # Remove the child nodes.
        if snap_uuid and snap_uuid in volume_names:
            util.SMlog('Destroying snap {}...'.format(snap_uuid))

            try:
                self._linstor.destroy_volume(snap_uuid)
            except Exception as e:
                util.SMlog(
                    'Cannot destroy snap {} during undo clone: {}'
                    .format(snap_uuid, e)
                )

        if vdi_uuid in volume_names:
            try:
                util.SMlog('Destroying {}...'.format(vdi_uuid))
                self._linstor.destroy_volume(vdi_uuid)
            except Exception as e:
                util.SMlog(
                    'Cannot destroy VDI {} during undo clone: {}'
                    .format(vdi_uuid, e)
                )
                # We can get an exception like this:
                # "Shutdown of the DRBD resource 'XXX failed", so the
                # volume info remains... The problem is we can't rename
                # properly the base VDI below this line, so we must change the
                # UUID of this bad VDI before.
                self._linstor.update_volume_uuid(
                    vdi_uuid, 'DELETED_' + vdi_uuid, force=True
                )

        # Rename!
        self._linstor.update_volume_uuid(base_uuid, vdi_uuid)

        # Inflate to the right size.
        if base_type == vhdutil.VDI_TYPE_VHD:
            vdi = self.vdi(vdi_uuid)
            volume_size = LinstorVhdUtil.compute_volume_size(vdi.size, vdi.vdi_type)
            self._vhdutil.inflate(
                self._journaler, vdi_uuid, vdi.path,
                volume_size, vdi.capacity
            )
            self.vdis[vdi_uuid] = vdi

        # At this stage, tapdisk and SM vdi will be in paused state. Remove
        # flag to facilitate vm deactivate.
        vdi_ref = self.session.xenapi.VDI.get_by_uuid(vdi_uuid)
        self.session.xenapi.VDI.remove_from_sm_config(vdi_ref, 'paused')

        util.SMlog('*** INTERRUPTED CLONE OP: rollback success')

    # --------------------------------------------------------------------------
    # Cache.
    # --------------------------------------------------------------------------

    def _create_linstor_cache(self):
        reconnect = False

        def create_cache():
            nonlocal reconnect
            try:
                if reconnect:
                    self._reconnect()
                return self._linstor.get_volumes_with_info()
            except Exception as e:
                reconnect = True
                raise e

        self._all_volume_metadata_cache = \
            self._linstor.get_volumes_with_metadata()
        self._all_volume_info_cache = util.retry(
            create_cache,
            maxretry=10,
            period=3
        )

    def _destroy_linstor_cache(self):
        self._all_volume_info_cache = None
        self._all_volume_metadata_cache = None

    # --------------------------------------------------------------------------
    # Misc.
    # --------------------------------------------------------------------------

    def _reconnect(self):
        controller_uri = get_controller_uri()

        self._journaler = LinstorJournaler(
            controller_uri, self._group_name, logger=util.SMlog
        )

        # Try to open SR if exists.
        # We can repair only if we are on the master AND if
        # we are trying to execute an exclusive operation.
        # Otherwise we could try to delete a VDI being created or
        # during a snapshot. An exclusive op is the guarantee that
        # the SR is locked.
        self._linstor = LinstorVolumeManager(
            controller_uri,
            self._group_name,
            repair=(
                self.is_master() and
                self.srcmd.cmd in self.ops_exclusive
            ),
            logger=util.SMlog
        )
        self._vhdutil = LinstorVhdUtil(self.session, self._linstor)

    def _ensure_space_available(self, amount_needed):
        space_available = self._linstor.max_volume_size_allowed
        if (space_available < amount_needed):
            util.SMlog(
                'Not enough space! Free space: {}, need: {}'.format(
                    space_available, amount_needed
                )
            )
            raise xs_errors.XenError('SRNoSpace')

    def _kick_gc(self):
        # Don't bother if an instance already running. This is just an
        # optimization to reduce the overhead of forking a new process if we
        # don't have to, but the process will check the lock anyways.
        lock = Lock(LOCK_TYPE_GC_RUNNING, self.uuid)
        if not lock.acquireNoblock():
            if not cleanup.should_preempt(self.session, self.uuid):
                util.SMlog('A GC instance already running, not kicking')
                return

            util.SMlog('Aborting currently-running coalesce of garbage VDI')
            try:
                if not cleanup.abort(self.uuid, soft=True):
                    util.SMlog('The GC has already been scheduled to re-start')
            except util.CommandException as e:
                if e.code != errno.ETIMEDOUT:
                    raise
                util.SMlog('Failed to abort the GC')
        else:
            lock.release()

        util.SMlog('Kicking GC')
        cleanup.gc(self.session, self.uuid, True)

# ==============================================================================
# LinstorSr VDI
# ==============================================================================


class LinstorVDI(VDI.VDI):
    # Warning: Not the same values than vhdutil.VDI_TYPE_*.
    # These values represents the types given on the command line.
    TYPE_RAW = 'raw'
    TYPE_VHD = 'vhd'

    # Metadata size given to the "S" param of vhd-util create.
    # "-S size (MB) for metadata preallocation".
    # Increase the performance when resize is called.
    MAX_METADATA_VIRT_SIZE = 2 * 1024 * 1024

    # --------------------------------------------------------------------------
    # VDI methods.
    # --------------------------------------------------------------------------

    def load(self, vdi_uuid):
        self._lock = self.sr.lock
        self._exists = True
        self._linstor = self.sr._linstor

        # Update hidden parent property.
        self.hidden = False

        def raise_bad_load(e):
            util.SMlog(
                'Got exception in LinstorVDI.load: {}'.format(e)
            )
            util.SMlog(traceback.format_exc())
            raise xs_errors.XenError(
                'VDIUnavailable',
                opterr='Could not load {} because: {}'.format(self.uuid, e)
            )

        #  Try to load VDI.
        try:
            if (
                self.sr.srcmd.cmd == 'vdi_attach_from_config' or
                self.sr.srcmd.cmd == 'vdi_detach_from_config'
            ):
                self.vdi_type = vhdutil.VDI_TYPE_RAW
                self.path = self.sr.srcmd.params['vdi_path']
            else:
                self._determine_type_and_path()
                self._load_this()

            util.SMlog('VDI {} loaded! (path={}, hidden={})'.format(
                self.uuid, self.path, self.hidden
            ))
        except LinstorVolumeManagerError as e:
            # 1. It may be a VDI deletion.
            if e.code == LinstorVolumeManagerError.ERR_VOLUME_NOT_EXISTS:
                if self.sr.srcmd.cmd == 'vdi_delete':
                    self.deleted = True
                    return

            # 2. Or maybe a creation.
            if self.sr.srcmd.cmd == 'vdi_create':
                # Set type attribute of VDI parent class.
                # We use VHD by default.
                self.vdi_type = vhdutil.VDI_TYPE_VHD
                self._key_hash = None  # Only used in create.

                self._exists = False
                vdi_sm_config = self.sr.srcmd.params.get('vdi_sm_config')
                if vdi_sm_config is not None:
                    type = vdi_sm_config.get('type')
                    if type is not None:
                        if type == self.TYPE_RAW:
                            self.vdi_type = vhdutil.VDI_TYPE_RAW
                        elif type == self.TYPE_VHD:
                            self.vdi_type = vhdutil.VDI_TYPE_VHD
                        else:
                            raise xs_errors.XenError(
                                'VDICreate',
                                opterr='Invalid VDI type {}'.format(type)
                            )
                    if self.vdi_type == vhdutil.VDI_TYPE_VHD:
                        self._key_hash = vdi_sm_config.get('key_hash')

                # For the moment we don't have a path.
                self._update_device_name(None)
                return
            raise_bad_load(e)
        except Exception as e:
            raise_bad_load(e)

    def create(self, sr_uuid, vdi_uuid, size):
        # Usage example:
        # xe vdi-create sr-uuid=39a5826b-5a90-73eb-dd09-51e3a116f937
        # name-label="linstor-vdi-1" virtual-size=4096MiB sm-config:type=vhd

        # 1. Check if we are on the master and if the VDI doesn't exist.
        util.SMlog('LinstorVDI.create for {}'.format(self.uuid))
        if self._exists:
            raise xs_errors.XenError('VDIExists')

        assert self.uuid
        assert self.ty
        assert self.vdi_type

        # 2. Compute size and check space available.
        size = vhdutil.validate_and_round_vhd_size(int(size))
        volume_size = LinstorVhdUtil.compute_volume_size(size, self.vdi_type)
        util.SMlog(
            'LinstorVDI.create: type={}, vhd-size={}, volume-size={}'
            .format(self.vdi_type, size, volume_size)
        )
        self.sr._ensure_space_available(volume_size)

        # 3. Set sm_config attribute of VDI parent class.
        self.sm_config = self.sr.srcmd.params['vdi_sm_config']

        # 4. Create!
        failed = False
        try:
            volume_name = None
            if self.ty == 'ha_statefile':
                volume_name = HA_VOLUME_NAME
            elif self.ty == 'redo_log':
                volume_name = REDO_LOG_VOLUME_NAME

            self._linstor.create_volume(
                self.uuid,
                volume_size,
                persistent=False,
                volume_name=volume_name,
                high_availability=volume_name is not None
            )
            volume_info = self._linstor.get_volume_info(self.uuid)

            self._update_device_name(volume_info.name)

            if self.vdi_type == vhdutil.VDI_TYPE_RAW:
                self.size = volume_info.virtual_size
            else:
                self.sr._vhdutil.create(
                    self.path, size, False, self.MAX_METADATA_VIRT_SIZE
                )
                self.size = self.sr._vhdutil.get_size_virt(self.uuid)

            if self._key_hash:
                self.sr._vhdutil.set_key(self.path, self._key_hash)

            # Because vhdutil commands modify the volume data,
            # we must retrieve a new time the utilization size.
            volume_info = self._linstor.get_volume_info(self.uuid)

            volume_metadata = {
                NAME_LABEL_TAG: util.to_plain_string(self.label),
                NAME_DESCRIPTION_TAG: util.to_plain_string(self.description),
                IS_A_SNAPSHOT_TAG: False,
                SNAPSHOT_OF_TAG: '',
                SNAPSHOT_TIME_TAG: '',
                TYPE_TAG: self.ty,
                VDI_TYPE_TAG: self.vdi_type,
                READ_ONLY_TAG: bool(self.read_only),
                METADATA_OF_POOL_TAG: ''
            }
            self._linstor.set_volume_metadata(self.uuid, volume_metadata)

            # Set the open timeout to 1min to reduce CPU usage
            # in http-disk-server when a secondary server tries to open
            # an already opened volume.
            if self.ty == 'ha_statefile' or self.ty == 'redo_log':
                self._linstor.set_auto_promote_timeout(self.uuid, 600)

            self._linstor.mark_volume_as_persistent(self.uuid)
        except util.CommandException as e:
            failed = True
            raise xs_errors.XenError(
                'VDICreate', opterr='error {}'.format(e.code)
            )
        except Exception as e:
            failed = True
            raise xs_errors.XenError('VDICreate', opterr='error {}'.format(e))
        finally:
            if failed:
                util.SMlog('Unable to create VDI {}'.format(self.uuid))
                try:
                    self._linstor.destroy_volume(self.uuid)
                except Exception as e:
                    util.SMlog(
                        'Ignoring exception after fail in LinstorVDI.create: '
                        '{}'.format(e)
                    )

        self.utilisation = volume_info.allocated_size
        self.sm_config['vdi_type'] = self.vdi_type

        self.ref = self._db_introduce()
        self.sr._update_stats(self.size)

        return VDI.VDI.get_params(self)

    def delete(self, sr_uuid, vdi_uuid, data_only=False):
        util.SMlog('LinstorVDI.delete for {}'.format(self.uuid))
        if self.attached:
            raise xs_errors.XenError('VDIInUse')

        if self.deleted:
            return super(LinstorVDI, self).delete(
                sr_uuid, vdi_uuid, data_only
            )

        vdi_ref = self.sr.srcmd.params['vdi_ref']
        if not self.session.xenapi.VDI.get_managed(vdi_ref):
            raise xs_errors.XenError(
                'VDIDelete',
                opterr='Deleting non-leaf node not permitted'
            )

        try:
            # Remove from XAPI and delete from LINSTOR.
            self._linstor.destroy_volume(self.uuid)
            if not data_only:
                self._db_forget()

            self.sr.lock.cleanupAll(vdi_uuid)
        except Exception as e:
            util.SMlog(
                'Failed to remove the volume (maybe is leaf coalescing) '
                'for {} err: {}'.format(self.uuid, e)
            )

            try:
                raise xs_errors.XenError('VDIDelete', opterr=str(e))
            except LinstorVolumeManagerError as e:
                if e.code != LinstorVolumeManagerError.ERR_VOLUME_DESTROY:
                    raise xs_errors.XenError('VDIDelete', opterr=str(e))

            return

        if self.uuid in self.sr.vdis:
            del self.sr.vdis[self.uuid]

        # TODO: Check size after delete.
        self.sr._update_stats(-self.size)
        self.sr._kick_gc()
        return super(LinstorVDI, self).delete(sr_uuid, vdi_uuid, data_only)

    def attach(self, sr_uuid, vdi_uuid):
        util.SMlog('LinstorVDI.attach for {}'.format(self.uuid))
        attach_from_config = self.sr.srcmd.cmd == 'vdi_attach_from_config'
        if (
            not attach_from_config or
            self.sr.srcmd.params['vdi_uuid'] != self.uuid
        ) and self.sr._journaler.has_entries(self.uuid):
            raise xs_errors.XenError(
                'VDIUnavailable',
                opterr='Interrupted operation detected on this VDI, '
                'scan SR first to trigger auto-repair'
            )

        writable = 'args' not in self.sr.srcmd.params or \
            self.sr.srcmd.params['args'][0] == 'true'

        if not attach_from_config or self.sr.is_master():
            # We need to inflate the volume if we don't have enough place
            # to mount the VHD image. I.e. the volume capacity must be greater
            # than the VHD size + bitmap size.
            need_inflate = True
            if (
                self.vdi_type == vhdutil.VDI_TYPE_RAW or
                not writable or
                self.capacity >= LinstorVhdUtil.compute_volume_size(self.size, self.vdi_type)
            ):
                need_inflate = False

            if need_inflate:
                try:
                    self._prepare_thin(True)
                except Exception as e:
                    raise xs_errors.XenError(
                        'VDIUnavailable',
                        opterr='Failed to attach VDI during "prepare thin": {}'
                        .format(e)
                    )

        if not hasattr(self, 'xenstore_data'):
            self.xenstore_data = {}
        self.xenstore_data['storage-type'] = LinstorSR.DRIVER_TYPE

        if (
            USE_HTTP_NBD_SERVERS and
            attach_from_config and
            self.path.startswith('/dev/http-nbd/')
        ):
            return self._attach_using_http_nbd()

        # Ensure we have a path...
        self.sr._vhdutil.create_chain_paths(self.uuid, readonly=not writable)

        self.attached = True
        return VDI.VDI.attach(self, self.sr.uuid, self.uuid)

    def detach(self, sr_uuid, vdi_uuid):
        util.SMlog('LinstorVDI.detach for {}'.format(self.uuid))
        detach_from_config = self.sr.srcmd.cmd == 'vdi_detach_from_config'
        self.attached = False

        if detach_from_config and self.path.startswith('/dev/http-nbd/'):
            return self._detach_using_http_nbd()

        if self.vdi_type == vhdutil.VDI_TYPE_RAW:
            return

        # The VDI is already deflated if the VHD image size + metadata is
        # equal to the LINSTOR volume size.
        volume_size = LinstorVhdUtil.compute_volume_size(self.size, self.vdi_type)
        already_deflated = self.capacity <= volume_size

        if already_deflated:
            util.SMlog(
                'VDI {} already deflated (old volume size={}, volume size={})'
                .format(self.uuid, self.capacity, volume_size)
            )

        need_deflate = True
        if already_deflated:
            need_deflate = False
        elif self.sr._provisioning == 'thick':
            need_deflate = False

            vdi_ref = self.sr.srcmd.params['vdi_ref']
            if self.session.xenapi.VDI.get_is_a_snapshot(vdi_ref):
                need_deflate = True

        if need_deflate:
            try:
                self._prepare_thin(False)
            except Exception as e:
                raise xs_errors.XenError(
                    'VDIUnavailable',
                    opterr='Failed to detach VDI during "prepare thin": {}'
                    .format(e)
                )

        # We remove only on slaves because the volume can be used by the GC.
        if self.sr.is_master():
            return

        while vdi_uuid:
            try:
                path = self._linstor.build_device_path(self._linstor.get_volume_name(vdi_uuid))
                parent_vdi_uuid = self.sr._vhdutil.get_vhd_info(vdi_uuid).parentUuid
            except Exception:
                break

            if util.pathexists(path):
                try:
                    self._linstor.remove_volume_if_diskless(vdi_uuid)
                except Exception as e:
                    # Ensure we can always detach properly.
                    # I don't want to corrupt the XAPI info.
                    util.SMlog('Failed to clean VDI {} during detach: {}'.format(vdi_uuid, e))
            vdi_uuid = parent_vdi_uuid

    def resize(self, sr_uuid, vdi_uuid, size):
        util.SMlog('LinstorVDI.resize for {}'.format(self.uuid))
        if not self.sr.is_master():
            raise xs_errors.XenError(
                'VDISize',
                opterr='resize on slave not allowed'
            )

        if self.hidden:
            raise xs_errors.XenError('VDIUnavailable', opterr='hidden VDI')

        # Compute the virtual VHD and DRBD volume size.
        size = vhdutil.validate_and_round_vhd_size(int(size))
        volume_size = LinstorVhdUtil.compute_volume_size(size, self.vdi_type)
        util.SMlog(
            'LinstorVDI.resize: type={}, vhd-size={}, volume-size={}'
            .format(self.vdi_type, size, volume_size)
        )

        if size < self.size:
            util.SMlog(
                'vdi_resize: shrinking not supported: '
                '(current size: {}, new size: {})'.format(self.size, size)
            )
            raise xs_errors.XenError('VDISize', opterr='shrinking not allowed')

        if size == self.size:
            return VDI.VDI.get_params(self)

        if self.vdi_type == vhdutil.VDI_TYPE_RAW:
            old_volume_size = self.size
            new_volume_size = LinstorVolumeManager.round_up_volume_size(size)
        else:
            old_volume_size = self.utilisation
            if self.sr._provisioning == 'thin':
                # VDI is currently deflated, so keep it deflated.
                new_volume_size = old_volume_size
            else:
                new_volume_size = LinstorVhdUtil.compute_volume_size(size, self.vdi_type)
        assert new_volume_size >= old_volume_size

        space_needed = new_volume_size - old_volume_size
        self.sr._ensure_space_available(space_needed)

        old_size = self.size
        if self.vdi_type == vhdutil.VDI_TYPE_RAW:
            self._linstor.resize(self.uuid, new_volume_size)
        else:
            if new_volume_size != old_volume_size:
                self.sr._vhdutil.inflate(
                    self.sr._journaler, self.uuid, self.path,
                    new_volume_size, old_volume_size
                )
            self.sr._vhdutil.set_size_virt_fast(self.path, size)

        # Reload size attributes.
        self._load_this()

        vdi_ref = self.sr.srcmd.params['vdi_ref']
        self.session.xenapi.VDI.set_virtual_size(vdi_ref, str(self.size))
        self.session.xenapi.VDI.set_physical_utilisation(
            vdi_ref, str(self.utilisation)
        )
        self.sr._update_stats(self.size - old_size)
        return VDI.VDI.get_params(self)

    def clone(self, sr_uuid, vdi_uuid):
        return self._do_snapshot(sr_uuid, vdi_uuid, VDI.SNAPSHOT_DOUBLE)

    def compose(self, sr_uuid, vdi1, vdi2):
        util.SMlog('VDI.compose for {} -> {}'.format(vdi2, vdi1))
        if self.vdi_type != vhdutil.VDI_TYPE_VHD:
            raise xs_errors.XenError('Unimplemented')

        parent_uuid = vdi1
        parent_path = self._linstor.get_device_path(parent_uuid)

        # We must pause tapdisk to correctly change the parent. Otherwise we
        # have a readonly error.
        # See: https://github.com/xapi-project/xen-api/blob/b3169a16d36dae0654881b336801910811a399d9/ocaml/xapi/storage_migrate.ml#L928-L929
        # and: https://github.com/xapi-project/xen-api/blob/b3169a16d36dae0654881b336801910811a399d9/ocaml/xapi/storage_migrate.ml#L775

        if not blktap2.VDI.tap_pause(self.session, self.sr.uuid, self.uuid):
            raise util.SMException('Failed to pause VDI {}'.format(self.uuid))
        try:
            self.sr._vhdutil.set_parent(self.path, parent_path, False)
            self.sr._vhdutil.set_hidden(parent_path)
            self.sr.session.xenapi.VDI.set_managed(
                self.sr.srcmd.params['args'][0], False
            )
        finally:
            blktap2.VDI.tap_unpause(self.session, self.sr.uuid, self.uuid)

        if not blktap2.VDI.tap_refresh(self.session, self.sr.uuid, self.uuid):
            raise util.SMException(
                'Failed to refresh VDI {}'.format(self.uuid)
            )

        util.SMlog('Compose done')

    def generate_config(self, sr_uuid, vdi_uuid):
        """
        Generate the XML config required to attach and activate
        a VDI for use when XAPI is not running. Attach and
        activation is handled by vdi_attach_from_config below.
        """

        util.SMlog('LinstorVDI.generate_config for {}'.format(self.uuid))

        resp = {}
        resp['device_config'] = self.sr.dconf
        resp['sr_uuid'] = sr_uuid
        resp['vdi_uuid'] = self.uuid
        resp['sr_sm_config'] = self.sr.sm_config
        resp['command'] = 'vdi_attach_from_config'

        # By default, we generate a normal config.
        # But if the disk is persistent, we must use a HTTP/NBD
        # server to ensure we can always write or read data.
        # Why? DRBD is unsafe when used with more than 4 hosts:
        # We are limited to use 1 diskless and 3 full.
        # We can't increase this limitation, so we use a NBD/HTTP device
        # instead.
        volume_name = self._linstor.get_volume_name(self.uuid)
        if not USE_HTTP_NBD_SERVERS or volume_name not in [
            HA_VOLUME_NAME, REDO_LOG_VOLUME_NAME
        ]:
            if not self.path or not util.pathexists(self.path):
                available = False
                # Try to refresh symlink path...
                try:
                    self.path = self._linstor.get_device_path(vdi_uuid)
                    available = util.pathexists(self.path)
                except Exception:
                    pass
                if not available:
                    raise xs_errors.XenError('VDIUnavailable')

            resp['vdi_path'] = self.path
        else:
            # Axiom: DRBD device is present on at least one host.
            resp['vdi_path'] = '/dev/http-nbd/' + volume_name

        config = xmlrpc.client.dumps(tuple([resp]), 'vdi_attach_from_config')
        return xmlrpc.client.dumps((config,), "", True)

    def attach_from_config(self, sr_uuid, vdi_uuid):
        """
        Attach and activate a VDI using config generated by
        vdi_generate_config above. This is used for cases such as
        the HA state-file and the redo-log.
        """

        util.SMlog('LinstorVDI.attach_from_config for {}'.format(vdi_uuid))

        try:
            if not util.pathexists(self.sr.path):
                self.sr.attach(sr_uuid)

            if not DRIVER_CONFIG['ATTACH_FROM_CONFIG_WITH_TAPDISK']:
                return self.attach(sr_uuid, vdi_uuid)
        except Exception:
            util.logException('LinstorVDI.attach_from_config')
            raise xs_errors.XenError(
                'SRUnavailable',
                opterr='Unable to attach from config'
            )

    def reset_leaf(self, sr_uuid, vdi_uuid):
        if self.vdi_type != vhdutil.VDI_TYPE_VHD:
            raise xs_errors.XenError('Unimplemented')

        if not self.sr._vhdutil.has_parent(self.uuid):
            raise util.SMException(
                'ERROR: VDI {} has no parent, will not reset contents'
                .format(self.uuid)
            )

        self.sr._vhdutil.kill_data(self.path)

    def _load_this(self):
        volume_metadata = None
        if self.sr._all_volume_metadata_cache:
            volume_metadata = self.sr._all_volume_metadata_cache.get(self.uuid)
        if volume_metadata is None:
            volume_metadata = self._linstor.get_volume_metadata(self.uuid)

        volume_info = None
        if self.sr._all_volume_info_cache:
            volume_info = self.sr._all_volume_info_cache.get(self.uuid)
        if volume_info is None:
            volume_info = self._linstor.get_volume_info(self.uuid)

        # Contains the max physical size used on a disk.
        # When LINSTOR LVM driver is used, the size should be similar to
        # virtual size (i.e. the LINSTOR max volume size).
        # When LINSTOR Thin LVM driver is used, the used physical size should
        # be lower than virtual size at creation.
        # The physical size increases after each write in a new block.
        self.utilisation = volume_info.allocated_size
        self.capacity = volume_info.virtual_size

        if self.vdi_type == vhdutil.VDI_TYPE_RAW:
            self.hidden = int(volume_metadata.get(HIDDEN_TAG) or 0)
            self.size = volume_info.virtual_size
            self.parent = ''
        else:
            vhd_info = self.sr._vhdutil.get_vhd_info(self.uuid)
            self.hidden = vhd_info.hidden
            self.size = vhd_info.sizeVirt
            self.parent = vhd_info.parentUuid

        if self.hidden:
            self.managed = False

        self.label = volume_metadata.get(NAME_LABEL_TAG) or ''
        self.description = volume_metadata.get(NAME_DESCRIPTION_TAG) or ''

        # Update sm_config_override of VDI parent class.
        self.sm_config_override = {'vhd-parent': self.parent or None}

    def _mark_hidden(self, hidden=True):
        if self.hidden == hidden:
            return

        if self.vdi_type == vhdutil.VDI_TYPE_VHD:
            self.sr._vhdutil.set_hidden(self.path, hidden)
        else:
            self._linstor.update_volume_metadata(self.uuid, {
                HIDDEN_TAG: hidden
            })
        self.hidden = hidden

    def update(self, sr_uuid, vdi_uuid):
        xenapi = self.session.xenapi
        vdi_ref = xenapi.VDI.get_by_uuid(self.uuid)

        volume_metadata = {
            NAME_LABEL_TAG: util.to_plain_string(
                xenapi.VDI.get_name_label(vdi_ref)
            ),
            NAME_DESCRIPTION_TAG: util.to_plain_string(
                xenapi.VDI.get_name_description(vdi_ref)
            )
        }

        try:
            self._linstor.update_volume_metadata(self.uuid, volume_metadata)
        except LinstorVolumeManagerError as e:
            if e.code == LinstorVolumeManagerError.ERR_VOLUME_NOT_EXISTS:
                raise xs_errors.XenError(
                    'VDIUnavailable',
                    opterr='LINSTOR volume {} not found'.format(self.uuid)
                )
            raise xs_errors.XenError('VDIUnavailable', opterr=str(e))

    # --------------------------------------------------------------------------
    # Thin provisioning.
    # --------------------------------------------------------------------------

    def _prepare_thin(self, attach):
        if self.sr.is_master():
            if attach:
                attach_thin(
                    self.session, self.sr._journaler, self._linstor,
                    self.sr.uuid, self.uuid
                )
            else:
                detach_thin(
                    self.session, self._linstor, self.sr.uuid, self.uuid
                )
        else:
            fn = 'attach' if attach else 'detach'

            master = util.get_master_ref(self.session)

            args = {
                'groupName': self.sr._group_name,
                'srUuid': self.sr.uuid,
                'vdiUuid': self.uuid
            }

            try:
                self.sr._exec_manager_command(master, fn, args, 'VDIUnavailable')
            except Exception:
                if fn != 'detach':
                    raise

        # Reload size attrs after inflate or deflate!
        self._load_this()
        self.sr._update_physical_size()

        vdi_ref = self.sr.srcmd.params['vdi_ref']
        self.session.xenapi.VDI.set_physical_utilisation(
            vdi_ref, str(self.utilisation)
        )

        self.session.xenapi.SR.set_physical_utilisation(
            self.sr.sr_ref, str(self.sr.physical_utilisation)
        )

    # --------------------------------------------------------------------------
    # Generic helpers.
    # --------------------------------------------------------------------------

    def _determine_type_and_path(self):
        """
        Determine whether this is a RAW or a VHD VDI.
        """

        # 1. Check vdi_ref and vdi_type in config.
        try:
            vdi_ref = self.session.xenapi.VDI.get_by_uuid(self.uuid)
            if vdi_ref:
                sm_config = self.session.xenapi.VDI.get_sm_config(vdi_ref)
                vdi_type = sm_config.get('vdi_type')
                if vdi_type:
                    # Update parent fields.
                    self.vdi_type = vdi_type
                    self.sm_config_override = sm_config
                    self._update_device_name(
                        self._linstor.get_volume_name(self.uuid)
                    )
                    return
        except Exception:
            pass

        # 2. Otherwise use the LINSTOR volume manager directly.
        # It's probably a new VDI created via snapshot.
        volume_metadata = self._linstor.get_volume_metadata(self.uuid)
        self.vdi_type = volume_metadata.get(VDI_TYPE_TAG)
        if not self.vdi_type:
            raise xs_errors.XenError(
                'VDIUnavailable',
                opterr='failed to get vdi_type in metadata'
            )
        self._update_device_name(self._linstor.get_volume_name(self.uuid))

    def _update_device_name(self, device_name):
        self._device_name = device_name

        # Mark path of VDI parent class.
        if device_name:
            self.path = self._linstor.build_device_path(self._device_name)
        else:
            self.path = None

    def _create_snapshot(self, snap_uuid, snap_of_uuid=None):
        """
        Snapshot self and return the snapshot VDI object.
        """

        # 1. Create a new LINSTOR volume with the same size than self.
        snap_path = self._linstor.shallow_clone_volume(
            self.uuid, snap_uuid, persistent=False
        )

        # 2. Write the snapshot content.
        is_raw = (self.vdi_type == vhdutil.VDI_TYPE_RAW)
        self.sr._vhdutil.snapshot(
            snap_path, self.path, is_raw, self.MAX_METADATA_VIRT_SIZE
        )

        # 3. Get snapshot parent.
        snap_parent = self.sr._vhdutil.get_parent(snap_uuid)

        # 4. Update metadata.
        util.SMlog('Set VDI {} metadata of snapshot'.format(snap_uuid))
        volume_metadata = {
            NAME_LABEL_TAG: util.to_plain_string(self.label),
            NAME_DESCRIPTION_TAG: util.to_plain_string(self.description),
            IS_A_SNAPSHOT_TAG: bool(snap_of_uuid),
            SNAPSHOT_OF_TAG: snap_of_uuid,
            SNAPSHOT_TIME_TAG: '',
            TYPE_TAG: self.ty,
            VDI_TYPE_TAG: vhdutil.VDI_TYPE_VHD,
            READ_ONLY_TAG: False,
            METADATA_OF_POOL_TAG: ''
        }
        self._linstor.set_volume_metadata(snap_uuid, volume_metadata)

        # 5. Set size.
        snap_vdi = LinstorVDI(self.sr, snap_uuid)
        if not snap_vdi._exists:
            raise xs_errors.XenError('VDISnapshot')

        volume_info = self._linstor.get_volume_info(snap_uuid)

        snap_vdi.size = self.sr._vhdutil.get_size_virt(snap_uuid)
        snap_vdi.utilisation = volume_info.allocated_size

        # 6. Update sm config.
        snap_vdi.sm_config = {}
        snap_vdi.sm_config['vdi_type'] = snap_vdi.vdi_type
        if snap_parent:
            snap_vdi.sm_config['vhd-parent'] = snap_parent
            snap_vdi.parent = snap_parent

        snap_vdi.label = self.label
        snap_vdi.description = self.description

        self._linstor.mark_volume_as_persistent(snap_uuid)

        return snap_vdi

    # --------------------------------------------------------------------------
    # Implement specific SR methods.
    # --------------------------------------------------------------------------

    def _rename(self, oldpath, newpath):
        # TODO: I'm not sure... Used by CBT.
        volume_uuid = self._linstor.get_volume_uuid_from_device_path(oldpath)
        self._linstor.update_volume_name(volume_uuid, newpath)

    def _do_snapshot(
        self, sr_uuid, vdi_uuid, snap_type, secondary=None, cbtlog=None
    ):
        # If cbt enabled, save file consistency state.
        if cbtlog is not None:
            if blktap2.VDI.tap_status(self.session, vdi_uuid):
                consistency_state = False
            else:
                consistency_state = True
            util.SMlog(
                'Saving log consistency state of {} for vdi: {}'
                .format(consistency_state, vdi_uuid)
            )
        else:
            consistency_state = None

        if self.vdi_type != vhdutil.VDI_TYPE_VHD:
            raise xs_errors.XenError('Unimplemented')

        if not blktap2.VDI.tap_pause(self.session, sr_uuid, vdi_uuid):
            raise util.SMException('Failed to pause VDI {}'.format(vdi_uuid))
        try:
            return self._snapshot(snap_type, cbtlog, consistency_state)
        finally:
            blktap2.VDI.tap_unpause(self.session, sr_uuid, vdi_uuid, secondary)

    def _snapshot(self, snap_type, cbtlog=None, cbt_consistency=None):
        util.SMlog(
            'LinstorVDI._snapshot for {} (type {})'
            .format(self.uuid, snap_type)
        )

        # 1. Checks...
        if self.hidden:
            raise xs_errors.XenError('VDIClone', opterr='hidden VDI')

        depth = self.sr._vhdutil.get_depth(self.uuid)
        if depth == -1:
            raise xs_errors.XenError(
                'VDIUnavailable',
                opterr='failed to get VHD depth'
            )
        elif depth >= vhdutil.MAX_CHAIN_SIZE:
            raise xs_errors.XenError('SnapshotChainTooLong')

        # Ensure we have a valid path if we don't have a local diskful.
        self.sr._vhdutil.create_chain_paths(self.uuid, readonly=True)

        volume_path = self.path
        if not util.pathexists(volume_path):
            raise xs_errors.XenError(
                'EIO',
                opterr='IO error checking path {}'.format(volume_path)
            )

        # 2. Create base and snap uuid (if required) and a journal entry.
        base_uuid = util.gen_uuid()
        snap_uuid = None

        if snap_type == VDI.SNAPSHOT_DOUBLE:
            snap_uuid = util.gen_uuid()

        clone_info = '{}_{}'.format(base_uuid, snap_uuid)

        active_uuid = self.uuid
        self.sr._journaler.create(
            LinstorJournaler.CLONE, active_uuid, clone_info
        )

        try:
            # 3. Self becomes the new base.
            # The device path remains the same.
            self._linstor.update_volume_uuid(self.uuid, base_uuid)
            self.uuid = base_uuid
            self.location = self.uuid
            self.read_only = True
            self.managed = False

            # 4. Create snapshots (new active and snap).
            active_vdi = self._create_snapshot(active_uuid)

            snap_vdi = None
            if snap_type == VDI.SNAPSHOT_DOUBLE:
                snap_vdi = self._create_snapshot(snap_uuid, active_uuid)

            self.label = 'base copy'
            self.description = ''

            # 5. Mark the base VDI as hidden so that it does not show up
            # in subsequent scans.
            self._mark_hidden()
            self._linstor.update_volume_metadata(
                self.uuid, {READ_ONLY_TAG: True}
            )

            # 6. We must update the new active VDI with the "paused" and
            # "host_" properties. Why? Because the original VDI has been
            # paused and we we must unpause it after the snapshot.
            # See: `tap_unpause` in `blktap2.py`.
            vdi_ref = self.session.xenapi.VDI.get_by_uuid(active_uuid)
            sm_config = self.session.xenapi.VDI.get_sm_config(vdi_ref)
            for key in [x for x in sm_config.keys() if x == 'paused' or x.startswith('host_')]:
                active_vdi.sm_config[key] = sm_config[key]

            # 7. Verify parent locator field of both children and
            # delete base if unused.
            introduce_parent = True
            try:
                snap_parent = None
                if snap_vdi:
                    snap_parent = snap_vdi.parent

                if active_vdi.parent != self.uuid and (
                    snap_type == VDI.SNAPSHOT_SINGLE or
                    snap_type == VDI.SNAPSHOT_INTERNAL or
                    snap_parent != self.uuid
                ):
                    util.SMlog(
                        'Destroy unused base volume: {} (path={})'
                        .format(self.uuid, self.path)
                    )
                    introduce_parent = False
                    self._linstor.destroy_volume(self.uuid)
            except Exception as e:
                util.SMlog('Ignoring exception: {}'.format(e))
                pass

            # 8. Introduce the new VDI records.
            if snap_vdi:
                # If the parent is encrypted set the key_hash for the
                # new snapshot disk.
                vdi_ref = self.sr.srcmd.params['vdi_ref']
                sm_config = self.session.xenapi.VDI.get_sm_config(vdi_ref)
                # TODO: Maybe remove key_hash support.
                if 'key_hash' in sm_config:
                    snap_vdi.sm_config['key_hash'] = sm_config['key_hash']
                # If we have CBT enabled on the VDI,
                # set CBT status for the new snapshot disk.
                if cbtlog:
                    snap_vdi.cbt_enabled = True

            if snap_vdi:
                snap_vdi_ref = snap_vdi._db_introduce()
                util.SMlog(
                    'vdi_clone: introduced VDI: {} ({})'
                    .format(snap_vdi_ref, snap_vdi.uuid)
                )
            if introduce_parent:
                base_vdi_ref = self._db_introduce()
                self.session.xenapi.VDI.set_managed(base_vdi_ref, False)
                util.SMlog(
                    'vdi_clone: introduced VDI: {} ({})'
                    .format(base_vdi_ref, self.uuid)
                )
                self._linstor.update_volume_metadata(self.uuid, {
                    NAME_LABEL_TAG: util.to_plain_string(self.label),
                    NAME_DESCRIPTION_TAG: util.to_plain_string(
                        self.description
                    ),
                    READ_ONLY_TAG: True,
                    METADATA_OF_POOL_TAG: ''
                })

            # 9. Update cbt files if user created snapshot (SNAPSHOT_DOUBLE)
            if snap_type == VDI.SNAPSHOT_DOUBLE and cbtlog:
                try:
                    self._cbt_snapshot(snap_uuid, cbt_consistency)
                except Exception:
                    # CBT operation failed.
                    # TODO: Implement me.
                    raise

            if snap_type != VDI.SNAPSHOT_INTERNAL:
                self.sr._update_stats(self.size)

            # 10. Return info on the new user-visible leaf VDI.
            ret_vdi = snap_vdi
            if not ret_vdi:
                ret_vdi = self
            if not ret_vdi:
                ret_vdi = active_vdi

            vdi_ref = self.sr.srcmd.params['vdi_ref']
            self.session.xenapi.VDI.set_sm_config(
                vdi_ref, active_vdi.sm_config
            )
        except Exception:
            util.logException('Failed to snapshot!')
            try:
                self.sr._handle_interrupted_clone(
                    active_uuid, clone_info, force_undo=True
                )
                self.sr._journaler.remove(LinstorJournaler.CLONE, active_uuid)
            except Exception as clean_error:
                util.SMlog(
                    'WARNING: Failed to clean up failed snapshot: {}'
                    .format(clean_error)
                )
            raise xs_errors.XenError('VDIClone', opterr=str(e))

        self.sr._journaler.remove(LinstorJournaler.CLONE, active_uuid)

        return ret_vdi.get_params()

    @staticmethod
    def _start_persistent_http_server(volume_name):
        pid_path = None
        http_server = None

        try:
            if volume_name == HA_VOLUME_NAME:
                port = '8076'
            else:
                port = '8077'

            try:
                # Use a timeout call because XAPI may be unusable on startup
                # or if the host has been ejected. So in this case the call can
                # block indefinitely.
                session = util.timeout_call(5, util.get_localAPI_session)
                host_ip = util.get_this_host_address(session)
            except:
                # Fallback using the XHA file if session not available.
                host_ip, _ = get_ips_from_xha_config_file()
                if not host_ip:
                    raise Exception(
                        'Cannot start persistent HTTP server: no XAPI session, nor XHA config file'
                    )

            arguments = [
                'http-disk-server',
                '--disk',
                '/dev/drbd/by-res/{}/0'.format(volume_name),
                '--ip',
                host_ip,
                '--port',
                port
            ]

            util.SMlog('Starting {} on port {}...'.format(arguments[0], port))
            http_server = subprocess.Popen(
                [FORK_LOG_DAEMON] + arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                # Ensure we use another group id to kill this process without
                # touch the current one.
                preexec_fn=os.setsid
            )

            pid_path = '/run/http-server-{}.pid'.format(volume_name)
            with open(pid_path, 'w') as pid_file:
                pid_file.write(str(http_server.pid))

            reg_server_ready = re.compile("Server ready!$")
            def is_ready():
                while http_server.poll() is None:
                    line = http_server.stdout.readline()
                    if reg_server_ready.search(line):
                        return True
                return False
            try:
                if not util.timeout_call(10, is_ready):
                    raise Exception('Failed to wait HTTP server startup, bad output')
            except util.TimeoutException:
                raise Exception('Failed to wait for HTTP server startup during given delay')
        except Exception as e:
            if pid_path:
                try:
                    os.remove(pid_path)
                except Exception:
                    pass

            if http_server:
                # Kill process and children in this case...
                try:
                    os.killpg(os.getpgid(http_server.pid), signal.SIGTERM)
                except:
                    pass

            raise xs_errors.XenError(
                'VDIUnavailable',
                opterr='Failed to start http-server: {}'.format(e)
            )

    def _start_persistent_nbd_server(self, volume_name):
        pid_path = None
        nbd_path = None
        nbd_server = None

        try:
            # We use a precomputed device size.
            # So if the XAPI is modified, we must update these values!
            if volume_name == HA_VOLUME_NAME:
                # See: https://github.com/xapi-project/xen-api/blob/703479fa448a8d7141954bb6e8964d8e25c4ac2e/ocaml/xapi/xha_statefile.ml#L32-L37
                port = '8076'
                device_size = 4 * 1024 * 1024
            else:
                # See: https://github.com/xapi-project/xen-api/blob/703479fa448a8d7141954bb6e8964d8e25c4ac2e/ocaml/database/redo_log.ml#L41-L44
                port = '8077'
                device_size = 256 * 1024 * 1024

            try:
                session = util.timeout_call(5, util.get_localAPI_session)
                ips = util.get_host_addresses(session)
            except Exception as e:
                _, ips = get_ips_from_xha_config_file()
                if not ips:
                    raise Exception(
                        'Cannot start persistent NBD server: no XAPI session, nor XHA config file ({})'.format(e)
                    )
                ips = ips.values()

            arguments = [
                'nbd-http-server',
                '--socket-path',
                '/run/{}.socket'.format(volume_name),
                '--nbd-name',
                volume_name,
                '--urls',
                ','.join(['http://' + ip + ':' + port for ip in ips]),
                '--device-size',
                str(device_size)
            ]

            util.SMlog('Starting {} using port {}...'.format(arguments[0], port))
            nbd_server = subprocess.Popen(
                [FORK_LOG_DAEMON] + arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                # Ensure we use another group id to kill this process without
                # touch the current one.
                preexec_fn=os.setsid
            )

            pid_path = '/run/nbd-server-{}.pid'.format(volume_name)
            with open(pid_path, 'w') as pid_file:
                pid_file.write(str(nbd_server.pid))

            reg_nbd_path = re.compile("NBD `(/dev/nbd[0-9]+)` is now attached.$")
            def get_nbd_path():
                while nbd_server.poll() is None:
                    line = nbd_server.stdout.readline()
                    match = reg_nbd_path.search(line)
                    if match:
                        return match.group(1)
            # Use a timeout to never block the smapi if there is a problem.
            try:
                nbd_path = util.timeout_call(10, get_nbd_path)
                if nbd_path is None:
                    raise Exception('Empty NBD path (NBD server is probably dead)')
            except util.TimeoutException:
                raise Exception('Unable to read NBD path')

            util.SMlog('Create symlink: {} -> {}'.format(self.path, nbd_path))
            os.symlink(nbd_path, self.path)
        except Exception as e:
            if pid_path:
                try:
                    os.remove(pid_path)
                except Exception:
                    pass

            if nbd_path:
                try:
                    os.remove(nbd_path)
                except Exception:
                    pass

            if nbd_server:
                # Kill process and children in this case...
                try:
                    os.killpg(os.getpgid(nbd_server.pid), signal.SIGTERM)
                except:
                    pass

            raise xs_errors.XenError(
                'VDIUnavailable',
                opterr='Failed to start nbd-server: {}'.format(e)
            )

    @classmethod
    def _kill_persistent_server(self, type, volume_name, sig):
        try:
            path = '/run/{}-server-{}.pid'.format(type, volume_name)
            if not os.path.exists(path):
                return

            pid = None
            with open(path, 'r') as pid_file:
                try:
                    pid = int(pid_file.read())
                except Exception:
                    pass

            if pid is not None and util.check_pid_exists(pid):
                util.SMlog('Kill {} server {} (pid={})'.format(type, path, pid))
                try:
                    os.killpg(os.getpgid(pid), sig)
                except Exception as e:
                    util.SMlog('Failed to kill {} server: {}'.format(type, e))

            os.remove(path)
        except:
            pass

    @classmethod
    def _kill_persistent_http_server(self, volume_name, sig=signal.SIGTERM):
        return self._kill_persistent_server('nbd', volume_name, sig)

    @classmethod
    def _kill_persistent_nbd_server(self, volume_name, sig=signal.SIGTERM):
        return self._kill_persistent_server('http', volume_name, sig)

    def _check_http_nbd_volume_name(self):
        volume_name = self.path[14:]
        if volume_name not in [
            HA_VOLUME_NAME, REDO_LOG_VOLUME_NAME
        ]:
            raise xs_errors.XenError(
                'VDIUnavailable',
                opterr='Unsupported path: {}'.format(self.path)
            )
        return volume_name

    def _attach_using_http_nbd(self):
        volume_name = self._check_http_nbd_volume_name()

        # Ensure there is no NBD and HTTP server running.
        self._kill_persistent_nbd_server(volume_name)
        self._kill_persistent_http_server(volume_name)

        # 0. Fetch drbd path.
        must_get_device_path = True
        if not self.sr.is_master():
            # We are on a slave, we must try to find a diskful locally.
            try:
                volume_info = self._linstor.get_volume_info(self.uuid)
            except Exception as e:
                raise xs_errors.XenError(
                    'VDIUnavailable',
                    opterr='Cannot get volume info of {}: {}'
                    .format(self.uuid, e)
                )

            hostname = socket.gethostname()
            must_get_device_path = hostname in volume_info.diskful

        drbd_path = None
        if must_get_device_path or self.sr.is_master():
            # If we are master, we must ensure we have a diskless
            # or diskful available to init HA.
            # It also avoid this error in xensource.log
            # (/usr/libexec/xapi/cluster-stack/xhad/ha_set_pool_state):
            # init exited with code 8 [stdout = ''; stderr = 'SF: failed to write in State-File \x10 (fd 4208696). (sys 28)\x0A']
            # init returned MTC_EXIT_CAN_NOT_ACCESS_STATEFILE (State-File is inaccessible)
            available = False
            try:
                drbd_path = self._linstor.get_device_path(self.uuid)
                available = util.pathexists(drbd_path)
            except Exception:
                pass

            if not available:
                raise xs_errors.XenError(
                    'VDIUnavailable',
                    opterr='Cannot get device path of {}'.format(self.uuid)
                )

        # 1. Prepare http-nbd folder.
        try:
            if not os.path.exists('/dev/http-nbd/'):
                os.makedirs('/dev/http-nbd/')
            elif os.path.islink(self.path):
                os.remove(self.path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise xs_errors.XenError(
                    'VDIUnavailable',
                    opterr='Cannot prepare http-nbd: {}'.format(e)
                )

        # 2. Start HTTP service if we have a diskful or if we are master.
        http_service = None
        if drbd_path:
            assert(drbd_path in (
                '/dev/drbd/by-res/{}/0'.format(HA_VOLUME_NAME),
                '/dev/drbd/by-res/{}/0'.format(REDO_LOG_VOLUME_NAME)
            ))
            self._start_persistent_http_server(volume_name)

        # 3. Start NBD server in all cases.
        try:
            self._start_persistent_nbd_server(volume_name)
        except Exception as e:
            if drbd_path:
                self._kill_persistent_http_server(volume_name)
            raise

        self.attached = True
        return VDI.VDI.attach(self, self.sr.uuid, self.uuid)

    def _detach_using_http_nbd(self):
        volume_name = self._check_http_nbd_volume_name()
        self._kill_persistent_nbd_server(volume_name)
        self._kill_persistent_http_server(volume_name)

# ------------------------------------------------------------------------------


if __name__ == '__main__':
    def run():
        SRCommand.run(LinstorSR, DRIVER_INFO)

    if not TRACE_PERFS:
        run()
    else:
        util.make_profile('LinstorSR', run)
else:
    SR.registerSR(LinstorSR)
