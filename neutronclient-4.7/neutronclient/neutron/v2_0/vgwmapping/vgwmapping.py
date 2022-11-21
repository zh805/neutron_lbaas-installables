# Copyright 2020 cmss, Inc.  All rights reserved.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
from neutronclient._i18n import _
from neutronclient.neutron import v2_0 as neutronv20
from oslo_log import log as logging
from oslo_utils import uuidutils
from oslo_serialization import jsonutils
from neutronclient.common import utils
from neutronclient.neutron.v2_0 import availability_zone

LOG = logging.getLogger(__name__)

def _format_mapping_detail(vgw):
    try:
        return jsonutils.dumps(vgw['mapping_detail'])
    except (TypeError, KeyError):
        return ''

class ListVgwmapping(neutronv20.ListCommand):
    """List all vgw mapping."""

    resource = 'vgw_mapping'
    list_columns = ['id', 'name', 'vrouter_id', 'mapping_detail']
    _formatters = {"mapping_detail": _format_mapping_detail}
    pagination_support = True
    sorting_support = True


class ShowVgwmapping(neutronv20.ShowCommand):
    """Show details of a given vgw mapping."""
    allow_names = True

    resource = 'vgw_mapping'


class CreateVgwmapping(neutronv20.CreateCommand):
    """Create a vgw mapping for a given tenant."""

    resource = 'vgw_mapping'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Set name for the vgw mapping.'))
        parser.add_argument(
            'vrouter_id', metavar='ROUTER ID',
            help=_('Set router id for vgw mapping.'))
        mapping_detail = parser.add_mutually_exclusive_group()
        mapping_detail.add_argument(
            '--detail', action='append', dest='mapping_detail',
            type=utils.str2dict_type(required_keys=['type', 'real_ip', 'mapping_ip'],
                                     optional_keys=['real_port', 'mapping_port']),
            help=_('Mapping detail to associate with the vgw_mapping.'
                   ' You can repeat this option.'))

        availability_zone.add_az_hint_argument(parser, self.resource)

    def args2body(self, parsed_args):
        body = {}
        neutron_client = self.get_client()
        if parsed_args.vrouter_id:
            vrouter_id = neutronv20.find_resourceid_by_name_or_id(
                neutron_client, 'router', parsed_args.vrouter_id)  # "router" -> client.py : list_routers()
            body['vrouter_id'] = vrouter_id
        body['id'] = uuidutils.generate_uuid()
        neutronv20.update_dict(parsed_args, body, ['name', 'tenant_id', 'mapping_detail'])
        if 'mapping_detail' in body:
            for detail in body['mapping_detail']:
                detail['id'] = uuidutils.generate_uuid()
                keys = detail.keys()
                if 'type' in keys:
                    detail['type'] = int(detail['type'])
                if 'real_port' in keys:
                    detail['real_port'] = int(detail['real_port'])
                if 'mapping_port' in keys:
                    detail['mapping_port'] = int(detail['mapping_port'])
        availability_zone.args2body_az_hint(parsed_args, body)
        return {self.resource: body}


class UpdateVgwmapping(neutronv20.UpdateCommand):
    """Update a given vgw mapping."""

    resource = 'vgw_mapping'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Update name for vgw_mapping.')
        )
        parser.add_argument(
            '--vrouter_id',
            help=_('Set vrouter_id for the vgw_mapping.')
        )
        mapping_detail = parser.add_mutually_exclusive_group()
        mapping_detail.add_argument(
            '--detail', action='append', dest='mapping_detail',
            type=utils.str2dict_type(required_keys=['type', 'real_ip', 'mapping_ip'],
                                     optional_keys=['real_port', 'mapping_port'],),
            help=_('Mapping detail to associate with the vgw_mapping.'
                   ' You can repeat this option.'))

    def args2body(self, parsed_args):
        body = {}
        neutron_client = self.get_client()
        if parsed_args.vrouter_id:
            vrouter_id = neutronv20.find_resourceid_by_name_or_id(
                neutron_client, 'router', parsed_args.vrouter_id)  # "router" -> client.py : list_routers()
            body['vrouter_id'] = vrouter_id
        neutronv20.update_dict(parsed_args, body, ['name', 'tenant_id', 'mapping_detail'])
        if 'mapping_detail' in body:
            for detail in body['mapping_detail']:
                detail['id'] = uuidutils.generate_uuid()
                keys = detail.keys()
                if 'type' in keys:
                    detail['type'] = int(detail['type'])
                if 'real_port' in keys:
                    detail['real_port'] = int(detail['real_port'])
                if 'mapping_port' in keys:
                    detail['mapping_port'] = int(detail['mapping_port'])
        return {self.resource: body}


class DeleteVgwmapping(neutronv20.DeleteCommand):
    """Delete a given vgw mapping."""
    allow_names = True
    resource = 'vgw_mapping'
