# Copyright 2017 cmss, Inc.  All rights reserved.
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


SUPPORT_VPC_CONNECTION_STATUS = ['ACTIVE', 'DOWN']


class ListVpcConnection(neutronv20.ListCommand):
    """List vpc connections that belong to a given tenant."""

    resource = 'vpc_connection'
    list_columns = ['id', 'name', 'status', 'local_router', 'peer_router']
    _formatters = {}
    pagination_support = True
    sorting_support = True


class ShowVpcConnection(neutronv20.ShowCommand):
    """Show details of a given vpc connection."""

    resource = 'vpc_connection'


class CreateVpcConnection(neutronv20.CreateCommand):
    """Create a vpc connection."""

    resource = 'vpc_connection'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Set name for the vpc connection.'))
        parser.add_argument(
            '--description',
            help=_('Set description for the vpc connection.'))
        parser.add_argument(
            '--status',
            default='ACTIVE',
            choices=SUPPORT_VPC_CONNECTION_STATUS,
            help=_('Set status for vpc connection.'))
        parser.add_argument(
            '--local-router',
            required=True,
            help=_('Set local router for vpc connection.'))
        parser.add_argument(
            '--local-subnet',
            action='append',
            help=_('Set local subnets for vpc connection, '
                   'support multi --local-subnet params.'))
        parser.add_argument(
            '--peer-router',
            required=True,
            help=_('Set peer router for vpc connection.'))
        parser.add_argument(
            '--peer-subnet',
            action='append',
            help=_('Set peer subnets for vpc connection. '
                   'support multi --peer-subnet params.'))

    def find_subnet_ids_by_input_subnets(self, subnet_names):
        """Return subnets id list by given subnets name or id"""
        subnet_ids = list()
        neutron_client = self.get_client()
        for name in subnet_names:
            sb_id = neutronv20.find_resourceid_by_name_or_id(
                neutron_client, 'subnet', name)
            subnet_ids.append(sb_id)
        return subnet_ids

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }
        neutron_client = self.get_client()
        if parsed_args.local_router is not None:
            local_router_id = neutronv20.find_resourceid_by_name_or_id(
                neutron_client, 'router', parsed_args.local_router)
            body[self.resource].update({'local_router': local_router_id})
        if parsed_args.peer_router is not None:
            peer_router_id = neutronv20.find_resourceid_by_name_or_id(
                neutron_client, 'router', parsed_args.peer_router)
            body[self.resource].update({'peer_router': peer_router_id})
        if parsed_args.local_subnet is not None:
            local_subnets = self.find_subnet_ids_by_input_subnets(
                parsed_args.local_subnet)
            body[self.resource].update({'local_subnets': local_subnets})
        if parsed_args.peer_subnet is not None:
            peer_subnets = self.find_subnet_ids_by_input_subnets(
                parsed_args.peer_subnet)
            body[self.resource].update({'peer_subnets': peer_subnets})

        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description',
                                'tenant_id', 'status'])
        return body


class UpdateVpcConnection(neutronv20.UpdateCommand):
    """Update a given vpc connection"""

    resource = 'vpc_connection'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Update name for vpc connection.')
        )
        parser.add_argument(
            '--description',
            help=_('Update description for vpc connection.')
        )
        parser.add_argument(
            '--local-subnet',
            action='append',
            help=_('Set local subnet for vpc connection, '
                   'support multi --local-subnet params.'))
        parser.add_argument(
            '--peer-subnet',
            action='append',
            help=_('Set peer subnet for vpc connection, '
                   'support multi --peer-subnet params.'))

    def find_subnet_ids_by_input_subnets(self, subnet_names):
        """Return subnets id list by given subnets name or id"""
        subnet_ids = list()
        neutron_client = self.get_client()
        for name in subnet_names:
            sb_id = neutronv20.find_resourceid_by_name_or_id(
                neutron_client, 'subnet', name)
            subnet_ids.append(sb_id)
        return subnet_ids

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }
        if parsed_args.local_subnet is not None:
            local_subnets = self.find_subnet_ids_by_input_subnets(
                parsed_args.local_subnet)
            body[self.resource].update({'local_subnets': local_subnets})
        if parsed_args.peer_subnet is not None:
            peer_subnets = self.find_subnet_ids_by_input_subnets(
                parsed_args.peer_subnet)
            body[self.resource].update({'peer_subnets': peer_subnets})

        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description'])
        return body


class DeleteVpcConnection(neutronv20.DeleteCommand):
    """Delete a given vpc connection."""

    resource = 'vpc_connection'
