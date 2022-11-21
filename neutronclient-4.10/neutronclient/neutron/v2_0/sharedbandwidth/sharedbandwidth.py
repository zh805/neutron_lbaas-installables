# Copyright 2018 cmss, Inc.  All rights reserved.
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

import argparse

from neutronclient._i18n import _
from neutronclient.neutron import v2_0 as neutronv20


class ListSharedBandwidth(neutronv20.ListCommand):
    """List shared bandwidth that belong to a given tenant."""

    resource = 'sharedbandwidth'
    list_columns = ['id', 'name', 'description', 'bandwidth',
                    'natgateway_id', 'floatingips']
    _formatters = {}
    pagination_support = True
    sorting_support = True


class ShowSharedBandwidth(neutronv20.ShowCommand):
    """Show details of a given shared bandwidth."""

    resource = 'sharedbandwidth'


class CreateSharedBandwidth(neutronv20.CreateCommand):
    """Create a shared bandwidth."""

    resource = 'sharedbandwidth'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Set name for the shared bandwidth.'))
        parser.add_argument(
            '--description',
            help=_('Set description for the shared bandwidth.'))
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false.'))
        parser.add_argument(
            '--admin_state_down',
            dest='admin_state', action='store_false',
            help=argparse.SUPPRESS)
        parser.add_argument(
            '--bandwidth',
            required=True,
            help=_('Set bandwidth for shared bandwidth, unit: Mbps'))
        parser.add_argument(
            '--natgateway-id',
            help=_('Set nat gateway id which shared bandwidth binding to.'))
        parser.add_argument(
            '--floatingip',
            action='append',
            help=_('Add floatingip to shared bandwidth.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {
                'admin_state_up': parsed_args.admin_state}
        }
        neutron_client = self.get_client()

        if parsed_args.natgateway_id is not None:
            natgateway_id = neutronv20.find_resourceid_by_name_or_id(
                neutron_client, 'nat_gateway', parsed_args.natgateway_id)
            body[self.resource].update({'natgateway_id': natgateway_id})

        if parsed_args.floatingip is not None:
            floatingips = []
            for fip_id in parsed_args.floatingip:
                floatingip_id = neutronv20.find_resourceid_by_name_or_id(
                    neutron_client, 'floatingip', fip_id)
                floatingips.append(floatingip_id)
            body[self.resource].update({'floatingips': floatingips})

        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description',
                                'tenant_id', 'bandwidth'])
        return body


class UpdateSharedBandwidth(neutronv20.UpdateCommand):
    """Update a shared bandwidth."""

    resource = 'sharedbandwidth'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Set name for the shared bandwidth.'))
        parser.add_argument(
            '--description',
            help=_('Set description for the shared bandwidth.'))
        parser.add_argument(
            '--admin-state-up',
            dest='admin_state',
            help=_('Set value of admin state up, Choice: (True | False).'))
        parser.add_argument(
            '--bandwidth',
            help=_('Set bandwidth for shared bandwidth, unit: Mbps'))
        parser.add_argument(
            '--floatingip',
            action='append',
            help=_('Add floatingip to shared bandwidth.'))
        parser.add_argument(
            '--no-floatingips', dest='no_floatingips',
            action='store_true',
            help=_('Release all floatingips from shared bandwidth.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }
        neutron_client = self.get_client()

        if parsed_args.admin_state is not None:
            body[self.resource].update(
                {'admin_state_up': parsed_args.admin_state})

        if parsed_args.floatingip is not None:
            floatingips = []
            for fip_id in parsed_args.floatingip:
                floatingip_id = neutronv20.find_resourceid_by_name_or_id(
                    neutron_client, 'floatingip', fip_id)
                floatingips.append(floatingip_id)
            body[self.resource].update({'floatingips': floatingips})

        if parsed_args.no_floatingips:
            body[self.resource].update({'floatingips': []})

        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description',
                                'tenant_id', 'bandwidth'])
        return body


class DeleteSharedBandwidth(neutronv20.DeleteCommand):
    """Delete a given shared bandwidth."""

    resource = 'sharedbandwidth'
