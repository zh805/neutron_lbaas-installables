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

from neutronclient._i18n import _
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronv20


SUPPORT_NAT_GATEWAY_STATUS = ['True', 'False']
SUPPORT_NAT_GATEWAY_SCALE = ['True', 'False']


class ListNatGateway(neutronv20.ListCommand):
    """List nat gateway that belong to a given project."""

    resource = 'nat_gateway'
    list_columns = ['id', 'name', 'vpc_id', 'description']
    _formatters = {}
    pagination_support = True
    sorting_support = True


class ShowNatGateway(neutronv20.ShowCommand):
    """Show information of a given nat gateway."""

    resource = 'nat_gateway'


class CreateNatGateway(neutronv20.CreateCommand):
    """Create a nat gateway."""

    resource = 'nat_gateway'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Set name for the nat gateway.'))
        parser.add_argument(
            '--description',
            help=_('Set description for the nat gateway.'))
        parser.add_argument(
            '--vpc',
            required=True,
            help=_('Set vpc name or id to nat gateway.'))
        parser.add_argument(
            '--bandwidth',
            default=100,
            help=_('Set bandwidth to nat gateway.'))
        parser.add_argument(
            '--max-concurrency',
            default=1000,
            help=_('Set max concurrency to nat gateway.'))
        parser.add_argument(
            '--admin-state-up',
            default=True,
            help=_('Specify the administrative state of the nat gateway.'))
        parser.add_argument(
            '--details',
            metavar='scale=normal|high',
            type=utils.str2dict_type(
                required_keys=['scale']),
            help=_('The specification of NAT GATEWAY.'))

    def args2body(self, parsed_args):
        neutron_client = self.get_client()
        _router_id = neutronv20.find_resourceid_by_name_or_id(
            neutron_client, 'router', parsed_args.vpc)
        body = {
            self.resource: {
                'vpc_id': _router_id
            }
        }
        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description', 'tenant_id',
                                'bandwidth', 'max_concurrency',
                                'admin_state_up', 'details'])
        return body


class UpdateNatGateway(neutronv20.UpdateCommand):
    """Update a given nat gateway."""

    resource = 'nat_gateway'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Update name for nat gateway.')
        )
        parser.add_argument(
            '--description',
            help=_('Update description for nat gateway.')
        )
        parser.add_argument(
            '--bandwidth',
            help=_('Update bandwidth for nat gateway.'))
        parser.add_argument(
            '--max-concurrency',
            help=_('Update max concurrency for nat gateway.')
        )
        parser.add_argument(
            '--admin-state-up',
            default=True,
            choices=SUPPORT_NAT_GATEWAY_STATUS,
            help=_('Specify the administrative state of the nat gateway.'))
        parser.add_argument(
            '--details',
            metavar='scale=normal|high',
            type=utils.str2dict_type(
                required_keys=['scale']),
            help=_('The specification of NAT GATEWAY.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }
        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['bandwidth', 'max_concurrency', 'description',
                                'name', 'admin_state_up', 'details'])
        return body


class DeleteNatGateway(neutronv20.DeleteCommand):
    """Delete a given nat gateway."""

    resource = 'nat_gateway'
