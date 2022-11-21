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

import netaddr

from neutronclient._i18n import _
from neutronclient.neutron import v2_0 as neutronv20


class ListNatGatewaySnatRule(neutronv20.ListCommand):
    """List nat gateway snat rule that belong to a given tenant."""

    resource = 'nat_gateway_snat_rule'
    list_columns = ['id', 'name', 'nat_gateway_id', 'description']
    _formatters = {}
    pagination_support = True
    sorting_support = True


class ShowNatGatewaySnatRule(neutronv20.ShowCommand):
    """Show information of a given nat gateway snat rule."""

    resource = 'nat_gateway_snat_rule'


class CreateNatGatewaySnatRule(neutronv20.CreateCommand):
    """Create a nat gateway snat rule."""

    resource = 'nat_gateway_snat_rule'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Set name for the nat gateway snat rule.'))
        parser.add_argument(
            '--description',
            help=_('Set description for the nat gateway snat rule.'))
        parser.add_argument(
            '--nat-gateway',
            required=True,
            help=_('Set nat gateway name or id to nat gateway snat rule.'))
        parser.add_argument(
            '--subnet-cidr',
            required=True,
            help=_('Set subnet cidr to nat gateway snat rule.'))
        parser.add_argument(
            '--fip-ip',
            required=True,
            help=_('Set floating ip to nat gateway snat rule.'))
        parser.add_argument(
            '--fip-bandwidth',
            required=True,
            help=_('Set floating ip bandwidth to nat gateway snat rule.'))

    def args2body(self, parsed_args):
        neutron_client = self.get_client()
        _nat_gateway_id = neutronv20.find_resourceid_by_name_or_id(
            neutron_client, 'nat_gateway', parsed_args.nat_gateway)
        body = {
            self.resource: {
                'nat_gateway_id': _nat_gateway_id,
                'subnet_cidr': netaddr.IPNetwork(parsed_args.subnet_cidr)
            }
        }
        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description', 'fip_ip',
                                'fip_bandwidth'])
        return body


class UpdateNatGatewaySnatRule(neutronv20.UpdateCommand):
    """Update a given nat gateway snat rule."""

    resource = 'nat_gateway_snat_rule'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Update name for nat gateway snat rule.')
        )
        parser.add_argument(
            '--description',
            help=_('Update description for nat gateway snat rule.'))
        parser.add_argument(
            '--subnet-cidr',
            help=_('Update subnet cidr to nat gateway snat rule.'))
        parser.add_argument(
            '--fip-ip',
            help=_('Update floating ip to nat gateway snat rule.'))
        parser.add_argument(
            '--fip-bandwidth',
            help=_('Update floating ip bandwidth to nat gateway snat rule.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }
        if parsed_args.subnet_cidr:
            body[self.resource] = {
                'subnet_cidr': netaddr.IPNetwork(parsed_args.subnet_cidr)}

        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['description', 'fip_ip', 'name',
                                'fip_bandwidth'])
        return body


class DeleteNatGatewaySnatRule(neutronv20.DeleteCommand):
    """Delete a given nat gateway snat rule."""

    resource = 'nat_gateway_snat_rule'
