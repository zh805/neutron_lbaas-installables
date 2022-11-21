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
from neutronclient.common import exceptions
from neutronclient.neutron import v2_0 as neutronv20

SUPPORT_PROTOCOLS = ['tcp', 'udp', 'icmp', 'any']


def _validate_dnat_params(args):
    # validate support protocols
    if args.protocol:
        if args.protocol not in SUPPORT_PROTOCOLS:
            raise exceptions.CommandError(_(
                "Invalid protocol, please check input protocol parameter."))

    if args.external_ip and not args.external_port:
        raise exceptions.CommandError(_(
            "Invalid input, external port "
            "must be provided after external ip."))

    if args.external_port and not args.external_ip:
        raise exceptions.CommandError(_(
            "Invalid input, external ip "
            "must be provided before external port."))

    if args.internal_ip and not args.internal_port:
        raise exceptions.CommandError(_(
            "Invalid input, internal port "
            "must be provided after internal ip."))

    if args.internal_port and not args.internal_ip:
        raise exceptions.CommandError(_(
            "Invalid input, internal ip "
            "must be provided before internal port."))


class ListNatGatewayDnatRule(neutronv20.ListCommand):
    """List nat gateway dnat rule that belong to a given tenant."""

    resource = 'nat_gateway_dnat_rule'
    list_columns = ['id', 'name', 'nat_gateway_id', 'description']
    _formatters = {}
    pagination_support = True
    sorting_support = True


class ShowNatGatewayDnatRule(neutronv20.ShowCommand):
    """Show information of a given nat gateway dnat rule."""

    resource = 'nat_gateway_dnat_rule'


class CreateNatGatewayDnatRule(neutronv20.CreateCommand):
    """Create a nat gateway dnat rule."""

    resource = 'nat_gateway_dnat_rule'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Set name for the nat gateway dnat rule.'))
        parser.add_argument(
            '--description',
            help=_('Set description for the nat gateway dnat rule.'))
        parser.add_argument(
            '--nat-gateway',
            required=True,
            help=_('Set nat gateway name or id to nat gateway dnat rule.'))
        parser.add_argument(
            '--external-ip',
            required=True,
            help=_('Set external ip to nat gateway dnat rule.'))
        parser.add_argument(
            '--external-port',
            required=True,
            help=_('Set external port to nat gateway dnat rule.'))
        parser.add_argument(
            '--protocol',
            required=True,
            choices=SUPPORT_PROTOCOLS,
            help=_('Set protocol to nat gateway dnat rule.'))
        parser.add_argument(
            '--internal-ip',
            required=True,
            help=_('Set internal ip to nat gateway dnat rule.'))
        parser.add_argument(
            '--internal-port',
            required=True,
            help=_('Set internal port to nat gateway dnat rule.'))
        parser.add_argument(
            '--external-bandwidth',
            required=True,
            help=_('Set external bandwidth to nat gateway dnat rule.'))

    def args2body(self, parsed_args):
        neutron_client = self.get_client()
        _nat_gateway_id = neutronv20.find_resourceid_by_name_or_id(
            neutron_client, 'nat_gateway', parsed_args.nat_gateway)
        body = {
            self.resource: {
                'nat_gateway_id': _nat_gateway_id
            }
        }
        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description', 'protocol',
                                'external_ip', 'external_port',
                                'internal_ip', 'internal_port',
                                'external_bandwidth'])
        return body


class UpdateNatGatewayDnatRule(neutronv20.UpdateCommand):
    """Update a given nat gateway dnat rule."""

    resource = 'nat_gateway_dnat_rule'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Update name for nat gateway dnat rule.')
        )
        parser.add_argument(
            '--description',
            help=_('Update description for the nat gateway dnat rule.'))
        parser.add_argument(
            '--external-ip',
            help=_('Update external ip to nat gateway dnat rule.'))
        parser.add_argument(
            '--external-port',
            help=_('Update external port to nat gateway dnat rule.'))
        parser.add_argument(
            '--protocol',
            choices=SUPPORT_PROTOCOLS,
            help=_('Update protocol to nat gateway dnat rule.'))
        parser.add_argument(
            '--internal-ip',
            help=_('Update internal ip to nat gateway dnat rule.'))
        parser.add_argument(
            '--internal-port',
            help=_('Update internal port to nat gateway dnat rule.'))
        parser.add_argument(
            '--external-bandwidth',
            help=_('Update external bandwidth to nat gateway dnat rule.'))

    def args2body(self, parsed_args):
        _validate_dnat_params(parsed_args)
        body = {
            self.resource: {}
        }
        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['description', 'external_ip',
                                'external_port', 'internal_ip',
                                'internal_port', 'protocol',
                                'name', 'external_bandwidth'])
        return body


class DeleteNatGatewayDnatRule(neutronv20.DeleteCommand):
    """Delete a given nat gateway dnat rule."""

    resource = 'nat_gateway_dnat_rule'
