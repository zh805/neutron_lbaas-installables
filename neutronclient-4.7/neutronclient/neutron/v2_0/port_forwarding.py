# Copyright 2018 OpenStack Foundation.
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
from neutronclient.common import validators
from neutronclient.neutron import v2_0 as neutronV20

PORT_FORWARDING = "port_forwarding"
SUPPORT_PROTOCOLS = ['tcp', 'udp']


def update_floatingip_args2body(parsed_args, body):
    neutronV20.update_dict(parsed_args, body, ['floatingip'])


def get_floatingip_id(client, floatingip_id_or_name):
    _floatingip_id = neutronV20.find_resourceid_by_id(
        client, 'floatingip', floatingip_id_or_name)
    return _floatingip_id


def add_floatingip_argument(parser):
    parser.add_argument(
        'floatingip_id', metavar='FLOATINGIP_ID',
        help=_('ID or name of the floatingip.'))


class PortForwardingMixin(object):
    def add_known_arguments(self, parser):
        add_floatingip_argument(parser)

    def set_extra_attrs(self, parsed_args):
        self.parent_id = get_floatingip_id(self.get_client(),
                                           parsed_args.floatingip_id)


class ListPortForwarding(PortForwardingMixin, neutronV20.ListCommand):
    """List port forwarding that belong to a given floatingip."""

    resource = PORT_FORWARDING
    list_columns = ['id', 'internal_ip_address', 'internal_port',
                    'internal_port_id', 'external_port', 'protocol']
    pagination_support = True
    sorting_support = True


class ShowPortForwarding(PortForwardingMixin, neutronV20.ShowCommand):
    """Show information of a given port forwarding."""

    resource = PORT_FORWARDING
    allow_names = False


class CreatePortForwarding(PortForwardingMixin, neutronV20.CreateCommand):
    """Create port forwarding information of a given floatingip."""

    resource = PORT_FORWARDING

    def add_known_arguments(self, parser):
        super(CreatePortForwarding, self).add_known_arguments(parser)
        parser.add_argument(
            '--protocol',
            required=True,
            type=utils.convert_to_lowercase,
            choices=SUPPORT_PROTOCOLS,
            help=_('The IP protocol of port forwarding.'))
        parser.add_argument(
            '--internal-ip-address',
            help=_('The internal ip address of port forwarding.'))
        parser.add_argument(
            '--internal-port',
            required=True,
            help=_('The internal port id of port forwarding, '
                   'ranges in [1-65535].'))
        parser.add_argument(
            '--internal-port-id',
            required=True,
            help=_('The internal port uuid of port forwarding.'))
        parser.add_argument(
            '--external-port',
            required=True,
            help=_('The internal port id of port forwarding, '
                   'ranges in [1-65535].'))

    def args2body(self, parsed_args):
        body = {}
        if parsed_args.internal_port:
            validators.validate_int_range(
                parsed_args, 'internal_port', min_value=1, max_value=65536)
        if parsed_args.external_port:
            validators.validate_int_range(
                parsed_args, 'external_port', min_value=1, max_value=65536)
        if parsed_args.internal_port_id:
            _port_id = neutronV20.find_resourceid_by_id(
                self.get_client(), 'port', parsed_args.internal_port_id)
            body["internal_port_id"] = _port_id
        neutronV20.update_dict(parsed_args, body,
                               ['internal_port', 'external_port', 'protocol',
                                'internal_ip_address'])
        return {self.resource: body}


class UpdatePortForwarding(PortForwardingMixin, neutronV20.UpdateCommand):
    """Update port forwarding information of a given floatingip."""

    resource = PORT_FORWARDING

    def add_known_arguments(self, parser):
        super(UpdatePortForwarding, self).add_known_arguments(parser)
        parser.add_argument(
            '--protocol',
            type=utils.convert_to_lowercase,
            choices=SUPPORT_PROTOCOLS,
            help=_('The IP protocol of port forwarding.'))
        parser.add_argument(
            '--internal-ip-address',
            help=_('The internal ip address of port forwarding.'))
        parser.add_argument(
            '--internal-port',
            help=_('The internal port id of port forwarding, '
                   'ranges in [1-65535].'))
        parser.add_argument(
            '--internal-port-id',
            help=_('The internal port uuid of port forwarding.'))
        parser.add_argument(
            '--external-port',
            help=_('The internal port id of port forwarding, '
                   'ranges in [1-65535].'))

    def args2body(self, parsed_args):
        body = {}
        if parsed_args.internal_port:
            validators.validate_int_range(
                parsed_args, 'internal_port', min_value=1, max_value=65536)
        if parsed_args.external_port:
            validators.validate_int_range(
                parsed_args, 'external_port', min_value=1, max_value=65536)
        if parsed_args.internal_port_id:
            _port_id = neutronV20.find_resourceid_by_id(
                self.get_client(), 'port', parsed_args.internal_port_id)
            body["internal_port_id"] = _port_id
        neutronV20.update_dict(parsed_args, body,
                               ['internal_port', 'external_port', 'protocol',
                                'internal_ip_address'])
        return {self.resource: body}


class DeletePortForwarding(PortForwardingMixin, neutronV20.DeleteCommand):
    """Delete port forwarding of given floatingips"""

    resource = PORT_FORWARDING
    allow_names = False
