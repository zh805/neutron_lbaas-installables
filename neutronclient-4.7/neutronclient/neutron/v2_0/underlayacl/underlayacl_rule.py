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


def get_underlayacl_id(client, underlayacl_id_or_name):
    underlayacl_id = neutronv20.find_resourceid_by_name_or_id(
        client, 'underlayacl', underlayacl_id_or_name)
    return underlayacl_id


def add_underlayacl_id_argument(parser):
    parser.add_argument(
        'underlayacl', metavar='UNDERLAYACL',
        help=_('ID or name of the underlayacl.'))


class UnderlayAclRuleMixin(object):
    def add_known_arguments(self, parser):
        add_underlayacl_id_argument(parser)

    def set_extra_attrs(self, parsed_args):
        self.parent_id = get_underlayacl_id(self.get_client(),
                                            parsed_args.underlayacl)


class ListUnderlayAclRule(UnderlayAclRuleMixin, neutronv20.ListCommand):
    """List underlayacls that belong to a given underlayacl."""

    resource = 'underlayacl_rule'
    list_columns = ['id', 'name', 'protocol', 'source_ip_address',
                    'source_port', 'destination_ip_address',
                    'destination_port', 'direction', 'action']
    _formatters = {}
    pagination_support = True
    sorting_support = True


class ShowUnderlayAclRule(UnderlayAclRuleMixin, neutronv20.ShowCommand):
    """Show details of a given underlayacl rule."""

    resource = 'underlayacl_rule'
    allow_names = False


class CreateUnderlayAclRule(UnderlayAclRuleMixin, neutronv20.CreateCommand):
    """Create a underlayacl rule."""

    resource = 'underlayacl_rule'

    def add_known_arguments(self, parser):
        super(CreateUnderlayAclRule, self).add_known_arguments(parser)
        parser.add_argument(
            '--name',
            help=_('Set name for the underlayacl rule.'))
        parser.add_argument(
            '--description',
            help=_('Set description for the underlayacl rule.'))
        parser.add_argument(
            '--ether-type',
            help=_('Set ip version for underlayacl rule.'))
        parser.add_argument(
            '--protocol',
            help=_('Set protocol for underlayacl rule.'))
        parser.add_argument(
            '--source-ip-address',
            help=_('Set source ip address for underlayacl rule.'))
        parser.add_argument(
            '--source-port',
            help=_('Set source port for underlayacl rule.'))
        parser.add_argument(
            '--destination-ip-address',
            help=_('Set destination ip address for underlayacl rule.'))
        parser.add_argument(
            '--destination-port',
            help=_('Set destination port for underlayacl rule.'))
        parser.add_argument(
            '--priority',
            help=_('Set priority for underlayacl rule.'))
        parser.add_argument(
            '--direction',
            help=_('Set direction for underlayacl rule.'))
        parser.add_argument(
            '--action',
            help=_('Set action for underlayacl rule.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }

        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description', 'ether_type',
                                'protocol', 'source_ip_address', 'source_port',
                                'destination_ip_address', 'destination_port',
                                'priority', 'direction', 'action',
                                'tenant_id'])
        return body


class UpdateUnderlayAclRule(UnderlayAclRuleMixin, neutronv20.UpdateCommand):
    """Update a given underlayacl_rule"""

    resource = 'underlayacl_rule'
    allow_names = False

    def add_known_arguments(self, parser):
        super(UpdateUnderlayAclRule, self).add_known_arguments(parser)
        parser.add_argument(
            '--name',
            help=_('Set name for the underlayacl rule.'))
        parser.add_argument(
            '--description',
            help=_('Set description for the underlayacl rule.'))
        parser.add_argument(
            '--ether-type',
            help=_('Set ip version for underlayacl rule.'))
        parser.add_argument(
            '--protocol',
            help=_('Set protocol for underlayacl rule.'))
        parser.add_argument(
            '--source-ip-address',
            help=_('Set source ip address for underlayacl rule.'))
        parser.add_argument(
            '--source-port',
            help=_('Set source port for underlayacl rule.'))
        parser.add_argument(
            '--destination-ip-address',
            help=_('Set destination ip address for underlayacl rule.'))
        parser.add_argument(
            '--destination-port',
            help=_('Set destination port for underlayacl rule.'))
        parser.add_argument(
            '--priority',
            help=_('Set priority for underlayacl rule.'))
        parser.add_argument(
            '--direction',
            help=_('Set direction for underlayacl rule.'))
        parser.add_argument(
            '--action',
            help=_('Set action for underlayacl rule.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }

        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description', 'ether_type',
                                'protocol', 'source_ip_address', 'source_port',
                                'destination_ip_address', 'destination_port',
                                'priority', 'direction', 'action'])
        return body


class DeleteUnderlayAclRule(UnderlayAclRuleMixin, neutronv20.DeleteCommand):
    """Delete a given underlayacl rule."""

    resource = 'underlayacl_rule'
    allow_names = False
