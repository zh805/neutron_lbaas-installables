# Copyright (c) 2016 Intel Corporation.
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


IPV6_NS_QOS_POLICY_RESOURCE = 'ipv6_ns_qos_policy'


class CreateIpv6NsQoSPolicy(neutronv20.CreateCommand):
    """Create an IPv6 qos policy."""

    resource = IPV6_NS_QOS_POLICY_RESOURCE

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Name of IPv6 ns qos policy'))
        parser.add_argument(
            '--description',
            help=_('Description of IPv6 ns qos policy'))
        parser.add_argument(
            '--router-id',
            dest='router_id',
            required=True,
            help=_('Id of the router binding IPv6 ns qos policy'))
        parser.add_argument(
            '--port-id',
            dest='port_id',
            required=True,
            help=_('Id of the port binding IPv6 ns qos policy'))
        parser.add_argument(
            '--qos-policy-id',
            dest='qos_policy_id',
            required=True,
            help=_('Id of the qos policy binding IPv6 ns qos policy'))

    def args2body(self, parsed_args):
        body = {}
        neutronv20.update_dict(parsed_args, body,
                               ['name', 'description',
                                'router_id', 'port_id',
                                'qos_policy_id'])
        return {self.resource: body}


class DeleteIpv6NsQoSPolicy(neutronv20.DeleteCommand):
    """Delete an IPv6 qos policy."""

    resource = IPV6_NS_QOS_POLICY_RESOURCE
    allow_names = False


class UpdateIpv6NsQoSPolicy(neutronv20.UpdateCommand):
    """Update an IPv6 qos policy."""
    resource = IPV6_NS_QOS_POLICY_RESOURCE
    allow_names = False

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Name of IPv6 ns qos policy'))
        parser.add_argument(
            '--description',
            help=_('Description of IPv6 ns qos policy'))
        parser.add_argument(
            '--router-id',
            dest='router_id',
            help=_('Id of the router binding IPv6 ns qos policy'))
        parser.add_argument(
            '--port-id',
            dest='port_id',
            help=_('Id of the port binding IPv6 ns qos policy'))
        parser.add_argument(
            '--qos-policy-id',
            dest='qos_policy_id',
            help=_('Id of the qos policy binding IPv6 ns qos policy'))

    def args2body(self, parsed_args):
        body = {}
        neutronv20.update_dict(parsed_args, body,
                               ['name', 'description',
                                'router_id', 'port_id',
                                'qos_policy_id'])
        return {self.resource: body}


class ListIpv6NsQoSPolicy(neutronv20.ListCommand):
    """List IPv6 qos policies."""
    resource = IPV6_NS_QOS_POLICY_RESOURCE

    list_columns = ['id', 'name', 'description',
                    'router_id', 'port_id', 'qos_policy_id']


class ShowIpv6NsQoSPolicy(neutronv20.ShowCommand):
    """Show information of an IPv6 qos policy."""

    resource = IPV6_NS_QOS_POLICY_RESOURCE
    allow_names = False
    json_indent = 5
