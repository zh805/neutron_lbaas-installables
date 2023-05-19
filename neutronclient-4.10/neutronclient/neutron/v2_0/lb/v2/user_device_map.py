# _*_coding: utf-8 _*_
# Copyright © 2014-2021 China Mobile (SuZhou) Software Technology Co.,Ltd.
# R&D by BC-SLB in 2021.
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

from neutronclient._i18n import _
from neutronclient.common import exceptions
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronV20
from neutronclient.neutron.v2_0 import availability_zone


class ListUserDeviceMap(neutronV20.ListCommand):
    """LBaaS v2 List user_device_map that belong to a given tenant."""

    resource = 'user_device_map'
    shadow_resource = 'lbaas_user_device_map'
    list_columns = ['id', 'user_id', 'node_ip', 'provider', "availability_zone_hints"]
    pagination_support = True
    sorting_support = True


class ShowUserDeviceMap(neutronV20.ShowCommand):
    """LBaaS v2 Show information of a given user_device_map."""

    resource = 'user_device_map'
    shadow_resource = 'lbaas_user_device_map'


class CreateUserDeviceMap(neutronV20.CreateCommand):
    """LBaaS v2 Create a user_device_map."""

    resource = 'user_device_map'
    shadow_resource = 'lbaas_user_device_map'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--user-id',
            required=True,
            help=_('The owner tenant ID.'))
        parser.add_argument(
            '--node-ip',
            required=True,
            help=_('IP addresses of the devices. '
                   'The IP addresses in the cluster are separated by ",", '
                   'and the clusters are separated by ";".'))
        parser.add_argument(
            '--provider',
            required=True,
            help=_('Provider name of the load balancer service.'))
        availability_zone.add_az_hint_argument(parser, self.resource)

    def args2body(self, parsed_args):
        body = {}
        neutronV20.update_dict(parsed_args, body,
                               ['user_id', 'node_ip',
                                'provider', 'tenant_id'])
        availability_zone.args2body_az_hint(parsed_args, body)
        return {self.resource: body}


class UpdateUserDeviceMap(neutronV20.UpdateCommand):
    """LBaaS v2 Update a given user_device_map."""

    resource = 'user_device_map'
    shadow_resource = 'lbaas_user_device_map'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--node-ip',
            help=_('IP addresses of the devices. '
                   'The IP addresses in the cluster are separated by ",", '
                   'and the clusters are separated by ";".'))
        availability_zone.add_az_hint_argument(parser, self.resource)

    def args2body(self, parsed_args):
        body = {}
        neutronV20.update_dict(parsed_args, body,
                               ['node_ip'])
        availability_zone.args2body_az_hint(parsed_args, body)
        return {self.resource: body}


class DeleteUserDeviceMap(neutronV20.DeleteCommand):
    """LBaaS v2 Delete a given user_device_map."""

    resource = 'user_device_map'
    shadow_resource = 'lbaas_user_device_map'
