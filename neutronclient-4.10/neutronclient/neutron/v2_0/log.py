# Copyright 2018 China Mobile.
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

import argparse

from neutronclient._i18n import _
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronV20


SUPPORTED_LOG_TYPES = ['security_group']
SUPPORTED_EVENT_TYPES = ['ACCEPT', 'DROP', 'ALL']


class ListLog(neutronV20.ListCommand):
    """List log resource that belong to a given tenant."""

    resource = 'log'
    pagination_support = True
    sorting_support = True
    allow_names = False


class ShowLog(neutronV20.ShowCommand):
    """Show information of a given log resource."""

    resource = 'log'
    allow_names = False


class CreateLog(neutronV20.CreateCommand):
    """Create log resource."""

    resource = 'log'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('ID or name of the RBAC object.'))
        parser.add_argument(
            '--description',
            help=_('Description of the RBAC object.'))
        parser.add_argument(
            '--resource-type',
            required=True,
            choices=SUPPORTED_LOG_TYPES,
            help=_('Resource type of Log object.'))
        parser.add_argument(
            '--resource-id',
            help=_('Resource id of Log object.'))
        parser.add_argument(
            '--event',
            choices=SUPPORTED_EVENT_TYPES,
            default='ALL',
            help=_('Log event of Log object.'))
        parser.add_argument(
            '--target-id',
            help=_('Target id of Log object.'))
        utils.add_boolean_argument(
            parser,
            '--enabled',
            default=argparse.SUPPRESS,
            help=_('Sets enabled flag. Default is True.'))

    def args2body(self, parsed_args):
        neutron_client = self.get_client()
        body = {}
        if parsed_args.resource_type == 'security_group' \
                and parsed_args.resource_id is not None:
            resource_id = neutronV20.find_resourceid_by_name_or_id(
                client=neutron_client, resource='security_group',
                name_or_id=parsed_args.resource_id)
            if resource_id:
                body['resource_id'] = resource_id

        neutronV20.update_dict(parsed_args, body,
                               ['name', 'description', 'resource_type',
                                'event', 'target_id', 'enabled'])
        return {self.resource: body}


class UpdateLog(neutronV20.UpdateCommand):
    """Update log resource."""

    resource = 'log'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('ID or name of the RBAC object.'))
        parser.add_argument(
            '--description',
            help=_('Description of the RBAC object.'))
        utils.add_boolean_argument(
            parser,
            '--enabled',
            default=argparse.SUPPRESS,
            help=_('Sets enabled flag. Default is True.'))

    def args2body(self, parsed_args):
        body = {}
        neutronV20.update_dict(parsed_args, body,
                               ['name', 'description', 'enabled'])
        return {self.resource: body}


class DeleteLog(neutronV20.DeleteCommand):
    """Delete log resource"""

    resource = 'log'


class ListLoggableResourceTypes(neutronV20.ListCommand):
    """List supported log resource types"""

    resource = 'loggable_resource'
    pagination_support = True
    sorting_support = True
