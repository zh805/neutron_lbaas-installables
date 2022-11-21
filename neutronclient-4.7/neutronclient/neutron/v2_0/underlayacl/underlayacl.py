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


class ListUnderlayAcl(neutronv20.ListCommand):
    """List underlayacls that belong to a given tenant."""

    resource = 'underlayacl'
    list_columns = ['id', 'name', 'description', 'project_id', 'vpc_id']
    _formatters = {}
    pagination_support = True
    sorting_support = True


class ShowUnderlayAcl(neutronv20.ShowCommand):
    """Show details of a given vpc connection."""

    resource = 'underlayacl'


class CreateUnderlayAcl(neutronv20.CreateCommand):
    """Create a underlayacl."""

    resource = 'underlayacl'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Set name for the underlayacl.'))
        parser.add_argument(
            '--description',
            help=_('Set description for the underlayacl.'))
        parser.add_argument(
            'vpc', metavar='VPC',
            help=_('Set router for underlayacl.'))

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }
        neutron_client = self.get_client()
        if parsed_args.vpc:
            vpc_id = neutronv20.find_resourceid_by_name_or_id(
                neutron_client, 'router', parsed_args.vpc)
            body[self.resource].update({'vpc_id': vpc_id})

        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description',
                                'tenant_id'])
        return body


class UpdateUnderlayAcl(neutronv20.UpdateCommand):
    """Update a given underlayacl"""

    resource = 'underlayacl'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--name',
            help=_('Update name for underlayacl.')
        )
        parser.add_argument(
            '--description',
            help=_('Update description for underlayacl.')
        )

    def args2body(self, parsed_args):
        body = {
            self.resource: {}
        }

        neutronv20.update_dict(parsed_args, body[self.resource],
                               ['name', 'description'])
        return body


class DeleteUnderlayAcl(neutronv20.DeleteCommand):
    """Delete a given underlayacl."""

    resource = 'underlayacl'
