# Copyright 2020 CMSS.
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
from __future__ import print_function

from neutronclient._i18n import _
from neutronclient.neutron import v2_0 as neutronV20


def _add_common_args(parser):
    parser.add_argument(
        '--name',
        help=_('Name of the LB-ACL group.'))
    parser.add_argument(
        '--description',
        help=_('Description of the LB-ACL group.'))


def _common_args2body(parsed_args):
    attributes = ['name', 'description', 'region']
    body = {}
    neutronV20.update_dict(parsed_args, body, attributes)
    return {'acl_group': body}


class CreateACLGroup(neutronV20.CreateCommand):
    """LBaaS v2 Create a LB-ACL Group."""

    resource = 'acl_group'
    shadow_resource = 'lbaas_acl_group'

    def add_known_arguments(self, parser):
        _add_common_args(parser)
        parser.add_argument(
            'region', metavar='REGION',
            help=_('Region is required for LB-ACL group.'))

    def args2body(self, parsed_args):
        return _common_args2body(parsed_args)


class ListACLGroup(neutronV20.ListCommand):
    """LBaaS v2 List all LB-ACL Groups."""

    resource = 'acl_group'
    shadow_resource = 'lbaas_acl_group'

    list_columns = [
        'id', 'name', 'description', 'region'
    ]
    pagination_support = True
    sorting_support = True


class ShowACLGroup(neutronV20.ShowCommand):
    """LBaaS v2 Show information of a given LB-ACL Group."""

    resource = 'acl_group'
    shadow_resource = 'lbaas_acl_group'


class UpdateACLGroup(neutronV20.UpdateCommand):
    """LBaaS v2 Update a given LB-ACL Group."""

    resource = 'acl_group'
    shadow_resource = 'lbaas_acl_group'

    def add_known_arguments(self, parser):
        _add_common_args(parser)

    def args2body(self, parsed_args):
        return _common_args2body(parsed_args)


class DeleteACLGroup(neutronV20.DeleteCommand):
    """LBaaS v2 Delete a given LB-ACL Group."""

    resource = 'acl_group'
    shadow_resource = 'lbaas_acl_group'


class AddListenerACL(neutronV20.NeutronCommand):
    """LBaaS v2 Add LB-ACL group to a given listener."""

    resource = 'acl_group'
    shadow_resource = 'lbaas_acl_group'

    def call_api(self, neutron_client, acl_group_id, body):
        return neutron_client.add_lbaas_acl_to_listener(
            acl_group_id, body)

    def success_message(self, acl_group_id, response_dict):
        return (_('Bind LB-ACL group %(acl_group)s to '
                  'listener %(listener)s.') %
                {'acl_group': acl_group_id,
                 'listener': response_dict['listener_id']})

    def get_parser(self, prog_name):
        parser = super(AddListenerACL, self).get_parser(prog_name)
        parser.add_argument(
            'acl_group', metavar='LB-ACL-GROUP',
            help=_('ID or name of the LB-ACL group.'))
        parser.add_argument(
            'listener', metavar='LISTENER',
            help=_('ID or name of the listener.'))
        parser.add_argument(
            '--type', required=True,
            help=_('Type of the bind mode: '
                   '[whitelist, blacklist]'))
        parser.add_argument(
            '--enabled',
            help=_('Enable the LB-ACL group when '
                   'binding it to the listener.')
        )
        return parser

    def take_action(self, parsed_args):
        neutron_client = self.get_client()
        _acl_group_id = neutronV20.find_resourceid_by_name_or_id(
            neutron_client, self.resource, parsed_args.acl_group)
        _listener_id = neutronV20.find_resourceid_by_name_or_id(
            neutron_client, 'listener', parsed_args.listener)

        body = {'listener_id': _listener_id,
                'type': parsed_args.type}
        if parsed_args.enabled is not None:
            body['enabled'] = parsed_args.enabled
        else:
            body['enabled'] = True

        response_dict = self.call_api(neutron_client, _acl_group_id, body)
        print(self.success_message(parsed_args.acl_group,
                                   response_dict),
              file=self.app.stdout)


class RemoveListenerACL(neutronV20.NeutronCommand):
    """LBaaS v2 Remove LB-ACL group from a given listener."""

    resource = 'acl_group'
    shadow_resource = 'lbaas_acl_group'

    def call_api(self, neutron_client, acl_group_id, body):
        return neutron_client.remove_lbaas_acl_from_listener(
            acl_group_id, body)

    def success_message(self, acl_group_id, response_dict):
        return (_('Unbind LB-ACL group %(acl_group)s from '
                  'listener %(listener)s.') %
                {'acl_group': acl_group_id,
                 'listener': response_dict['listener_id']})

    def get_parser(self, prog_name):
        parser = super(RemoveListenerACL, self).get_parser(prog_name)
        parser.add_argument(
            'acl_group', metavar='LB-ACL-GROUP',
            help=_('ID or name of the LB-ACL group.'))
        parser.add_argument(
            'listener', metavar='LISTENER',
            help=_('ID or name of the listener.'))
        return parser

    def take_action(self, parsed_args):
        neutron_client = self.get_client()
        _acl_group_id = neutronV20.find_resourceid_by_name_or_id(
            neutron_client, self.resource, parsed_args.acl_group)
        _listener_id = neutronV20.find_resourceid_by_name_or_id(
            neutron_client, 'listener', parsed_args.listener)

        body = {'listener_id': _listener_id}

        response_dict = self.call_api(neutron_client, _acl_group_id, body)
        print(self.success_message(parsed_args.acl_group,
                                   response_dict),
              file=self.app.stdout)


class FlushACLGroupRules(neutronV20.NeutronCommand):
    """LBaaS v2 Clean up a given LB-ACL group rules."""

    resource = 'acl_group'
    shadow_resource = 'lbaas_acl_group'

    def call_api(self, neutron_client, acl_group_id):
        return neutron_client.flush_lbaas_acl_group_rules(acl_group_id)

    def success_message(self, acl_group_id):
        return (_('ACL rules of LB-ACL group %(acl_group)s '
                  'have been cleaned up.') %
                {'acl_group': acl_group_id})

    def get_parser(self, prog_name):
        parser = super(FlushACLGroupRules, self).get_parser(prog_name)
        parser.add_argument(
            'acl_group', metavar='LB-ACL-GROUP',
            help=_('ID or name of the LB-ACL group.'))
        return parser

    def take_action(self, parsed_args):
        neutron_client = self.get_client()
        _acl_group_id = neutronV20.find_resourceid_by_name_or_id(
            neutron_client, self.resource, parsed_args.acl_group)
        self.call_api(neutron_client, _acl_group_id)
        print(self.success_message(parsed_args.acl_group),
              file=self.app.stdout)
