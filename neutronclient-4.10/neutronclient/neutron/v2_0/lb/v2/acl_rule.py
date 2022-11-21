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

from neutronclient._i18n import _
from neutronclient.neutron import v2_0 as neutronV20


def _get_acl_group_id(client, acl_group_id_or_name):
    return neutronV20.find_resourceid_by_name_or_id(
        client, 'acl_group', acl_group_id_or_name)


def _add_common_args(parser):
    parser.add_argument(
        '--description',
        help=_('Description of LB-ACL rule.'))
    parser.add_argument(
        'acl_group', metavar='LB-ACL-GROUP',
        help=_('ID or name of the LB-ACL group '
               'that this LB-ACL rule belongs to.'))


def _common_args2body(parsed_args):
    attributes = ['description', 'ip_version', 'ip_address']
    body = {}
    neutronV20.update_dict(parsed_args, body, attributes)
    return {'acl_rule': body}


class LBaaSACLRuleMixin(object):

    def set_extra_attrs(self, parsed_args):
        self.parent_id = _get_acl_group_id(self.get_client(),
                                           parsed_args.acl_group)

    def add_known_arguments(self, parser):
        parser.add_argument(
            'acl_group', metavar='LB-ACL-GROUP',
            help=_('ID or name of the LB-ACL group '
                   'that this LB-ACL rule belongs to.'))


class CreateACLRule(neutronV20.CreateCommand):
    """LBaaS v2 Create a LB-ACL rule."""

    resource = 'acl_rule'
    shadow_resource = 'lbaas_acl_rule'

    def add_known_arguments(self, parser):
        _add_common_args(parser)
        parser.add_argument(
            '--ip-version', dest='ip_version',
            help=_('IP version of LB-ACL rule (default:IPv4, [IPv4, IPv6]).'))
        parser.add_argument(
            '--ip-address', dest='ip_address',
            required=True,
            help=_('IP address of LB-ACL rule.'))

    def args2body(self, parsed_args):
        self.parent_id = _get_acl_group_id(
            self.get_client(), parsed_args.acl_group)
        return _common_args2body(parsed_args)


class DeleteACLRule(LBaaSACLRuleMixin, neutronV20.DeleteCommand):
    """LBaaS v2 Delete a given LB-ACL rule."""

    resource = 'acl_rule'
    shadow_resource = 'lbaas_acl_rule'


class UpdateACLRule(neutronV20.UpdateCommand):
    """LBaaS v2 Update a given LB-ACL rule."""

    resource = 'acl_rule'
    shadow_resource = 'lbaas_acl_rule'

    def add_known_arguments(self, parser):
        _add_common_args(parser)
        parser.add_argument(
            '--ip-address', dest='ip_address',
            help=_('IP address of LB-ACL rule.'))

    def args2body(self, parsed_args):
        self.parent_id = _get_acl_group_id(
            self.get_client(), parsed_args.acl_group)
        return _common_args2body(parsed_args)


class ShowACLRule(LBaaSACLRuleMixin, neutronV20.ShowCommand):
    """LBaaS v2 Show information of a given LB-ACL Rule."""

    resource = 'acl_rule'
    shadow_resource = 'lbaas_acl_rule'


class ListACLRule(LBaaSACLRuleMixin, neutronV20.ListCommand):
    """LBaaS v2 List LB-ACL rules
    that belong to a given LB-ACL group.
    """

    resource = 'acl_rule'
    shadow_resource = 'lbaas_acl_rule'

    list_columns = [
        'id', 'description', 'ip_version', 'ip_address']
    pagination_support = True
    sorting_support = True
