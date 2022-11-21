# Copyright 2020 CMSS.
#
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

from neutron_lib.api import extensions as api_extensions
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as nexception
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper

from neutron_lbaas._i18n import _
from neutron_lbaas.extensions import loadbalancerv2
from neutron_lbaas.services.loadbalancer import constants as lb_const

LOADBALANCERV2_PREFIX = "/lbaas"


class ACLGroupInUse(nexception.InUse):
    message = _("Fail to delete the ACL Group %(acl_group_id)s"
                ", as it is used by Listeners.")


class ACLRuleIpAddressConflict(nexception.BadRequest):
    message = _("Invalid input - IP addresses do not agree with IP Version.")


class DBOperationFailed(nexception.NeutronException):
    message = _("DB operation %(operation)s failed.")


class DuplicateBindListenerWithACL(nexception.BadRequest):
    message = _("The listener %(listener_id)s has already bound "
                "with an ACL group %(acl_group_id)s.")


class InvalidRegionForACLGroup(nexception.BadRequest):
    message = _("Invalid input - Invalid region for the ACL Group.")


class MissingOrInvalidBindingInfo(nexception.BadRequest):
    message = _("Missing or invalid %(info_type)s in binding info.")


class NonexistentRelationShip(nexception.BadRequest):
    message = _("There is no relationship between listener %(listener_id)s "
                "and ACL group %(acl_group_id)s .")


RESOURCE_ATTRIBUTE_MAP = {
    'acl_groups': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate':
                          {'type:string': db_const.NAME_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate':
                            {'type:string': db_const.
                                DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'region': {'allow_post': True, 'allow_put': False,
                   'validate': {'type:string': None},
                   'is_visible': True},
        'acl_rules': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:uuid_list': None},
                      'is_visible': True},
        'listeners': {'allow_post': False, 'allow_put': False,
                      'validate': {'type:uuid_list': None},
                      'is_visible': True}
    }

}

SUB_RESOURCE_ATTRIBUTE_MAP = {
    'acl_rules': {
        'parent': {'collection_name': 'acl-groups',
                   'member_name': 'acl_group'},
        'parameters': {
            'id': {'allow_post': False, 'allow_put': False,
                   'validate': {'type:uuid': None},
                   'is_visible': True,
                   'primary_key': True},
            'tenant_id': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:string': None},
                          'required_by_policy': True,
                          'is_visible': True},
            'description': {'allow_post': True, 'allow_put': True,
                            'validate':
                                {'type:string': db_const.
                                    DESCRIPTION_FIELD_SIZE},
                            'is_visible': True, 'default': ''},
            'ip_version': {'allow_post': True, 'allow_put': False,
                           'default': 'IPv4',
                           'validate': {
                               'type:values': lb_const.ACL_IP_VERSIONS},
                           'is_visible': True},
            'ip_address': {'allow_post': True, 'allow_put': True,
                           'validate': {'type:ip_or_subnet_or_none': None},
                           'is_visible': True},
        }
    }
}


class Acl(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "ACL capabilities for LBaaSv2"

    @classmethod
    def get_alias(cls):
        return "acl"

    @classmethod
    def get_description(cls):
        return "Adding acl groups and rules support for LBaaSv2"

    @classmethod
    def get_namespace(cls):
        return "LBaaSv2 ACL function"

    @classmethod
    def get_updated(cls):
        return "2020-05-08T10:00:00-00:00"

    def get_required_extensions(self):
        return ["lbaasv2"]

    @classmethod
    def get_resources(cls):
        acl_plurals = [(key, key[:-1])
                       for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        plural_mappings = resource_helper.build_plural_mappings(
            dict(acl_plurals), RESOURCE_ATTRIBUTE_MAP)

        action_map = {'acl_group': {'flush_acl_rules': 'PUT',
                                    'add_listener': 'PUT',
                                    'remove_listener': 'PUT'}}

        resources = resource_helper.build_resource_info(
            plural_mappings, RESOURCE_ATTRIBUTE_MAP,
            constants.LOADBALANCERV2, action_map=action_map,
            translate_name=True, register_quota=True)
        plugin = directory.get_plugin(constants.LOADBALANCERV2)

        for collection_name in SUB_RESOURCE_ATTRIBUTE_MAP:
            # Special handling needed for sub-resources with 'y' ending
            # (e.g. proxies -> proxy)
            resource_name = plural_mappings.get(collection_name,
                                                collection_name[:-1])
            parent = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get('parent')
            params = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
                'parameters')
            collection_name = collection_name.replace('_', '-')
            controller = base.create_resource(collection_name, resource_name,
                                              plugin, params,
                                              allow_bulk=True,
                                              parent=parent,
                                              allow_pagination=True,
                                              allow_sorting=True)

            resource = extensions.ResourceExtension(
                collection_name,
                controller, parent,
                path_prefix=LOADBALANCERV2_PREFIX,
                attr_map=params)
            resources.append(resource)

        return resources

    @classmethod
    def get_plugin_interface(cls):
        return loadbalancerv2.LoadBalancerPluginBaseV2

    def update_attributes_map(self, attributes, extension_attrs_map=None):
        super(Acl, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
