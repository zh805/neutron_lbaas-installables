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

from neutron_lib.api import converters
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

class EntityNotFound(nexception.NotFound):
    message = _("%(name)s %(id)s could not be found")

class DBOperationFailed(nexception.NeutronException):
    message = _("DB operation %(operation)s failed.")

class IPAddressInvalid(nexception.InvalidInput):
    message = _("%(str)s is invalid, please check. "
                "The IP addresses in the cluster are separated by ',', "
                "and the clusters are separated by ';'.")

class NodeIpNotFound(nexception.NotFound):
    message = _("node_ip %(node_ip)s not found, please check. ")

RESOURCE_ATTRIBUTE_MAP = {
    'user_device_maps': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},

        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},

        'user_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'default': None, 'is_visible': True},

        'node_ip': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                   'default': None, 'is_visible': True},

        'provider': {'allow_post': True, 'allow_put': False,
                     'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                     'default': None, 'is_visible': True},

        'availability_zone_hints': {'allow_post': True, 'allow_put': True,
                                    'convert_to': converters.convert_to_list,
                                    'validate': {'type:az_list_or_none': None},
                                    'default': None,'is_visible': True}
    }
}

class Lb_user_device_map(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "user_device_map capabilities for LBaaSv2"

    @classmethod
    def get_alias(cls):
        return "lb_user_device_map"

    @classmethod
    def get_description(cls):
        return "Adding loadbalancer user device map support for LBaaSv2"

    @classmethod
    def get_namespace(cls):
        return "LBaaSv2 user device map function"

    @classmethod
    def get_updated(cls):
        return "2021-10-25T10:00:00-00:00"

    def get_required_extensions(self):
        return ["lbaasv2"]

    @classmethod
    def get_resources(cls):
        lb_user_device_map_plurals = [(key, key[:-1])
                       for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        plural_mappings = resource_helper.build_plural_mappings(
            dict(lb_user_device_map_plurals), RESOURCE_ATTRIBUTE_MAP)
        action_map = {}
        resources = resource_helper.build_resource_info(
            plural_mappings, RESOURCE_ATTRIBUTE_MAP,
            constants.LOADBALANCERV2, action_map=action_map,
            translate_name=True, register_quota=True)
        return resources

    @classmethod
    def get_plugin_interface(cls):
        return loadbalancerv2.LoadBalancerPluginBaseV2

    def update_attributes_map(self, attributes, extension_attrs_map=None):
        super(Lb_user_device_map, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
