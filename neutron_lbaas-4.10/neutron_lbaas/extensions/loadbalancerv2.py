# Copyright 2014 OpenStack Foundation.
# All Rights Reserved.
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


import abc

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import validators
from neutron_lib import constants as n_constants
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as nexception
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.quota import resource_registry

from neutron_lbaas._i18n import _
from neutron_lbaas.services.loadbalancer import constants as lb_const

LOADBALANCERV2_PREFIX = "/lbaas"

LOG = logging.getLogger(__name__)


# Loadbalancer Exceptions
# This exception is only for a workaround when having v1 and v2 lbaas extension
# and plugins enabled
class FlavorNotSupportedByProvider(nexception.BadRequest):
    message = _("LBaaS provider %(provider_name)s does not support "
                "flavor %(flavor_num)s. \n"
                "Notice: haproxy, brocade and nokia support flavor 1, "
                "while other providers support flavor 1-6")


class RequiredAttributeNotSpecified(nexception.BadRequest):
    message = _("Required attribute %(attr_name)s not specified")


class EntityNotFound(nexception.NotFound):
    message = _("%(name)s %(id)s could not be found")


class DelayOrTimeoutInvalid(nexception.BadRequest):
    message = _("Delay must be greater than or equal to timeout")


class EntityInUse(nexception.InUse):
    message = _("%(entity_using)s %(id)s is using this %(entity_in_use)s")


class OnePoolPerListener(nexception.InUse):
    message = _("Only one pool per listener allowed.  Listener "
                "%(listener_id)s is already using Pool %(pool_id)s.")


class OneHealthMonitorPerPool(nexception.InUse):
    message = _("Only one health monitor per pool allowed.  Pool %(pool_id)s"
                " is already using Health Monitor %(hm_id)s.")


class LoadBalancerListenerProtocolPortExists(nexception.Conflict):
    message = _("Load Balancer %(lb_id)s already has a listener with "
                "protocol_port of %(protocol_port)s")


class ListenerPoolProtocolMismatch(nexception.Conflict):
    message = _("Listener protocol %(listener_proto)s and pool protocol "
                "%(pool_proto)s are not compatible.")


class AttributeIDImmutable(nexception.NeutronException):
    message = _("Cannot change %(attribute)s if one already exists")


class StateInvalid(nexception.Conflict):
    message = _("Invalid state %(state)s of loadbalancer resource %(id)s")


class MemberNotFoundForPool(nexception.NotFound):
    message = _("Member %(member_id)s could not be found in pool "
                "%(pool_id)s")


class MemberExists(nexception.Conflict):
    message = _("Member with address %(address)s and protocol_port %(port)s "
                "already present in pool %(pool)s")


class MembersExists(nexception.Conflict):
    message = _("Members already present in pool %(pool)s")


class MemberAddressTypeSubnetTypeMismatch(nexception.NeutronException):
    message = _("Member with address %(address)s and subnet %(subnet_id) "
                "have mismatched IP versions")


class MutualAuthContainerNotFound(nexception.NotFound):
    message = _("Container for mutual auth %(container_id)s"
                "could not be found")


class MutualAuthContainerNotProvided(nexception.BadRequest):
    message = _("Try to enable mutual auth, but container id"
                " is not provided")


class DriverError(nexception.NeutronException):
    message = _("Driver error: %(msg)s")


class SessionPersistenceConfigurationInvalid(nexception.BadRequest):
    message = _("Session Persistence Invalid: %(msg)s")


class TLSDefaultContainerNotSpecified(nexception.BadRequest):
    message = _("Default TLS container was not specified")


class TLSContainerNotFound(nexception.NotFound):
    message = _("TLS container %(container_id)s could not be found")


class TLSContainerInvalid(nexception.NeutronException):
    message = _("TLS container %(container_id)s is invalid. %(reason)s")

class TLSProtocolInvalid(nexception.BadRequest):
    message = _("TLS protocol %(tls_protocols)s is invalid.")

class TLSCipherNotSupport(nexception.BadRequest):
    message = _("TLS protocol %(tls_protocols)s is not support %(cipher_suites)s.")

class TLSCipherInvalid(nexception.BadRequest):
    message = _("TLS protocol %(tls_protocols)s is contains TLS1.3, but %(cipher_suites)s has not contained "
                "ciphers for protocol TLS1.3.")

class CertManagerError(nexception.NeutronException):
    message = _("Could not process TLS container %(ref)s, %(reason)s")


class ProviderFlavorConflict(nexception.Conflict):
    message = _("Cannot specify both a flavor and a provider")


class FlavorsPluginNotLoaded(nexception.NotFound):
    message = _("Flavors plugin not found")


class EnableTransparentInvalid(nexception.BadRequest):
    message = _("Try enable transparent for listener "
                "whose protocol is %(protocol)s")


class NamespaceIptablesConfigFail(nexception.BadRequest):
    message = _("Fail to config lbaas namespace iptables when apply "
                "command %(cmd)s")


class LoadbalancerAZNotConfig(nexception.BadRequest):
    message = _("availability_zones_configuration_enable is False, "
                "it couldn't specify az info for loadbalancer service.")


class LoadbalancerAZAreSame(nexception.BadRequest):
    message = _("There has some same az %(availability_zones)s was exist.")


class LoadbalancerAZNotFound(nexception.BadRequest):
    message = _("The specified az %(availability_zones)s wasn't exist, "
                "there only have %(azs)s in the configuration.")


def _validate_connection_limit(data, min_value=lb_const.MIN_CONNECT_VALUE):
    if int(data) < min_value:
        msg = (_("'%(data)s' is not a valid value, "
                 "because it cannot be less than %(min_value)s") %
               {'data': data, 'min_value': min_value})
        LOG.debug(msg)
        return msg


def _validate_bw_conf_and_value(data, key_specs=None):
    if not cfg.CONF.extra.enable_bw:
        if data is not None:
            msg = (_("Please check the config of lbaas, bandwidth should "
                     "not be used while enable_bw is set to False"))
            raise nexception.InvalidInput(error_message=msg)
    else:
        if data is not None:
            converters.convert_to_int(data)
        else:
            msg = (_("'enable_bw' is set to True, there must be an int "
                     "value for loadbalancer bandwidth"))
            raise nexception.InvalidInput(error_message=msg)


def _validate_az_list_or_none(data, max_len=None):
    if data is not None:
        return validators.validate_list_of_unique_strings(data, max_len)


validators.validators['type:connection_limit'] = _validate_connection_limit
validators.validators['type:conf_bw'] = _validate_bw_conf_and_value
validators.add_validator('type:az_list_or_none',
                         _validate_az_list_or_none)


RESOURCE_ATTRIBUTE_MAP = {
    'loadbalancers': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'default': '',
                 'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:not_empty_string':
                                   db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {
                            'type:string': db_const.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'vip_subnet_id': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:uuid': None},
                          'is_visible': True},
        'vip_address': {'allow_post': True, 'allow_put': False,
                        'default': n_constants.ATTR_NOT_SPECIFIED,
                        'validate': {'type:ip_address_or_none': None},
                        'is_visible': True},
        'vip_port_id': {'allow_post': False, 'allow_put': False,
                        'is_visible': True},
        'provider': {'allow_post': True, 'allow_put': False,
                     'validate': {'type:string': None}, 'is_visible': True,
                     'default': n_constants.ATTR_NOT_SPECIFIED},
        'listeners': {'allow_post': False, 'allow_put': False,
                      'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': converters.convert_to_boolean,
                           'is_visible': True},
        'provisioning_status': {'allow_post': False, 'allow_put': False,
                                'is_visible': True},
        'operating_status': {'allow_post': False, 'allow_put': False,
                             'is_visible': True},
        'flavor_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': True,
                      'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                      'default': n_constants.ATTR_NOT_SPECIFIED},
        'bandwidth': {'allow_post': True, 'allow_put': True,
                      'validate': {'type:conf_bw': None},
                      'default': None, 'is_visible': True},
        'availability_zone_hints': {'allow_post': True, 'allow_put': False,
                                    'convert_to': converters.convert_to_list,
                                    'validate': {'type:az_list_or_none': None},
                                    'is_visible': True,
                                    'default': None},
        'flavor': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:range': [1, 6]},
                   'default': 1,
                   'convert_to': converters.convert_to_int,
                   'is_visible': True},
    },
    'listeners': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:not_empty_string':
                                   db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {
                            'type:string': db_const.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'loadbalancer_id': {'allow_post': True, 'allow_put': False,
                            'validate': {'type:uuid': None},
                            'is_visible': False},
        'loadbalancers': {'allow_post': False, 'allow_put': False,
                          'is_visible': True},
        'default_pool_id': {'allow_post': False, 'allow_put': False,
                            'validate': {'type:uuid': None},
                            'is_visible': True},
        'default_tls_container_ref': {'allow_post': True,
                                      'allow_put': True,
                                      'default': None,
                                      'validate': {'type:string_or_none': 128},
                                      'is_visible': True},
        'sni_container_refs': {'allow_post': True, 'allow_put': True,
                               'default': None,
                               'convert_to': converters.convert_to_list,
                               'is_visible': True},
        'connection_limit': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:connection_limit':
                                          lb_const.MIN_CONNECT_VALUE},
                             'default': lb_const.MIN_CONNECT_VALUE,
                             'convert_to': converters.convert_to_int,
                             'is_visible': True},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'validate': {'type:values':
                                  lb_const.LISTENER_SUPPORTED_PROTOCOLS},
                     'is_visible': True},
        'protocol_port': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:range': [0, 65535]},
                          'convert_to': converters.convert_to_int,
                          'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': converters.convert_to_boolean,
                           'is_visible': True},
        'transparent': {'allow_post': True, 'allow_put': True,
                        'default': False,
                        'convert_to': converters.convert_to_boolean,
                        'is_visible': True},
        'mutual_authentication_up': {
            'allow_post': True, 'allow_put': True,
            'default': False, 'convert_to': converters.convert_to_boolean,
            'is_visible': True},
        'ca_container_id': {'allow_post': True, 'allow_put': True,
                            'default': None,
                            'validate': {'type:string_or_none': 128},
                            'is_visible': True},
        'redirect_up': {'allow_post': True, 'allow_put': True,
                        'default': False,
                        'convert_to': converters.convert_to_boolean,
                        'is_visible': True},
        'redirect_protocol': {'allow_post': True, 'allow_put': True,
                              'default': None,
                              'is_visible': True},
        'redirect_port': {'allow_post': True, 'allow_put': True,
                          'default': 0,
                          'validate': {'type:range': [0, 65535]},
                          'convert_to': converters.convert_to_int,
                          'is_visible': True},
        'http2': {'allow_post': True, 'allow_put': True,
                  'default': False,
                  'convert_to': converters.convert_to_boolean,
                  'is_visible': True},
        'tls_protocols': {'allow_post': True,
                          'allow_put': True,
                          'default': None,
                          'validate': {'type:string_or_none': 128},
                          'is_visible': True},
        'cipher_suites': {'allow_post': True,
                          'allow_put': True,
                          'default': None,
                          'validate': {'type:string_or_none': 1024},
                          'is_visible': True},
        'customized': {'allow_post': True, 'allow_put': True,
            'default': None,
            'validate': {'type:string_or_none': None},
            'is_visible': True}
    },
    'pools': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:not_empty_string':
                                   db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {
                            'type:string': db_const.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'listener_id': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:uuid': None},
                        'is_visible': False},
        'listeners': {'allow_post': False, 'allow_put': False,
                      'is_visible': True},
        'healthmonitor_id': {'allow_post': False, 'allow_put': False,
                             'validate': {'type:uuid': None},
                             'is_visible': True},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'validate': {'type:values':
                                  lb_const.POOL_SUPPORTED_PROTOCOLS},
                     'is_visible': True},
        'lb_algorithm': {'allow_post': True, 'allow_put': True,
                         'validate': {
                             'type:values': lb_const.SUPPORTED_LB_ALGORITHMS},
                         'is_visible': True},
        'session_persistence': {
            'allow_post': True, 'allow_put': True,
            'convert_to': converters.convert_none_to_empty_dict,
            'default': {},
            'validate': {
                'type:dict_or_empty': {
                    'type': {
                        'type:values': lb_const.SUPPORTED_SP_TYPES,
                        'required': True},
                    'cookie_name': {'type:string': None,
                                    'required': False},
                    'persistence_timeout': {
                        'convert_to': converters.convert_to_int,
                        'type:integer': None,
                        'required': False}}},
            'is_visible': True},
        'members': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': converters.convert_to_boolean,
                           'is_visible': True}
    },
    'healthmonitors': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:not_empty_string':
                                   db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True,
                      'is_visible': True},
        'pool_id': {'allow_post': True, 'allow_put': False,
                    'validate': {'type:uuid': None},
                    'is_visible': False},
        'pools': {'allow_post': False, 'allow_put': False,
                  'is_visible': True},
        'type': {'allow_post': True, 'allow_put': False,
                 'validate': {
                     'type:values': lb_const.SUPPORTED_HEALTH_MONITOR_TYPES},
                 'is_visible': True},
        'delay': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:non_negative': None},
                  'convert_to': converters.convert_to_int,
                  'is_visible': True},
        'timeout': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:non_negative': None},
                    'convert_to': converters.convert_to_int,
                    'is_visible': True},
        'max_retries': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:range': [1, 10]},
                        'convert_to': converters.convert_to_int,
                        'is_visible': True},
        'http_method': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:values':
                                     lb_const.SUPPORTED_HTTP_METHODS},
                        'default': 'GET',
                        'is_visible': True},
        'url_path': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:regex_or_none':
                                  lb_const.SUPPORTED_URL_PATH},
                     'default': '/',
                     'is_visible': True},
        'expected_codes': {
            'allow_post': True,
            'allow_put': True,
            'validate': {
                'type:regex': r'^(\d{3}(\s*,\s*\d{3})*)$|^(\d{3}-\d{3})$'
            },
            'default': '200',
            'is_visible': True
        },
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': converters.convert_to_boolean,
                           'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'default': '',
                 'is_visible': True}
    }
}

SUB_RESOURCE_ATTRIBUTE_MAP = {
    'members': {
        'parent': {'collection_name': 'pools',
                   'member_name': 'pool'},
        'parameters': {
            'id': {'allow_post': False, 'allow_put': False,
                   'validate': {'type:uuid': None},
                   'is_visible': True,
                   'primary_key': True},
            'tenant_id': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:not_empty_string':
                                       db_const.PROJECT_ID_FIELD_SIZE},
                          'required_by_policy': True,
                          'is_visible': True},
            'address': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:ip_address': None},
                        'is_visible': True},
            'protocol_port': {'allow_post': True, 'allow_put': False,
                              'validate': {'type:range': [1, 65535]},
                              'convert_to': converters.convert_to_int,
                              'is_visible': True},
            'weight': {'allow_post': True, 'allow_put': True,
                       'default': 1,
                       'validate': {'type:range': [0, 256],
                                    'type:integer': None},
                       'is_visible': True},
            'admin_state_up': {'allow_post': True, 'allow_put': True,
                               'default': True,
                               'convert_to': converters.convert_to_boolean,
                               'is_visible': True},
            'subnet_id': {'allow_post': True, 'allow_put': False,
                          'validate': {'type:uuid': None},
                          'is_visible': True},
            'name': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                     'default': '',
                     'is_visible': True},
            'member_status': {'allow_post': False, 'allow_put': False,
                              'is_visible': True}
        }
    }
}


DEFAULT_LOADBALANCER_QUOTA = -1
DEFAULT_LISTENER_QUOTA = -1
DEFAULT_POOL_QUOTA = -1
DEFAULT_MEMBER_QUOTA = -1
DEFAULT_HEALTHMONITOR = -1


lbaasv2_quota_opts = [
    cfg.IntOpt('quota_loadbalancer',
               default=DEFAULT_LOADBALANCER_QUOTA,
               help=_('Number of LoadBalancers allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_listener',
               default=DEFAULT_LISTENER_QUOTA,
               help=_('Number of Loadbalancer Listeners allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_pool',
               default=DEFAULT_POOL_QUOTA,
               help=_('Number of pools allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_member',
               default=DEFAULT_MEMBER_QUOTA,
               help=_('Number of pool members allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_healthmonitor',
               default=DEFAULT_HEALTHMONITOR,
               help=_('Number of health monitors allowed per tenant. '
                      'A negative value means unlimited.'))
]
cfg.CONF.register_opts(lbaasv2_quota_opts, 'QUOTAS')


lbaasv2_extra_opts = [
    cfg.BoolOpt('enable_bw',
                default=False,
                help=_('Allow set bandwidth to loadbalancer. '
                       'This is for nuage.')),
    cfg.BoolOpt('enable_member_status',
                default=False,
                help=_('Allow member show and member list get member_status '
                       'information'))
]
cfg.CONF.register_opts(lbaasv2_extra_opts, 'extra')


class Loadbalancerv2(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "LoadBalancing service v2"

    @classmethod
    def get_alias(cls):
        return "lbaasv2"

    @classmethod
    def get_description(cls):
        return "Extension for LoadBalancing service v2"

    @classmethod
    def get_updated(cls):
        return "2014-06-18T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        action_map = {'loadbalancer': {'stats': 'GET', 'statuses': 'GET'}}
        plural_mappings['members'] = 'member'
        resource_registry.register_resource_by_name('member', 'members')
        plural_mappings['sni_container_refs'] = 'sni_container_ref'
        plural_mappings['sni_container_ids'] = 'sni_container_id'
        resources = resource_helper.build_resource_info(
            plural_mappings,
            RESOURCE_ATTRIBUTE_MAP,
            constants.LOADBALANCERV2,
            action_map=action_map,
            register_quota=True)
        plugin = directory.get_plugin(constants.LOADBALANCERV2)
        for collection_name in SUB_RESOURCE_ATTRIBUTE_MAP:
            # Special handling needed for sub-resources with 'y' ending
            # (e.g. proxies -> proxy)
            resource_name = collection_name[:-1]
            parent = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get('parent')
            params = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
                'parameters')

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
        return LoadBalancerPluginBaseV2

    def update_attributes_map(self, attributes, extension_attrs_map=None):
        super(Loadbalancerv2, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class LoadBalancerPluginBaseV2(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return constants.LOADBALANCERV2

    def get_plugin_type(self):
        return constants.LOADBALANCERV2

    def get_plugin_description(self):
        return 'LoadBalancer service plugin v2'

    @abc.abstractmethod
    def get_loadbalancers(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_loadbalancer(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_loadbalancer(self, context, loadbalancer):
        pass

    @abc.abstractmethod
    def update_loadbalancer(self, context, id, loadbalancer):
        pass

    @abc.abstractmethod
    def delete_loadbalancer(self, context, id):
        pass

    @abc.abstractmethod
    def create_listener(self, context, listener):
        pass

    @abc.abstractmethod
    def get_listener(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_listeners(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def update_listener(self, context, id, listener):
        pass

    @abc.abstractmethod
    def delete_listener(self, context, id):
        pass

    @abc.abstractmethod
    def get_pools(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_pool(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_pool(self, context, pool):
        pass

    @abc.abstractmethod
    def update_pool(self, context, id, pool):
        pass

    @abc.abstractmethod
    def delete_pool(self, context, id):
        pass

    @abc.abstractmethod
    def stats(self, context, loadbalancer_id):
        pass

    @abc.abstractmethod
    def get_pool_members(self, context, pool_id,
                         filters=None,
                         fields=None):
        pass

    @abc.abstractmethod
    def get_pool_member(self, context, id, pool_id,
                        fields=None):
        pass

    @abc.abstractmethod
    def create_pool_member(self, context, pool_id, member):
        pass

    @abc.abstractmethod
    def update_pool_member(self, context, id, pool_id, member):
        pass

    @abc.abstractmethod
    def delete_pool_member(self, context, id, pool_id):
        pass

    @abc.abstractmethod
    def get_healthmonitors(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_healthmonitor(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_healthmonitor(self, context, healthmonitor):
        pass

    @abc.abstractmethod
    def update_healthmonitor(self, context, id, healthmonitor):
        pass

    @abc.abstractmethod
    def delete_healthmonitor(self, context, id):
        pass

    @abc.abstractmethod
    def get_members(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_member(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def statuses(self, context, loadbalancer_id):
        pass

    @abc.abstractmethod
    def get_l7policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_l7policy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_l7policy(self, context, l7policy):
        pass

    @abc.abstractmethod
    def update_l7policy(self, context, id, l7policy):
        pass

    @abc.abstractmethod
    def delete_l7policy(self, context, id):
        pass

    @abc.abstractmethod
    def get_l7policy_rules(self, context, l7policy_id,
                           filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_l7policy_rule(self, context, id, l7policy_id, fields=None):
        pass

    @abc.abstractmethod
    def create_l7policy_rule(self, context, rule, l7policy_id):
        pass

    @abc.abstractmethod
    def update_l7policy_rule(self, context, id, rule, l7policy_id):
        pass

    @abc.abstractmethod
    def delete_l7policy_rule(self, context, id, l7policy_id):
        pass

    @abc.abstractmethod
    def create_graph(self, context, graph):
        pass

    @abc.abstractmethod
    def create_acl_group(self, context, acl_group):
        pass

    @abc.abstractmethod
    def delete_acl_group(self, context, id):
        pass

    @abc.abstractmethod
    def update_acl_group(self, context, id, acl_group):
        pass

    @abc.abstractmethod
    def get_acl_groups(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_acl_group(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_acl_group_acl_rule(self, context, acl_group_id, acl_rule):
        pass

    @abc.abstractmethod
    def delete_acl_group_acl_rule(self, context, id, acl_group_id):
        pass

    @abc.abstractmethod
    def update_acl_group_acl_rule(self, context, id, acl_group_id, acl_rule):
        pass

    @abc.abstractmethod
    def get_acl_group_acl_rules(self, context,
                                acl_group_id, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_acl_group_acl_rule(self, context, id, acl_group_id, fields=None):
        pass

    @abc.abstractmethod
    def flush_acl_rules(self, context, acl_group_id):
        pass

    @abc.abstractmethod
    def add_listener(self, context, acl_group_id, binding_info):
        pass

    @abc.abstractmethod
    def remove_listener(self, context, acl_group_id, binding_info):
        pass
