#
# -*- coding: utf-8 -*-
# Copyright 2013 Radware LTD.
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

import copy
import netaddr

from neutron_lib import context as ncontext
from neutron_lib.plugins import directory

from neutron.api.v2 import attributes as attrs
from neutron.api.v2 import base as napi_base
from neutron.db import agentschedulers_db
from neutron.db import servicetype_db as st_db
from neutron.extensions import availability_zone as az_ext
from neutron.extensions import flavors
from neutron import service
from neutron.services.flavors import flavors_plugin
from neutron.services import provider_configuration as pconf
from neutron.services import service_base
from neutron_lib import constants as n_constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import encodeutils
from oslo_utils import strutils

from neutron_lbaas import agent_scheduler as agent_scheduler_v2
import neutron_lbaas.common.cert_manager
from neutron_lbaas.common.tls_utils import cert_parser
from neutron_lbaas.db.loadbalancer import loadbalancer_dbv2 as ldbv2
from neutron_lbaas.db.loadbalancer import models
from neutron_lbaas.extensions import acl as acl_ext
from neutron_lbaas.extensions import l7
from neutron_lbaas.extensions import lb_graph as lb_graph_ext
from neutron_lbaas.extensions import lbaas_agentschedulerv2
from neutron_lbaas.extensions import loadbalancerv2
from neutron_lbaas.extensions import sharedpools
from neutron_lbaas.services.loadbalancer import constants as lb_const
from neutron_lbaas.services.loadbalancer import data_models
LOG = logging.getLogger(__name__)
CERT_MANAGER_PLUGIN = neutron_lbaas.common.cert_manager.get_backend()
FLAVOR_UNEDITABLE_PROVIDER = ['haproxy', 'brocade', 'nokia']
IP_VERSION_MAP = {
    "4": "IPv4",
    "6": "IPv6"
}


def add_provider_configuration(type_manager, service_type):
    type_manager.add_provider_configuration(
        service_type,
        pconf.ProviderConfiguration('neutron_lbaas'))


class LoadBalancerPluginv2(loadbalancerv2.LoadBalancerPluginBaseV2,
                           agentschedulers_db.AgentSchedulerDbMixin):
    """Implementation of the Neutron Loadbalancer Service Plugin.

    This class manages the workflow of LBaaS request/response.
    Most DB related works are implemented in class
    loadbalancer_db.LoadBalancerPluginDb.
    """
    __native_bulk_support = True

    supported_extension_aliases = ["lbaasv2",
                                   "shared_pools",
                                   "acl",
                                   "l7",
                                   "lbaas_agent_schedulerv2",
                                   "service-type",
                                   "lb-graph",
                                   "lb_network_vip",
                                   "hm_max_retries_down"]
    path_prefix = loadbalancerv2.LOADBALANCERV2_PREFIX

    agent_notifiers = (
        agent_scheduler_v2.LbaasAgentSchedulerDbMixin.agent_notifiers)

    def __init__(self):
        """Initialization for the loadbalancer service plugin."""
        self.db = ldbv2.LoadBalancerPluginDbv2()
        self.service_type_manager = st_db.ServiceTypeManager.get_instance()
        add_provider_configuration(
            self.service_type_manager, constants.LOADBALANCERV2)
        self._load_drivers()
        self.start_periodic_jobs()
        self.start_rpc_listeners()
        self.db.subscribe()
        rpc_worker = service.RpcWorker([self], worker_process_count=0)
        self.add_worker(rpc_worker)

    def start_periodic_jobs(self):
        for driver_name, driver_class in self.drivers.items():
            if hasattr(driver_class, 'get_periodic_jobs'):
                for job in self.drivers[driver_name].get_periodic_jobs():
                    self.add_agent_status_check_worker(job)

    def start_rpc_listeners(self):
        listeners = []
        for driver in self.drivers.values():
            if hasattr(driver, 'start_rpc_listeners'):
                listener = driver.start_rpc_listeners()
                listeners.append(listener)
        return listeners

    def _load_drivers(self):
        """Loads plugin-drivers specified in configuration."""
        self.drivers, self.default_provider = service_base.load_drivers(
            constants.LOADBALANCERV2, self)

        ctx = ncontext.get_admin_context()
        # stop service in case provider was removed, but resources were not
        self._check_orphan_loadbalancer_associations(ctx, self.drivers.keys())

    def _check_orphan_loadbalancer_associations(self, context, provider_names):
        """Checks remaining associations between loadbalancers and providers.

        If admin has not undeployed resources with provider that was deleted
        from configuration, neutron service is stopped. Admin must delete
        resources prior to removing providers from configuration.
        """
        used_provider_names = (
            self.db.get_provider_names_used_in_loadbalancers(context))
        lost_providers = set(
            [name for name in used_provider_names
                if name not in provider_names])
        # resources are left without provider - stop the service
        if lost_providers:
            msg = ("Delete associated load balancers before "
                   "removing providers %s") % list(lost_providers)
            LOG.error(msg)
            raise SystemExit(1)

    def _get_driver_for_provider(self, provider):
        try:
            return self.drivers[provider]
        except KeyError:
            # raise if not associated (should never be reached)
            raise n_exc.Invalid(_("Error retrieving driver for provider %s") %
                                provider)

    def _get_driver_for_loadbalancer(self, context, loadbalancer_id):
        lb = self.db.get_loadbalancer_as_api_dict(context, loadbalancer_id)
        try:
            return self.drivers[lb['provider']]
        except KeyError:
            raise n_exc.Invalid(
                _("Error retrieving provider for load balancer. Possible "
                 "providers are %s.") % self.drivers.keys()
            )

    def _get_provider_name(self, entity):
        if ('provider' in entity and
                entity['provider'] != n_constants.ATTR_NOT_SPECIFIED):
            provider_name = pconf.normalize_provider_name(entity['provider'])
            del entity['provider']
            self.validate_provider(provider_name)
            return provider_name
        else:
            if not self.default_provider:
                raise pconf.DefaultServiceProviderNotFound(
                    service_type=constants.LOADBALANCERV2)
            if entity.get('provider'):
                del entity['provider']
            return self.default_provider

    def _call_driver_operation(self, context, driver_method, db_entity,
                               old_db_entity=None, **kwargs):
        manager_method = "%s.%s" % (driver_method.__self__.__class__.__name__,
                                    driver_method.__name__)
        LOG.info("Calling driver operation %s" % manager_method)
        get_status = kwargs.get('get_status')
        try:
            if get_status:
                return driver_method(context, db_entity, **kwargs)
            else:
                if old_db_entity:
                    driver_method(context, old_db_entity, db_entity, **kwargs)
                else:
                    driver_method(context, db_entity, **kwargs)
        # catching and reraising agent issues
        except (lbaas_agentschedulerv2.NoEligibleLbaasAgent,
                lbaas_agentschedulerv2.NoActiveLbaasAgent) as no_agent:
            raise no_agent
        except Exception as e:
            LOG.exception("There was an error in the driver")
            self._handle_driver_error(context, db_entity)
            raise loadbalancerv2.DriverError(msg=e)

    def _handle_driver_error(self, context, db_entity):
        try:
            lb_id = db_entity.root_loadbalancer.id
            self.db.update_status(context, models.LoadBalancer, lb_id,
                                  n_constants.ERROR)
        except Exception as e:
            LOG.info('handle_driver_error %s', e)

    def _eliminate_flavor(self, loadbalancer_obj):
        try:
            delattr(loadbalancer_obj, "flavor")
        except Exception as exc:
            lb_id = getattr(loadbalancer_obj, "id")
            log_dict = {'lb_id': lb_id}
            LOG.error('Failed to eliminate flavor param'
                      ' in load balancer %(lb_id)s ',
                      log_dict)
            raise exc

    def _validate_flavor(self, flavor, provider_name):
        if provider_name in FLAVOR_UNEDITABLE_PROVIDER:
            if flavor != 1:
                raise loadbalancerv2.FlavorNotSupportedByProvider(
                    provider_name=provider_name,
                    flavor_num=flavor
                )

    def _validate_session_persistence_info(self, sp_info):
        """Performs sanity check on session persistence info.

        :param sp_info: Session persistence info
        """
        if not sp_info:
            return
        if sp_info['type'] == lb_const.SESSION_PERSISTENCE_APP_COOKIE:
            if not sp_info.get('cookie_name'):
                raise loadbalancerv2.SessionPersistenceConfigurationInvalid(
                    msg="'cookie_name' should be specified for %s"
                        " session persistence." % sp_info['type'])
        else:
            if 'cookie_name' in sp_info:
                raise loadbalancerv2.SessionPersistenceConfigurationInvalid(
                    msg="'cookie_name' is not allowed for %s"
                        " session persistence" % sp_info['type'])

    def get_plugin_type(self):
        return constants.LOADBALANCERV2

    def get_plugin_description(self):
        return "Neutron LoadBalancer Service Plugin v2"

    def _insert_provider_name_from_flavor(self, context, loadbalancer):
        """Select provider based on flavor."""

        # TODO(jwarendt) Support passing flavor metainfo from the
        # selected flavor profile into the provider, not just selecting
        # the provider, when flavor templating arrives.

        if ('provider' in loadbalancer and
            loadbalancer['provider'] != n_constants.ATTR_NOT_SPECIFIED):
            raise loadbalancerv2.ProviderFlavorConflict()

        plugin = directory.get_plugin(constants.FLAVORS)
        if not plugin:
            raise loadbalancerv2.FlavorsPluginNotLoaded()

        # Will raise FlavorNotFound if doesn't exist
        fl_db = flavors_plugin.FlavorsPlugin.get_flavor(
            plugin,
            context,
            loadbalancer['flavor_id'])

        if fl_db['service_type'] != constants.LOADBALANCERV2:
            raise flavors.InvalidFlavorServiceType(
                service_type=fl_db['service_type'])

        if not fl_db['enabled']:
            raise flavors.FlavorDisabled()

        providers = flavors_plugin.FlavorsPlugin.get_flavor_next_provider(
            plugin,
            context,
            fl_db['id'])

        provider = providers[0].get('provider')

        LOG.debug("Selected provider %s" % provider)

        loadbalancer['provider'] = provider

    def _get_tweaked_resource_attribute_map(self):
        memo = {id(n_constants.ATTR_NOT_SPECIFIED):
                n_constants.ATTR_NOT_SPECIFIED}
        ram = copy.deepcopy(attrs.RESOURCE_ATTRIBUTE_MAP, memo=memo)
        del ram['listeners']['loadbalancer_id']
        del ram['pools']['listener_id']
        del ram['healthmonitors']['pool_id']
        for resource in ram:
            if resource in lb_graph_ext.EXISTING_ATTR_GRAPH_ATTR_MAP:
                ram[resource].update(
                    lb_graph_ext.EXISTING_ATTR_GRAPH_ATTR_MAP[resource])
        return ram

    def _prepare_loadbalancer_graph(self, context, loadbalancer):
        """Prepares the entire user requested body of a load balancer graph

        To minimize code duplication, this method reuses the neutron API
        controller's method to do all the validation, conversion, and
        defaulting of each resource.  This reuses the RESOURCE_ATTRIBUTE_MAP
        and SUB_RESOURCE_ATTRIBUTE_MAP from the extension to enable this.
        """
        # NOTE(blogan): it is assumed the loadbalancer attributes have already
        # passed through the prepare_request_body method by nature of the
        # normal neutron wsgi workflow.  So we start with listeners since
        # that probably has not passed through the neutron wsgi workflow.
        ram = self._get_tweaked_resource_attribute_map()
        # NOTE(blogan): members are not populated in the attributes.RAM so
        # our only option is to use the original extension definition of member
        # to validate.  If members ever need something added to it then it too
        # will need to be added here.
        prepped_lb = napi_base.Controller.prepare_request_body(
            context, {'loadbalancer': loadbalancer}, True, 'loadbalancer',
            ram['loadbalancers']
        )
        sub_ram = loadbalancerv2.SUB_RESOURCE_ATTRIBUTE_MAP
        sub_ram.update(l7.SUB_RESOURCE_ATTRIBUTE_MAP)
        prepped_listeners = []
        for listener in loadbalancer.get('listeners', []):
            prepped_listener = napi_base.Controller.prepare_request_body(
                context, {'listener': listener}, True, 'listener',
                ram['listeners'])
            l7policies = listener.get('l7policies')
            if l7policies and l7policies != n_constants.ATTR_NOT_SPECIFIED:
                prepped_policies = []
                for policy in l7policies:
                    prepped_policy = napi_base.Controller.prepare_request_body(
                        context, {'l7policy': policy}, True, 'l7policy',
                        ram['l7policies'])
                    l7rules = policy.get('rules')
                    redirect_pool = policy.get('redirect_pool')
                    if l7rules and l7rules != n_constants.ATTR_NOT_SPECIFIED:
                        prepped_rules = []
                        for rule in l7rules:
                            prepped_rule = (
                                napi_base.Controller.prepare_request_body(
                                    context, {'l7rule': rule}, True, 'l7rule',
                                    sub_ram['rules']['parameters']))
                            prepped_rules.append(prepped_rule)
                        prepped_policy['l7_rules'] = prepped_rules
                    if (redirect_pool and
                            redirect_pool != n_constants.ATTR_NOT_SPECIFIED):
                        prepped_r_pool = (
                            napi_base.Controller.prepare_request_body(
                                context, {'pool': redirect_pool}, True, 'pool',
                                ram['pools']))
                        prepped_r_members = []
                        for member in redirect_pool.get('members', []):
                            prepped_r_member = (
                                napi_base.Controller.prepare_request_body(
                                    context, {'member': member},
                                    True, 'member',
                                    sub_ram['members']['parameters']))
                            prepped_r_members.append(prepped_r_member)
                        prepped_r_pool['members'] = prepped_r_members
                        r_hm = redirect_pool.get('healthmonitor')
                        if r_hm and r_hm != n_constants.ATTR_NOT_SPECIFIED:
                            prepped_r_hm = (
                                napi_base.Controller.prepare_request_body(
                                    context, {'healthmonitor': r_hm},
                                    True, 'healthmonitor',
                                    ram['healthmonitors']))
                            prepped_r_pool['healthmonitor'] = prepped_r_hm
                        prepped_policy['redirect_pool'] = redirect_pool
                    prepped_policies.append(prepped_policy)
                prepped_listener['l7_policies'] = prepped_policies
            pool = listener.get('default_pool')
            if pool and pool != n_constants.ATTR_NOT_SPECIFIED:
                prepped_pool = napi_base.Controller.prepare_request_body(
                    context, {'pool': pool}, True, 'pool',
                    ram['pools'])
                prepped_members = []
                for member in pool.get('members', []):
                    prepped_member = napi_base.Controller.prepare_request_body(
                        context, {'member': member}, True, 'member',
                        sub_ram['members']['parameters'])
                    prepped_members.append(prepped_member)
                prepped_pool['members'] = prepped_members
                hm = pool.get('healthmonitor')
                if hm and hm != n_constants.ATTR_NOT_SPECIFIED:
                    prepped_hm = napi_base.Controller.prepare_request_body(
                        context, {'healthmonitor': hm}, True, 'healthmonitor',
                        ram['healthmonitors'])
                    prepped_pool['healthmonitor'] = prepped_hm
                prepped_listener['default_pool'] = prepped_pool
            prepped_listeners.append(prepped_listener)
        prepped_lb['listeners'] = prepped_listeners
        return loadbalancer

    def _validate_az_hints(self, availability_zones):
        # get the current az info from config file or db
        az_config = cfg.CONF.availability_zones_configuration_enable
        azs = cfg.CONF.functional_availability_zones
        if not az_config:
            raise loadbalancerv2.LoadbalancerAZNotConfig()
        azs_num = len(availability_zones)
        azs_set_num = len(set(availability_zones))
        if azs_num != azs_set_num:
            raise loadbalancerv2.LoadbalancerAZAreSame(
                availability_zones=availability_zones)
        for az in availability_zones:
            if az not in azs:
                raise loadbalancerv2.LoadbalancerAZNotFound(
                    availability_zones=availability_zones, azs=azs)

    def _check_acl_group_exists(self, context, acl_group_id):
        if not self.db._resource_exists(
                context, models.ACLGroup, acl_group_id):
            raise loadbalancerv2.EntityNotFound(name=models.ACLGroup.NAME,
                                                id=acl_group_id)

    def _check_acl_rule_exists(self, context, acl_rule_id):
        if not self.db._resource_exists(context, models.ACLRule, acl_rule_id):
            raise loadbalancerv2.EntityNotFound(name=models.ACLRule.NAME,
                                                id=acl_rule_id)

    def _validate_acl_rule_ip_version(self, ip_address, ip_version):
        if IP_VERSION_MAP[str(
                netaddr.IPNetwork(ip_address).version)] != ip_version:
            raise acl_ext.ACLRuleIpAddressConflict()

    def _make_acl_group_binding_info_dict(self,
                                          acl_group_with_rules_dict,
                                          binding_info_dict):
        acl_group_binding_info = acl_group_with_rules_dict
        # deliver acl binding mode (type and enable)
        acl_group_binding_info['type'] = binding_info_dict['type']
        acl_group_binding_info['enabled'] = binding_info_dict['enabled']
        acl_group_binding_info['listener_id'] = \
            binding_info_dict['listener_id']

        return acl_group_binding_info

    def _make_acl_group_with_rule_dict(self, context, acl_group_id):
        # Based on acl group info, construct acl group
        # dict with its acl rules
        acl_group_dict_with_rules = self.db.get_acl_group_as_api_dict(
            context, acl_group_id)
        # prevent other listeners info
        acl_group_dict_with_rules.pop("listeners")
        # replace acl rule id list with acl rule details list
        rule_id_list = acl_group_dict_with_rules.pop("acl_rules")
        if len(rule_id_list) > 0:
            rule_detail_list = [self.db.get_acl_group_acl_rule_as_api_dict(
                context, rule_id['id'])
                                for rule_id in rule_id_list]
            acl_group_dict_with_rules['acl_rules_detail'] = \
                rule_detail_list
        else:
            acl_group_dict_with_rules['acl_rules_detail'] = []

        return acl_group_dict_with_rules

    def _update_acl_group_rules(
            self, context, acl_group_id):

        ag_with_rule = self._make_acl_group_with_rule_dict(
            context, acl_group_id)

        loadbalancers = self.get_acl_group_bind_loadbalancers(context, acl_group_id)
        for driver in self.drivers.values():
            self._call_driver_operation(
                context, driver.acl_group.update,
                ag_with_rule, loadbalancers=loadbalancers)

    def get_acl_group_bind_loadbalancers(self, context, acl_group_id):
        binding_infos = self.db.get_acl_binding_info_by_acl_group_id(context, acl_group_id)
        loadbalancer_dict = {}
        for binding_info in binding_infos:
            listener_db = self.db.get_listener_as_api_dict(context, binding_info['listener_id'])
            if listener_db['loadbalancers'][0]['id'] in loadbalancer_dict:
                continue
            loadbalancer = self.db.get_loadbalancer_as_api_dict(context, listener_db['loadbalancers'][0]['id'])
            loadbalancer_dict[loadbalancer['id']] = loadbalancer
        return loadbalancer_dict.values()

    def _sync_acl_group_to_listener(
            self, context, acl_group_id):
        acl_group_db = self.get_acl_group(context, acl_group_id)
        listeners = acl_group_db.get("listeners")
        loadbalancers = []
        # Acl group has been associated to listener(s),
        # sync acl group change to each listener(s)
        if listeners:
            # Acl group with rule dict is general for each
            # listeners, but acl group binding info is not.
            ag_with_rule = self._make_acl_group_with_rule_dict(
                context, acl_group_id)
            for listener in listeners:
                bi = self.db.get_acl_listener_binding_info(
                    context, listener['id'],
                    acl_group_id).to_api_dict()
                bi_to_driver = self._make_acl_group_binding_info_dict(
                    acl_group_with_rules_dict=ag_with_rule,
                    binding_info_dict=bi)
                lsn_dict = self.db.get_listener_as_api_dict(
                    context, listener['id'])
                driver = self._get_driver_for_loadbalancer(
                    context,
                    lsn_dict['loadbalancers'][0]['id'])
                if lsn_dict['loadbalancers'][0]['id'] not in loadbalancers:
                    loadbalancers.append(lsn_dict['loadbalancers'][0]['id'])
                    self._call_driver_operation(
                        context, driver.listener.config_acl, bi_to_driver)

    def _get_one_provider_driver(self):
        """We use default, if there is no default driver,
           it uses the first one driver in drivers list.
        """
        provider_name = self.default_provider
        driver = self.drivers.get(provider_name)

        if not driver:
            drivers = self.drivers.values()
            driver = drivers[0]

        return driver

    def create_acl_group(self, context, acl_group):
        acl_group_dict = acl_group.get('acl_group')
        try:
            acl_group_db = self.db.create_acl_group(
                context, acl_group_dict)
        except Exception:
            raise acl_ext.DBOperationFailed(
                operation='create_acl_group')

        return self.db.get_acl_group(
            context, acl_group_db.id).to_api_dict()

    def delete_acl_group(self, context, id):
        self._check_acl_group_exists(context, id)
        acl_group = self.db.get_acl_group(context, id)
        if acl_group.listeners:
            raise acl_ext.ACLGroupInUse(
                acl_group_id=id)
        try:
            self.db.delete_acl_group(context, id)
        except Exception:
            raise acl_ext.DBOperationFailed(
                operation='delete_acl_group')

    def _filter_resource_key(self, allow_keys, resource):
        return {k: resource[k] for k in allow_keys
                if k in resource}

    def update_acl_group(self, context, id, acl_group):
        """We only allow to update name and desc, but
           the attributes to update is not checked
           in this funciton.
        """
        allow_keys = ["name", "description"]

        acl_group_dict = acl_group.get('acl_group')
        acl_group_dict = self._filter_resource_key(allow_keys,
                                                   acl_group_dict)

        self._check_acl_group_exists(context, id)
        try:
            updated_acl_group = self.db.update_acl_group(
                context, id, acl_group_dict)
            acl_group_dict = updated_acl_group.to_api_dict()
        except Exception:
            raise acl_ext.DBOperationFailed(
                operation='update_acl_group')

        return acl_group_dict

    def get_acl_groups(self, context, filters=None, fields=None):
        return [acl_group_db.to_api_dict() for acl_group_db in
                self.db.get_acl_groups(context, filters=filters)]

    def get_acl_group(self, context, id, fields=None):
        self._check_acl_group_exists(context, id)
        return self.db.get_acl_group(context, id).to_api_dict()

    def create_acl_group_acl_rule(self, context, acl_group_id, acl_rule):
        """We should check project_ids of acl_group and acl_rule
           are the same.
        """
        self._check_acl_group_exists(context, acl_group_id)

        acl_rule_data = acl_rule.get('acl_rule')
        self._validate_acl_rule_ip_version(
            ip_address=acl_rule_data.get('ip_address'),
            ip_version=acl_rule_data.get('ip_version'))
        with context.session.begin(subtransactions=True):
            try:
                acl_rule_db = self.db.create_acl_group_acl_rule(
                    context, acl_group_id=acl_group_id,
                    acl_rule=acl_rule_data)
            except Exception:
                raise acl_ext.DBOperationFailed(
                    operation='create_acl_group_acl_rule')

            try:
                for provider, driver in self.drivers.items():
                    if provider.lower() != lb_const.PROVIDER_ESLB:
                        self._update_acl_group_rules(context, acl_group_id)
                    else:
                        self._sync_acl_group_to_listener(context, acl_group_id)
            except Exception as ex:
                mesg = "Create ACL rule %s of ACL group %s fail" % (
                    str(acl_rule), str(acl_group_id)
                )
                LOG.error(mesg)
                raise ex

        return acl_rule_db.to_api_dict()

    def delete_acl_group_acl_rule(self, context, id, acl_group_id):
        self._check_acl_group_exists(context, acl_group_id)
        self._check_acl_rule_exists(context, id)
        with context.session.begin(subtransactions=True):
            try:
                self.db.delete_acl_group_acl_rule(context, id)
            except Exception:
                raise acl_ext.DBOperationFailed(
                    operation='delete_acl_group_acl_rule')
            try:
                for provider, driver in self.drivers.items():
                    if provider.lower() != lb_const.PROVIDER_ESLB:
                        self._update_acl_group_rules(context, acl_group_id)
                    else:
                        self._sync_acl_group_to_listener(context, acl_group_id)
            except Exception as ex:
                mesg = "Delete ACL rule %s of ACL group %s fail" % (
                    str(id), str(acl_group_id)
                )
                LOG.error(mesg)
                raise ex

    def update_acl_group_acl_rule(self, context, id, acl_group_id, acl_rule):
        """Acl_rule should not contain id, or it will be update ?"""
        self._check_acl_group_exists(context, acl_group_id)
        self._check_acl_rule_exists(context, id)

        acl_rule_data = acl_rule.get('acl_rule')
        allow_keys = ["description", "ip_version",
                      "ip_address"]
        acl_rule_dict = self._filter_resource_key(allow_keys,
                                                  acl_rule_data)

        if acl_rule_dict.get('ip_address'):
            current_ip_version = self.db.get_acl_group_acl_rule(
                context, id).ip_version
            self._validate_acl_rule_ip_version(
                ip_address=acl_rule_dict.get('ip_address'),
                ip_version=current_ip_version)
        with context.session.begin(subtransactions=True):
            try:
                updated_rule = self.db.update_acl_group_acl_rule(
                    context, id, acl_rule=acl_rule_dict)
            except Exception:
                raise acl_ext.DBOperationFailed(
                    operation='update_acl_group_acl_rule')

            try:
                for provider, driver in self.drivers.items():
                    if provider.lower() != lb_const.PROVIDER_ESLB:
                        self._update_acl_group_rules(context, acl_group_id)
                    else:
                        self._sync_acl_group_to_listener(context, acl_group_id)
            except Exception as ex:
                msg = "Update ACL rule %s of ACL group %s fail" % (
                    str(id), str(acl_group_id)
                )
                LOG.error(msg)
                raise ex

        return updated_rule.to_api_dict()

    def get_acl_group_acl_rules(
            self, context, acl_group_id, filters=None, fields=None):
        self._check_acl_group_exists(context, acl_group_id)
        if not filters:
            filters = {}
        filters['acl_group_id'] = [acl_group_id]
        return [rule.to_api_dict() for rule in self.db.get_acl_group_acl_rules(
            context, filters=filters)]

    def get_acl_group_acl_rule(
            self, context, id, acl_group_id, fields=None):
        self._check_acl_group_exists(context, acl_group_id)
        self._check_acl_rule_exists(context, id)
        return self.db.get_acl_group_acl_rule(context, id).to_api_dict()

    def get_acl_rule(
            self, context, id, fields=None):
        self._check_acl_rule_exists(context, id)
        return self.db.get_acl_group_acl_rule(context, id).to_api_dict()

    def flush_acl_rules(self, context, acl_group_id):
        self._check_acl_group_exists(context, acl_group_id)
        rule_dbs = self.get_acl_group_acl_rules(context, acl_group_id)
        with context.session.begin(subtransactions=True):
            try:
                for rule_db in rule_dbs:
                    self.db.delete_acl_group_acl_rule(
                        context, rule_db['id'])
            except Exception:
                raise acl_ext.DBOperationFailed(
                    operation='flush_acl_group_acl_rules')

            try:
                for provider, driver in self.drivers.items():
                    if provider.lower() != lb_const.PROVIDER_ESLB:
                        self._update_acl_group_rules(context, acl_group_id)
                    else:
                        self._sync_acl_group_to_listener(context, acl_group_id)
            except Exception as ex:
                raise ex

        return self.get_acl_group(context, acl_group_id)

    def add_listener(self, context, acl_group_id, binding_info):
        self._check_acl_group_exists(context, acl_group_id)
        listener_id = binding_info.get('listener_id')
        if not listener_id:
            raise acl_ext.MissingOrInvalidBindingInfo(
                info_type='listener_id')
        try:
            listener_db_dict = self.db.get_listener_as_api_dict(
                context, listener_id)
        except loadbalancerv2.EntityNotFound as notfound:
            raise notfound
        binding_type = binding_info.get('type')
        if not (binding_type and
                binding_type in lb_const.ACL_CONTROL_TYPES):
            raise acl_ext.MissingOrInvalidBindingInfo(
                info_type='type')
        enabled = binding_info.get('enabled', True)
        enabled = strutils.bool_from_string(enabled)
        binding_info.update({'enabled': enabled})
        with context.session.begin(subtransactions=True):
            try:
                bind_db_obj = self.db.add_listener(
                    context, acl_group_id=acl_group_id,
                    binding_info=binding_info)
            except acl_ext.DuplicateBindListenerWithACL as duplicate:
                raise duplicate
            except Exception:
                raise acl_ext.DBOperationFailed(
                    operation='add_listener')

            driver_target = self._get_driver_for_loadbalancer(
                context, listener_db_dict['loadbalancers'][0]['id'])

            for provider, driver in self.drivers.items():
                if driver_target == driver:
                    if provider.lower() != lb_const.PROVIDER_ESLB:
                        listener_db_obj = self.db.get_listener_as_api_dict(
                            context, listener_id
                        )

                        acl_bind = copy.deepcopy(binding_info)
                        acl_bind['acl_group_id'] = acl_group_id

                        ag_with_rule = self._make_acl_group_with_rule_dict(
                            context, acl_group_id)

                        loadbalancer=self.db.get_loadbalancer_as_api_dict(context, listener_db_dict['loadbalancers'][0]['id'])
                        self._call_driver_operation(
                            context, driver.acl_group.add_acl_bind, acl_bind,
                            listener=listener_db_obj, loadbalancer=loadbalancer,
                            acl_group=ag_with_rule)
                    else:
                        ag_with_rule = self._make_acl_group_with_rule_dict(
                            context, acl_group_id)
                        bi_to_driver = self._make_acl_group_binding_info_dict(
                            acl_group_with_rules_dict=ag_with_rule,
                            binding_info_dict=bind_db_obj.to_api_dict())
                        self._call_driver_operation(
                            context, driver.listener.config_acl, bi_to_driver)
                    break

        return bind_db_obj.to_api_dict()

    def remove_listener(self, context, acl_group_id, binding_info):
        self._check_acl_group_exists(context, acl_group_id)
        listener_id = binding_info.get('listener_id')
        if not listener_id:
            raise acl_ext.MissingOrInvalidBindingInfo(
                info_type='listener_id')
        try:
            listener_db_dict = self.db.get_listener_as_api_dict(
                context, listener_id)
        except loadbalancerv2.EntityNotFound as notfound:
            raise notfound
        with context.session.begin(subtransactions=True):
            try:
                bind_db_obj = self.db.remove_listener(
                    context, listener_id=listener_id,
                    acl_group_id=acl_group_id)

                # we update he  enable attribute to remove acl bind
                bind_db_obj.enabled = False
            except acl_ext.NonexistentRelationShip as nonexistent:
                raise nonexistent
            except Exception:
                raise acl_ext.DBOperationFailed(
                    operation='remove_listener')
            driver_target = self._get_driver_for_loadbalancer(
                context, listener_db_dict['loadbalancers'][0]['id'])

            for provider, driver in self.drivers.items():
                if driver_target == driver:
                    if provider.lower() != lb_const.PROVIDER_ESLB:
                        listener_db_obj = self.db.get_listener_as_api_dict(
                            context, listener_id
                        )
                        acl_bind = copy.deepcopy(binding_info)
                        acl_bind['acl_group_id'] = acl_group_id

                        ag_with_rule = self._make_acl_group_with_rule_dict(
                            context, acl_group_id)

                        loadbalancer=self.db.get_loadbalancer_as_api_dict(context, listener_db_dict['loadbalancers'][0]['id'])

                        self._call_driver_operation(
                            context, driver.acl_group.remove_acl_bind, acl_bind,
                            listener=listener_db_dict, loadbalancer=loadbalancer,
                            acl_group=ag_with_rule
                        )

                    else:
                        ag_with_rule = self._make_acl_group_with_rule_dict(
                            context, acl_group_id)
                        bi_to_driver = self._make_acl_group_binding_info_dict(
                            acl_group_with_rules_dict=ag_with_rule,
                            binding_info_dict=bind_db_obj.to_api_dict())
                        self._call_driver_operation(
                            context, driver.listener.remove_acl, bi_to_driver)
                    break

        return bind_db_obj.to_api_dict()

    def create_loadbalancer(self, context, loadbalancer):
        loadbalancer = loadbalancer.get('loadbalancer')
        if loadbalancer['flavor_id'] != n_constants.ATTR_NOT_SPECIFIED:
            self._insert_provider_name_from_flavor(context, loadbalancer)
        else:
            del loadbalancer['flavor_id']
        availability_zones = loadbalancer.get(az_ext.AZ_HINTS)
        if availability_zones:
            self._validate_az_hints(availability_zones)
            az_hints = az_ext.convert_az_list_to_string(availability_zones)
            loadbalancer[az_ext.AZ_HINTS] = az_hints
        else:
            loadbalancer[az_ext.AZ_HINTS] = None
        provider_name = self._get_provider_name(loadbalancer)
        flavor = loadbalancer.get('flavor')
        self._validate_flavor(flavor=flavor,
                              provider_name=provider_name)
        driver = self.drivers[provider_name]
        lb_db = self.db.create_loadbalancer(
            context, loadbalancer,
            allocate_vip=not driver.load_balancer.allocates_vip)
        if provider_name in FLAVOR_UNEDITABLE_PROVIDER:
            self._eliminate_flavor(lb_db)
        self.service_type_manager.add_resource_association(
            context,
            constants.LOADBALANCERV2,
            provider_name, lb_db.id)
        create_method = (driver.load_balancer.create_and_allocate_vip
                         if driver.load_balancer.allocates_vip
                         else driver.load_balancer.create)
        try:
            self._call_driver_operation(context, create_method, lb_db)
        except (lbaas_agentschedulerv2.NoEligibleLbaasAgent,
                lbaas_agentschedulerv2.NoActiveLbaasAgent) as no_agent:
            self.db.delete_loadbalancer(context, lb_db.id)
            raise no_agent
        return self.db.get_loadbalancer_as_api_dict(context, lb_db.id)

    def create_graph(self, context, graph):
        loadbalancer = graph.get('graph', {}).get('loadbalancer')
        loadbalancer = self._prepare_loadbalancer_graph(context, loadbalancer)
        if loadbalancer['flavor_id'] != n_constants.ATTR_NOT_SPECIFIED:
            self._insert_provider_name_from_flavor(context, loadbalancer)
        else:
            del loadbalancer['flavor_id']
        az_list = loadbalancer.get(az_ext.AZ_HINTS)
        if az_list:
            loadbalancer[az_ext.AZ_HINTS] = az_ext.\
                convert_az_list_to_string(az_list)
        else:
            loadbalancer[az_ext.AZ_HINTS] = ""
        provider_name = self._get_provider_name(loadbalancer)
        driver = self.drivers[provider_name]
        if not driver.load_balancer.allows_create_graph:
            raise lb_graph_ext.ProviderCannotCreateLoadBalancerGraph
        lb_db = self.db.create_loadbalancer_graph(
            context, loadbalancer,
            allocate_vip=not driver.load_balancer.allocates_vip)
        self.service_type_manager.add_resource_association(
            context, constants.LOADBALANCERV2, provider_name, lb_db.id)
        create_method = (driver.load_balancer.create_and_allocate_vip
                         if driver.load_balancer.allocates_vip
                         else driver.load_balancer.create)
        self._call_driver_operation(context, create_method, lb_db)
        api_lb = {'loadbalancer': self.db.get_loadbalancer(
            context, lb_db.id).to_api_dict(full_graph=True)}
        return api_lb

    def update_loadbalancer(self, context, id, loadbalancer):
        loadbalancer = loadbalancer.get('loadbalancer')
        flavor = loadbalancer.get('flavor')
        old_lb = self.db.get_loadbalancer(context, id)
        provider_name = old_lb.provider.provider_name
        if flavor is not None:
            self._validate_flavor(flavor=flavor,
                                  provider_name=provider_name)
        self.db.test_and_set_status(context, models.LoadBalancer, id,
                                    n_constants.PENDING_UPDATE)
        try:
            updated_lb = self.db.update_loadbalancer(
                context, id, loadbalancer)
        except Exception as exc:
            self.db.update_status(context, models.LoadBalancer, id,
                                  old_lb.provisioning_status)
            raise exc
        if provider_name in FLAVOR_UNEDITABLE_PROVIDER:
            self._eliminate_flavor(old_lb)
            self._eliminate_flavor(updated_lb)
        driver = self._get_driver_for_provider(provider_name)
        self._call_driver_operation(context,
                                    driver.load_balancer.update,
                                    updated_lb, old_db_entity=old_lb)
        return self.db.get_loadbalancer_as_api_dict(context, id)

    def delete_loadbalancer(self, context, id):
        old_lb = self.db.get_loadbalancer(context, id)
        if old_lb.listeners:
            raise loadbalancerv2.EntityInUse(
                entity_using=models.Listener.NAME,
                id=old_lb.listeners[0].id,
                entity_in_use=models.LoadBalancer.NAME)
        if old_lb.pools:
            raise loadbalancerv2.EntityInUse(
                entity_using=models.PoolV2.NAME,
                id=old_lb.pools[0].id,
                entity_in_use=models.LoadBalancer.NAME)
        self.db.test_and_set_status(context, models.LoadBalancer, id,
                                    n_constants.PENDING_DELETE)
        driver = self._get_driver_for_provider(old_lb.provider.provider_name)
        db_lb = self.db.get_loadbalancer(context, id)
        self._call_driver_operation(
            context, driver.load_balancer.delete, db_lb)

    def get_loadbalancer(self, context, id, fields=None):
        return self.db.get_loadbalancer_as_api_dict(context, id)

    def get_loadbalancers(self, context, filters=None, fields=None):
        return self.db.get_loadbalancers_as_api_dict(context, filters=filters)

    def _validate_mutual_auth_container(self, listener,
                                        current_listener=None):

        def _validate_mutual_auth(mutual_authentication_up, container_ref):
            if not mutual_authentication_up:
                listener['ca_container_id'] = None
                return

            else:
                if container_ref is None:
                    raise loadbalancerv2.MutualAuthContainerNotProvided(
                        container_id=container_ref)
                try:
                    lb_id = listener.get('loadbalancer_id')
                    tenant_id = listener.get('tenant_id')
                    cert_mgr = CERT_MANAGER_PLUGIN.CertManager()
                    cert_mgr.get_cert(
                        project_id=tenant_id, cert_ref=container_ref,
                        check_only=True,
                        resource_ref=cert_mgr.get_service_url(lb_id))
                except Exception:
                    raise loadbalancerv2.MutualAuthContainerNotFound(
                        container_id=container_ref)
                return

        mutual_authentication_up = listener.get('mutual_authentication_up')
        container_ref = listener.get('ca_container_id')

        # create new listener
        if not current_listener:
            _validate_mutual_auth(mutual_authentication_up,
                                  container_ref)
        # update existing listener
        else:
            if mutual_authentication_up is None:
                mutual_authentication_up = current_listener[
                    'mutual_authentication_up']
            if container_ref is None:
                container_ref = current_listener['ca_container_id']

            _validate_mutual_auth(mutual_authentication_up,
                                  container_ref)

    def _validate_tls_cipher_suites(self, listener, curr_listener=None):
        def validate_cipher_list(tls_pro_sorted, cipher_suites):
            tls_13_cipher = False
            tls_cipher_list = cipher_suites.upper().split(':')
            for cipher in tls_cipher_list:
                if lb_const.TLS_POLICY.has_key(tls_pro_sorted) and \
                    cipher.lower() in lb_const.TLS_POLICY[tls_pro_sorted]:
                    if len(tls_cipher_list) != 1:
                        raise loadbalancerv2.TLSCipherNotSupport(tls_protocols=tls_pro_sorted,
                                                                 cipher_suites=cipher_suites)
                    else:
                        LOG.info('TLS protocol is %s and cipher suite is %s' %
                                 (tls_pro_sorted, cipher_suites))
                        return
                elif lb_const.TLS_PRO_13 in tls_pro_sorted and \
                        cipher in lb_const.TLS_CIPHERS_USER_DEFINED_13:
                        tls_13_cipher = True
                else:
                    if cipher not in lb_const.TLS_CIPHERS_USER_DEFINED:
                        raise loadbalancerv2.TLSCipherNotSupport(tls_protocols=tls_pro_sorted,
                                                                 cipher_suites=cipher_suites)
            if lb_const.TLS_PRO_13 in tls_pro_sorted and tls_13_cipher == False:
                raise loadbalancerv2.TLSCipherInvalid(tls_protocols=tls_pro_sorted,
                                                      cipher_suites=cipher_suites)

        tls_protocols = listener.get('tls_protocols', None)
        cipher_suites = listener.get('cipher_suites', None)

        # support tls protocols is None
        if not tls_protocols:
            if not cipher_suites:
                LOG.info('TLS protocol is None and cipher suite is None')
                return
            else:
                tls_protocols_sorted = 'None'
                raise loadbalancerv2.TLSCipherNotSupport(tls_protocols=tls_protocols_sorted,
                                                         cipher_suites=cipher_suites)
        else:
            # support tls protocols is specified or 'default'
            tls_protocols_list = tls_protocols.lower().split(',')
            for tls in tls_protocols_list:
                if tls not in lb_const.TLS_PROTOCOLS:
                    raise loadbalancerv2.TLSProtocolInvalid(tls_protocols=tls_protocols)
            tls_protocols_uniq = list(set(tls_protocols_list))
            tls_protocols_uniq.sort()
            tls_protocols_sorted = ','.join(tls_protocols_uniq)
            if tls_protocols_sorted not in lb_const.TLS_PRO_LIST:
                raise loadbalancerv2.TLSProtocolInvalid(tls_protocols=tls_protocols)
            else:
                if not cipher_suites:
                    cipher_suites = 'None'
                    raise loadbalancerv2.TLSCipherNotSupport(tls_protocols=tls_protocols_sorted,
                                                             cipher_suites=cipher_suites)
                elif tls_protocols_sorted.lower() == 'default' and \
                        cipher_suites.lower() == 'default':
                    LOG.info('TLS protocol is %s and cipher suite is %s' %
                             (tls_protocols_sorted.lower(), cipher_suites.lower()))
                    return
                else:
                    validate_cipher_list(tls_protocols_sorted.lower(), cipher_suites)

    def _validate_tls(self, listener, curr_listener=None):
        def validate_tls_container(container_ref):
            cert_mgr = CERT_MANAGER_PLUGIN.CertManager()

            if curr_listener:
                lb_id = curr_listener['loadbalancer_id']
                tenant_id = curr_listener['tenant_id']
            else:
                lb_id = listener.get('loadbalancer_id')
                tenant_id = listener.get('tenant_id')

            try:
                cert_container = cert_mgr.get_cert(
                    project_id=tenant_id,
                    cert_ref=container_ref,
                    resource_ref=cert_mgr.get_service_url(lb_id))
            except Exception as e:
                if hasattr(e, 'status_code') and e.status_code == 404:
                    raise loadbalancerv2.TLSContainerNotFound(
                        container_id=container_ref)
                else:
                    # Could be a keystone configuration error...
                    err_msg = encodeutils.exception_to_unicode(e)
                    raise loadbalancerv2.CertManagerError(
                        ref=container_ref, reason=err_msg
                    )

            try:
                cert_parser.validate_cert(
                    cert_container.get_certificate(),
                    private_key=cert_container.get_private_key(),
                    private_key_passphrase=(
                        cert_container.get_private_key_passphrase()),
                    intermediates=cert_container.get_intermediates())
            except Exception as e:
                cert_mgr.delete_cert(
                    project_id=tenant_id,
                    cert_ref=container_ref,
                    resource_ref=cert_mgr.get_service_url(lb_id))
                raise loadbalancerv2.TLSContainerInvalid(
                    container_id=container_ref, reason=str(e))

        def validate_tls_containers(to_validate):
            for container_ref in to_validate:
                validate_tls_container(container_ref)

        to_validate = []
        if not curr_listener:
            if not listener['default_tls_container_ref']:
                raise loadbalancerv2.TLSDefaultContainerNotSpecified()
            to_validate.extend([listener['default_tls_container_ref']])
            if 'sni_container_refs' in listener:
                to_validate.extend(listener['sni_container_refs'])
        elif curr_listener['provisioning_status'] == n_constants.ERROR:
            to_validate.extend(curr_listener['default_tls_container_id'])
            to_validate.extend([
                container['tls_container_id'] for container in (
                    curr_listener['sni_containers'])])
        else:
            if (curr_listener['default_tls_container_id'] !=
                    listener['default_tls_container_ref']):
                to_validate.extend([listener['default_tls_container_ref']])

            if ('sni_container_refs' in listener and
                    [container['tls_container_id'] for container in (
                        curr_listener['sni_containers'])] !=
                    listener['sni_container_refs']):
                to_validate.extend(listener['sni_container_refs'])

        if len(to_validate) > 0:
            validate_tls_containers(to_validate)

        return len(to_validate) > 0

    def _validate_transparent_condition(self, listener,
                                        curr_listener=None):
        """TCP/UDP listener could enable transparent"""
        if curr_listener:
            protocol = curr_listener.get('protocol')
        else:
            protocol = listener.get('protocol')

        transparent = listener.get('transparent')
        if transparent:
            LOG.debug("Try to enable transparent")
            if protocol not in [lb_const.PROTOCOL_TCP,
                                lb_const.PROTOCOL_FTP,
                                lb_const.PROTOCOL_HTTPS,
                                lb_const.PROTOCOL_HTTP,
                                lb_const.PROTOCOL_TERMINATED_HTTPS,
                                lb_const.PROTOCOL_UDP
                                ]:
                raise loadbalancerv2.EnableTransparentInvalid(
                    protocol=protocol)

    def _check_pool_loadbalancer_match(self, context, pool_id, lb_id):
        lb = self.db.get_loadbalancer(context, lb_id)
        pool = self.db.get_pool(context, pool_id)
        if not lb.id == pool.loadbalancer.id:
            raise sharedpools.ListenerAndPoolMustBeOnSameLoadbalancer()

    def create_listener(self, context, listener):
        listener = listener.get('listener')
        lb_id = listener.get('loadbalancer_id')
        default_pool_id = listener.get('default_pool_id')
        if default_pool_id:
            self._check_pool_exists(context, default_pool_id)
            # Get the loadbalancer from the default_pool_id
            if not lb_id:
                default_pool = self.db.get_pool(context, default_pool_id)
                lb_id = default_pool.loadbalancer.id
                listener['loadbalancer_id'] = lb_id
            else:
                self._check_pool_loadbalancer_match(
                    context, default_pool_id, lb_id)
        elif not lb_id:
            raise sharedpools.ListenerMustHaveLoadbalancer()
        self.db.test_and_set_status(context, models.LoadBalancer, lb_id,
                                    n_constants.PENDING_UPDATE)

        try:
            if listener['protocol'] == lb_const.PROTOCOL_TERMINATED_HTTPS:
                self._validate_tls_cipher_suites(listener)
                self._validate_tls(listener)
            self._validate_mutual_auth_container(listener)
            self._validate_transparent_condition(listener)
            listener_db = self.db.create_listener(context, listener)
        except Exception as exc:
            self.db.update_loadbalancer_provisioning_status(
                context, lb_id)
            raise exc
        driver = self._get_driver_for_loadbalancer(
            context, listener_db.loadbalancer_id)
        self._call_driver_operation(
            context, driver.listener.create, listener_db)

        return self.db.get_listener_as_api_dict(context, listener_db.id)

    def _check_listener_pool_lb_match(self, context, listener_id, pool_id):
        listener = self.db.get_listener(context, listener_id)
        pool = self.db.get_pool(context, pool_id)
        if not listener.loadbalancer.id == pool.loadbalancer.id:
            raise sharedpools.ListenerAndPoolMustBeOnSameLoadbalancer()

    def update_listener(self, context, id, listener):
        listener = listener.get('listener')
        curr_listener_db = self.db.get_listener(context, id)
        default_pool_id = listener.get('default_pool_id')
        if default_pool_id:
            self._check_listener_pool_lb_match(
                context, id, default_pool_id)
        self.db.test_and_set_status(context, models.Listener, id,
                                    n_constants.PENDING_UPDATE)
        try:
            curr_listener = curr_listener_db.to_dict()

            if 'default_tls_container_ref' not in listener:
                listener['default_tls_container_ref'] = (
                    # NOTE(blogan): not changing to ref bc this dictionary is
                    # created from a data model
                    curr_listener['default_tls_container_id'])
            if 'sni_container_refs' not in listener:
                listener['sni_container_ids'] = [
                    container.tls_container_id for container in (
                        curr_listener['sni_containers'])]

            tls_containers_changed = False
            if curr_listener['protocol'] == lb_const.PROTOCOL_TERMINATED_HTTPS:
                self._validate_tls_cipher_suites(
                    listener,  curr_listener=curr_listener)
                tls_containers_changed = self._validate_tls(
                    listener, curr_listener=curr_listener)
            self._validate_mutual_auth_container(
                listener, current_listener=curr_listener)
            self._validate_transparent_condition(listener, curr_listener)
            listener_db = self.db.update_listener(
                context, id, listener,
                tls_containers_changed=tls_containers_changed)
        except Exception as exc:
            self.db.update_status(
                context,
                models.LoadBalancer,
                curr_listener_db.loadbalancer.id,
                provisioning_status=n_constants.ACTIVE
            )
            self.db.update_status(
                context,
                models.Listener,
                curr_listener_db.id,
                provisioning_status=n_constants.ACTIVE
            )
            raise exc

        driver = self._get_driver_for_loadbalancer(
            context, listener_db.loadbalancer_id)
        self._call_driver_operation(
            context,
            driver.listener.update,
            listener_db,
            old_db_entity=curr_listener_db)

        return self.db.get_listener_as_api_dict(context, id)

    def delete_listener(self, context, id):
        old_listener = self.db.get_listener(context, id)
        if old_listener.l7_policies:
            raise loadbalancerv2.EntityInUse(
                entity_using=models.L7Policy.NAME,
                id=old_listener.l7_policies[0].id,
                entity_in_use=models.Listener.NAME)
        with context.session.begin(subtransactions=True):
            self.db.test_and_set_status(context, models.Listener, id,
                                        n_constants.PENDING_DELETE)
            listener_db = self.db.get_listener(context, id)

            driver_target = self._get_driver_for_loadbalancer(
                context, listener_db.loadbalancer_id)

            for provider, driver in self.drivers.items():
                if driver_target == driver:
                    if provider.lower() != lb_const.PROVIDER_ESLB:
                        acl_bind_db = self.db.get_acl_listener_binding_by_listener_id(
                            context, listener_id=id
                        )

                        if acl_bind_db:
                            acl_bind_db.enabled = False
                            acl_group_id = acl_bind_db.acl_group_id

                            self.db.remove_listener(
                                context, listener_id=id,
                                acl_group_id=acl_group_id)

                            ag_with_rule = self._make_acl_group_with_rule_dict(
                                context, acl_group_id)

                            loadbalancer = self.db.get_loadbalancer_as_api_dict(context, old_listener.loadbalancer_id)
                            self._call_driver_operation(
                                context, driver.acl_group.remove_acl_bind, acl_bind_db.to_api_dict(),
                                listener=old_listener.to_api_dict(), loadbalancer=loadbalancer,
                                acl_group=ag_with_rule
                            )

                    self._call_driver_operation(
                        context, driver.listener.delete, listener_db)
                    break

    def get_listener(self, context, id, fields=None):
        return self.db.get_listener_as_api_dict(context, id)

    def get_listeners(self, context, filters=None, fields=None):
        return self.db.get_listeners_as_api_dict(
            context, filters=filters)

    def create_pool(self, context, pool):
        pool = pool.get('pool')
        listener_id = pool.get('listener_id')
        listeners = pool.get('listeners', [])
        if listener_id:
            listeners.append(listener_id)
        lb_id = pool.get('loadbalancer_id')
        db_listeners = []
        for l in listeners:
            db_l = self.db.get_listener(context, l)
            db_listeners.append(db_l)
            # Take the pool's loadbalancer_id from the first listener found
            # if it wasn't specified in the API call.
            if not lb_id:
                lb_id = db_l.loadbalancer.id
            # All specified listeners must be on the same loadbalancer
            if db_l.loadbalancer.id != lb_id:
                raise sharedpools.ListenerAndPoolMustBeOnSameLoadbalancer()
            if db_l.default_pool_id:
                raise sharedpools.ListenerDefaultPoolAlreadySet(
                    listener_id=db_l.id, pool_id=db_l.default_pool_id)
            if ((pool['protocol'], db_l.protocol)
                not in lb_const.LISTENER_POOL_COMPATIBLE_PROTOCOLS):
                raise loadbalancerv2.ListenerPoolProtocolMismatch(
                    listener_proto=db_l.protocol,
                    pool_proto=pool['protocol'])
        if not lb_id:
            raise sharedpools.PoolMustHaveLoadbalancer()
        pool['loadbalancer_id'] = lb_id
        self._validate_session_persistence_info(
            pool.get('session_persistence'))
        # SQLAlchemy gets strange ideas about populating the pool if we don't
        # blank out the listeners at this point.
        del pool['listener_id']
        pool['listeners'] = []
        self.db.test_and_set_status(context, models.LoadBalancer,
                                    lb_id, n_constants.PENDING_UPDATE)
        db_pool = self.db.create_pool(context, pool)
        for db_l in db_listeners:
            try:
                self.db.update_listener(context, db_l.id,
                                        {'default_pool_id': db_pool.id})
            except Exception as exc:
                self.db.update_loadbalancer_provisioning_status(
                    context, db_pool.loadbalancer_id)
                raise exc
        # Reload the pool from the DB to re-populate pool.listeners
        # before calling the driver
        db_pool = self.db.get_pool(context, db_pool.id)
        db_pool.listeners = db_listeners
        driver = self._get_driver_for_loadbalancer(
            context, db_pool.loadbalancer_id)
        self._call_driver_operation(context, driver.pool.create, db_pool)
        return db_pool.to_api_dict()

    def update_pool(self, context, id, pool):
        pool = pool.get('pool')
        self._validate_session_persistence_info(
            pool.get('session_persistence'))
        old_pool = self.db.get_pool(context, id)
        self.db.test_and_set_status(context, models.PoolV2, id,
                                    n_constants.PENDING_UPDATE)
        try:
            updated_pool = self.db.update_pool(context, id, pool)
        except Exception as exc:
            self.db.update_loadbalancer_provisioning_status(
                context, old_pool.root_loadbalancer.id)
            raise exc

        driver = self._get_driver_for_loadbalancer(
            context, updated_pool.loadbalancer_id)
        self._call_driver_operation(context,
                                    driver.pool.update,
                                    updated_pool,
                                    old_db_entity=old_pool)

        return self.db.get_pool_as_api_dict(context, id)

    def delete_pool(self, context, id):
        old_pool = self.db.get_pool(context, id)
        if old_pool.healthmonitor:
            raise loadbalancerv2.EntityInUse(
                entity_using=models.HealthMonitorV2.NAME,
                id=old_pool.healthmonitor.id,
                entity_in_use=models.PoolV2.NAME)
        self.db.test_and_set_status(context, models.PoolV2, id,
                                    n_constants.PENDING_DELETE)
        db_pool = self.db.get_pool(context, id)

        driver = self._get_driver_for_loadbalancer(
            context, db_pool.loadbalancer_id)
        self._call_driver_operation(context, driver.pool.delete, db_pool)

    def get_pools(self, context, filters=None, fields=None):
        return self.db.get_pools_as_api_dict(
            context, filters=filters)

    def get_pool(self, context, id, fields=None):
        return self.db.get_pool_as_api_dict(context, id)

    def _check_pool_exists(self, context, pool_id):
        if not self.db._resource_exists(context, models.PoolV2, pool_id):
            raise loadbalancerv2.EntityNotFound(name=models.PoolV2.NAME,
                                                id=pool_id)

    def create_pool_member(self, context, pool_id, member):
        member = member.get('member')
        self.db.check_subnet_exists(context, member['subnet_id'])
        db_pool = self.db.get_pool_as_api_dict(context, pool_id)
        lb_id = db_pool['loadbalancers'][0]['id']
        self.db.test_and_set_status(context, models.LoadBalancer,
                                    lb_id, n_constants.PENDING_UPDATE)
        try:
            member_db = self.db.create_pool_member(context, member, pool_id)
        except Exception as exc:
            self.db.update_loadbalancer_provisioning_status(
                context, lb_id)
            raise exc

        driver = self._get_driver_for_loadbalancer(
            context, member_db.pool.loadbalancer_id)
        self._call_driver_operation(context,
                                    driver.member.create,
                                    member_db)

        return self.db.get_pool_member_as_api_dict(context, member_db.id)

    def create_pool_member_bulk(self, context, pool_id, members,
                                filters=None):
        members = members.get('members')
        db_pool = self.db.get_pool_as_api_dict(context, pool_id)
        if not filters:
            filters = {}
        filters['pool_id'] = [pool_id]
        lb_id = db_pool['loadbalancers'][0]['id']
        self.db.test_and_set_status(context, models.LoadBalancer,
                                    lb_id, n_constants.PENDING_UPDATE)
        try:
            members_db = self.db.create_pool_member_bulk(context,
                                                         members,
                                                         pool_id)
        except Exception as exc:
            self.db.update_loadbalancer_provisioning_status(
                context, lb_id)
            raise exc

        driver = self._get_driver_for_loadbalancer(
            context, lb_id)
        self._call_driver_operation(context,
                                    driver.member.create_bulk,
                                    members_db)
        ids = [member_db.id for member_db in members_db]
        return self.db.get_pool_member_bulk_as_api_dict(
                context, ids)

    def update_pool_member(self, context, id, pool_id, member):
        self._check_pool_exists(context, pool_id)
        member = member.get('member')
        old_member = self.db.get_pool_member(context, id)
        self.db.test_and_set_status(context, models.MemberV2, id,
                                    n_constants.PENDING_UPDATE)
        try:
            updated_member = self.db.update_pool_member(context, id, member)
        except Exception as exc:
            self.db.update_loadbalancer_provisioning_status(
                context, old_member.pool.loadbalancer.id)
            raise exc

        driver = self._get_driver_for_loadbalancer(
            context, updated_member.pool.loadbalancer_id)
        self._call_driver_operation(context,
                                    driver.member.update,
                                    updated_member,
                                    old_db_entity=old_member)

        return self.db.get_pool_member_as_api_dict(context, id)

    def delete_pool_member(self, context, id, pool_id):
        self._check_pool_exists(context, pool_id)
        self.db.test_and_set_status(context, models.MemberV2, id,
                                    n_constants.PENDING_DELETE)
        db_member = self.db.get_pool_member(context, id)

        driver = self._get_driver_for_loadbalancer(
            context, db_member.pool.loadbalancer_id)
        self._call_driver_operation(context,
                                    driver.member.delete,
                                    db_member)

    def get_pool_members(self, context, pool_id, filters=None, fields=None):
        self._check_pool_exists(context, pool_id)
        if not filters:
            filters = {}
        filters['pool_id'] = [pool_id]
        return self.db.get_pool_members_as_api_dict(context, filters=filters)

    def get_pool_member(self, context, id, pool_id, fields=None):
        self._check_pool_exists(context, pool_id)
        return self.db.get_pool_member_as_api_dict(context, id)

    def _check_pool_already_has_healthmonitor(self, context, pool_id):
        pool = self.db.get_pool(context, pool_id)
        if pool.healthmonitor:
            raise loadbalancerv2.OneHealthMonitorPerPool(
                pool_id=pool_id, hm_id=pool.healthmonitor.id)

    def create_healthmonitor(self, context, healthmonitor):
        healthmonitor = healthmonitor.get('healthmonitor')
        pool_id = healthmonitor.pop('pool_id')
        self._check_pool_exists(context, pool_id)
        self._check_pool_already_has_healthmonitor(context, pool_id)
        db_pool = self.db.get_pool(context, pool_id)
        self.db.test_and_set_status(context, models.LoadBalancer,
                                    db_pool.root_loadbalancer.id,
                                    n_constants.PENDING_UPDATE)
        try:
            db_hm = self.db.create_healthmonitor_on_pool(context, pool_id,
                                                         healthmonitor)
        except Exception as exc:
            self.db.update_loadbalancer_provisioning_status(
                context, db_pool.root_loadbalancer.id)
            raise exc
        driver = self._get_driver_for_loadbalancer(
            context, db_hm.pool.loadbalancer_id)
        self._call_driver_operation(context,
                                    driver.health_monitor.create,
                                    db_hm)
        return self.db.get_healthmonitor_as_api_dict(context, db_hm.id)

    def update_healthmonitor(self, context, id, healthmonitor):
        healthmonitor = healthmonitor.get('healthmonitor')
        old_hm = self.db.get_healthmonitor(context, id)
        self.db.test_and_set_status(context, models.HealthMonitorV2, id,
                                    n_constants.PENDING_UPDATE)
        try:
            updated_hm = self.db.update_healthmonitor(context, id,
                                                      healthmonitor)
        except Exception as exc:
            self.db.update_loadbalancer_provisioning_status(
                context, old_hm.root_loadbalancer.id)
            raise exc

        driver = self._get_driver_for_loadbalancer(
            context, updated_hm.pool.loadbalancer_id)
        self._call_driver_operation(context,
                                    driver.health_monitor.update,
                                    updated_hm,
                                    old_db_entity=old_hm)

        return self.db.get_healthmonitor_as_api_dict(context, updated_hm.id)

    def delete_healthmonitor(self, context, id):
        self.db.test_and_set_status(context, models.HealthMonitorV2, id,
                                    n_constants.PENDING_DELETE)
        db_hm = self.db.get_healthmonitor(context, id)

        driver = self._get_driver_for_loadbalancer(
            context, db_hm.pool.loadbalancer_id)
        self._call_driver_operation(
            context, driver.health_monitor.delete, db_hm)

    def get_healthmonitor(self, context, id, fields=None):
        return self.db.get_healthmonitor_as_api_dict(context, id)

    def get_healthmonitors(self, context, filters=None, fields=None):
        return self.db.get_healthmonitors_as_api_dict(
            context, filters=filters)

    def stats(self, context, loadbalancer_id):
        lb = self.db.get_loadbalancer(context, loadbalancer_id)
        driver = self._get_driver_for_loadbalancer(context, loadbalancer_id)
        stats_data = driver.load_balancer.stats(context, lb)
        # if we get something from the driver -
        # update the db and return the value from db
        # else - return what we have in db
        if stats_data:
            self.db.update_loadbalancer_stats(context, loadbalancer_id,
                                              stats_data)
        db_stats = self.db.stats(context, loadbalancer_id)
        return {'stats': db_stats.to_api_dict()}

    def create_l7policy(self, context, l7policy):
        l7policy = l7policy.get('l7policy')
        l7policy_db = self.db.create_l7policy(context, l7policy)

        if l7policy_db.attached_to_loadbalancer():
            driver = self._get_driver_for_loadbalancer(
                context, l7policy_db.listener.loadbalancer_id)
            self._call_driver_operation(context,
                                        driver.l7policy.create,
                                        l7policy_db)

        return l7policy_db.to_dict()

    def update_l7policy(self, context, id, l7policy):
        l7policy = l7policy.get('l7policy')
        old_l7policy = self.db.get_l7policy(context, id)
        self.db.test_and_set_status(context, models.L7Policy, id,
                                    n_constants.PENDING_UPDATE)
        try:
            updated_l7policy = self.db.update_l7policy(
                context, id, l7policy)
        except Exception as exc:
            self.db.update_loadbalancer_provisioning_status(
                context, old_l7policy.root_loadbalancer.id)
            raise exc

        if (updated_l7policy.attached_to_loadbalancer() or
                old_l7policy.attached_to_loadbalancer()):
            if updated_l7policy.attached_to_loadbalancer():
                driver = self._get_driver_for_loadbalancer(
                    context, updated_l7policy.listener.loadbalancer_id)
            else:
                driver = self._get_driver_for_loadbalancer(
                    context, old_l7policy.listener.loadbalancer_id)
            self._call_driver_operation(context,
                                        driver.l7policy.update,
                                        updated_l7policy,
                                        old_db_entity=old_l7policy)

        return self.db.get_l7policy_as_api_dict(context, updated_l7policy.id)

    def delete_l7policy(self, context, id):
        self.db.test_and_set_status(context, models.L7Policy, id,
                                    n_constants.PENDING_DELETE)
        l7policy_db = self.db.get_l7policy(context, id)

        if l7policy_db.attached_to_loadbalancer():
            driver = self._get_driver_for_loadbalancer(
                context, l7policy_db.listener.loadbalancer_id)
            self._call_driver_operation(context, driver.l7policy.delete,
                                        l7policy_db)
        else:
            self.db.delete_l7policy(context, id)

    def get_l7policies(self, context, filters=None, fields=None):
        return self.db.get_l7policies_as_api_dict(
            context, filters=filters)

    def get_l7policy(self, context, id, fields=None):
        return self.db.get_l7policy_as_api_dict(context, id)

    def _check_l7policy_exists(self, context, l7policy_id):
        if not self.db._resource_exists(context, models.L7Policy, l7policy_id):
            raise loadbalancerv2.EntityNotFound(name=models.L7Policy.NAME,
                                                id=l7policy_id)

    def create_l7policy_rule(self, context, rule, l7policy_id):
        rule = rule.get('rule')
        rule_db = self.db.create_l7policy_rule(context, rule, l7policy_id)

        if rule_db.attached_to_loadbalancer():
            driver = self._get_driver_for_loadbalancer(
                context, rule_db.policy.listener.loadbalancer_id)
            self._call_driver_operation(context,
                                        driver.l7rule.create,
                                        rule_db)
        else:
            self.db.update_status(context, models.L7Rule, rule_db.id,
                                  lb_const.DEFERRED)

        return rule_db.to_dict()

    def update_l7policy_rule(self, context, id, rule, l7policy_id):
        rule = rule.get('rule')
        old_rule_db = self.db.get_l7policy_rule(context, id, l7policy_id)
        self.db.test_and_set_status(context, models.L7Rule, id,
                                    n_constants.PENDING_UPDATE)
        try:
            upd_rule_db = self.db.update_l7policy_rule(
                context, id, rule, l7policy_id)
        except Exception as exc:
            self.db.update_loadbalancer_provisioning_status(
                context, old_rule_db.root_loadbalancer.id)
            raise exc

        if (upd_rule_db.attached_to_loadbalancer() or
                old_rule_db.attached_to_loadbalancer()):
            if upd_rule_db.attached_to_loadbalancer():
                driver = self._get_driver_for_loadbalancer(
                    context, upd_rule_db.policy.listener.loadbalancer_id)
            else:
                driver = self._get_driver_for_loadbalancer(
                    context, old_rule_db.policy.listener.loadbalancer_id)
            self._call_driver_operation(context,
                                        driver.l7rule.update,
                                        upd_rule_db,
                                        old_db_entity=old_rule_db)
        else:
            self.db.update_status(context, models.L7Rule, id,
                                  lb_const.DEFERRED)

        return upd_rule_db.to_dict()

    def delete_l7policy_rule(self, context, id, l7policy_id):
        self.db.test_and_set_status(context, models.L7Rule, id,
                                    n_constants.PENDING_DELETE)
        rule_db = self.db.get_l7policy_rule(context, id, l7policy_id)

        if rule_db.attached_to_loadbalancer():
            driver = self._get_driver_for_loadbalancer(
                context, rule_db.policy.listener.loadbalancer_id)
            self._call_driver_operation(context, driver.l7rule.delete,
                                        rule_db)
        else:
            self.db.delete_l7policy_rule(context, id)

    def get_l7policy_rules(self, context, l7policy_id,
                           filters=None, fields=None):
        self._check_l7policy_exists(context, l7policy_id)
        return self.db.get_l7policy_rules_as_api_dict(
            context, l7policy_id, filters=filters)

    def get_l7policy_rule(self, context, id, l7policy_id, fields=None):
        self._check_l7policy_exists(context, l7policy_id)
        return self.db.get_l7policy_rule_as_api_dict(context, id, l7policy_id)

    def validate_provider(self, provider):
        if provider not in self.drivers:
            raise pconf.ServiceProviderNotFound(
                provider=provider, service_type=constants.LOADBALANCERV2)

    def _default_status(self, obj, exclude=None, **kw):
        exclude = exclude or []
        status = {}
        status["id"] = obj.id
        if "provisioning_status" not in exclude:
            status["provisioning_status"] = obj.provisioning_status
        if "operating_status" not in exclude:
            status["operating_status"] = obj.operating_status
        for key, value in kw.items():
            status[key] = value
        try:
            status['name'] = getattr(obj, 'name')
        except AttributeError:
            pass
        return status

    def _disable_entity_and_children(self, obj):
        DISABLED = lb_const.DISABLED
        d = {}
        if isinstance(obj, data_models.LoadBalancer):
            d = {'loadbalancer': {'id': obj.id, 'operating_status': DISABLED,
                'provisioning_status': obj.provisioning_status,
                'name': obj.name, 'listeners': []}}
            for listener in obj.listeners:
                listener_dict = self._disable_entity_and_children(listener)
                d['loadbalancer']['listeners'].append(listener_dict)
        if isinstance(obj, data_models.Listener):
            d = {'id': obj.id, 'operating_status': DISABLED,
                 'provisioning_status': obj.provisioning_status,
                 'name': obj.name, 'pools': [], 'l7policies': []}
            if obj.default_pool:
                pool_dict = self._disable_entity_and_children(obj.default_pool)
                d['pools'].append(pool_dict)
            for policy in obj.l7_policies:
                policy_dict = self._disable_entity_and_children(policy)
                d['l7policies'].append(policy_dict)
        if isinstance(obj, data_models.L7Policy):
            d = {'id': obj.id,
                 'provisioning_status': obj.provisioning_status,
                 'name': obj.name, 'rules': []}
            for rule in obj.rules:
                rule_dict = self._disable_entity_and_children(rule)
                d['rules'].append(rule_dict)
        if isinstance(obj, data_models.L7Rule):
            d = {'id': obj.id,
                 'provisioning_status': obj.provisioning_status,
                 'type': obj.type}
        if isinstance(obj, data_models.Pool):
            d = {'id': obj.id, 'operating_status': DISABLED,
                 'provisioning_status': obj.provisioning_status,
                 'name': obj.name, 'members': [], 'healthmonitor': {}}
            for member in obj.members:
                member_dict = self._disable_entity_and_children(member)
                d['members'].append(member_dict)
            d['healthmonitor'] = self._disable_entity_and_children(
                obj.healthmonitor)
        if isinstance(obj, data_models.HealthMonitor):
            d = {'id': obj.id, 'provisioning_status': obj.provisioning_status,
                 'type': obj.type}
        if isinstance(obj, data_models.Member):
            d = {'id': obj.id, 'operating_status': DISABLED,
                 'provisioning_status': obj.provisioning_status,
                 'address': obj.address, 'protocol_port': obj.protocol_port}
        return d

    def statuses(self, context, loadbalancer_id):
        OS = "operating_status"
        lb = self.db.get_loadbalancer(context, loadbalancer_id)
        if not lb.admin_state_up:
            return {"statuses": self._disable_entity_and_children(lb)}
        lb_status = self._default_status(lb, listeners=[], pools=[])
        statuses = {"statuses": {"loadbalancer": lb_status}}
        if self._is_degraded(lb):
            self._set_degraded(lb_status)
        for curr_listener in lb.listeners:
            if not curr_listener.admin_state_up:
                lb_status["listeners"].append(
                    self._disable_entity_and_children(curr_listener)
                )
                continue
            listener_status = self._default_status(curr_listener,
                                                   pools=[], l7policies=[])
            lb_status["listeners"].append(listener_status)
            if self._is_degraded(curr_listener):
                self._set_degraded(lb_status)

            for policy in curr_listener.l7_policies:
                if not policy.admin_state_up:
                    listener_status["l7policies"].append(
                        self._disable_entity_and_children(policy))
                    continue
                policy_opts = {"action": policy.action, "rules": []}
                policy_status = self._default_status(policy, exclude=[OS],
                                                     **policy_opts)
                listener_status["l7policies"].append(policy_status)
                if self._is_degraded(policy, exclude=[OS]):
                    self._set_degraded(policy_status, listener_status,
                                       lb_status)
                for rule in policy.rules:
                    if not rule.admin_state_up:
                        policy_status["rules"].append(
                            self._disable_entity_and_children(rule))
                        continue
                    rule_opts = {"type": rule.type}
                    rule_status = self._default_status(rule, exclude=[OS],
                                                       **rule_opts)
                    policy_status["rules"].append(rule_status)
                    if self._is_degraded(rule, exclude=[OS]):
                        self._set_degraded(rule_status, policy_status,
                                           listener_status,
                                           lb_status)
            if not curr_listener.default_pool:
                continue
            if not curr_listener.default_pool.admin_state_up:
                listener_status["pools"].append(
                    self._disable_entity_and_children(
                        curr_listener.default_pool))
                continue
            pool_status = self._default_status(curr_listener.default_pool,
                                              members=[], healthmonitor={})
            listener_status["pools"].append(pool_status)
            if (pool_status["id"] not in
                [ps["id"] for ps in lb_status["pools"]]):
                lb_status["pools"].append(pool_status)
            if self._is_degraded(curr_listener.default_pool):
                self._set_degraded(listener_status, lb_status)
            members = curr_listener.default_pool.members
            for curr_member in members:
                if not curr_member.admin_state_up:
                    pool_status["members"].append(
                        self._disable_entity_and_children(curr_member))
                    continue
                member_opts = {"address": curr_member.address,
                               "protocol_port": curr_member.protocol_port}
                member_status = self._default_status(curr_member,
                                                     **member_opts)
                pool_status["members"].append(member_status)
                if self._is_degraded(curr_member):
                    self._set_degraded(pool_status, listener_status,
                                       lb_status)
            healthmonitor = curr_listener.default_pool.healthmonitor
            if healthmonitor:
                if not healthmonitor.admin_state_up:
                    dhm = self._disable_entity_and_children(healthmonitor)
                    hm_status = dhm
                else:
                    hm_status = self._default_status(healthmonitor,
                                exclude=[OS], type=healthmonitor.type)
                    if self._is_degraded(healthmonitor, exclude=[OS]):
                        self._set_degraded(pool_status, listener_status,
                                           lb_status)
            else:
                hm_status = {}
            pool_status["healthmonitor"] = hm_status

        # Needed for pools not associated with a listener
        for curr_pool in lb.pools:
            if curr_pool.id in [ps["id"] for ps in lb_status["pools"]]:
                continue
            if not curr_pool.admin_state_up:
                lb_status["pools"].append(
                    self._disable_entity_and_children(curr_pool))
                continue
            pool_status = self._default_status(curr_pool, members=[],
                                               healthmonitor={})
            lb_status["pools"].append(pool_status)
            if self._is_degraded(curr_pool):
                self._set_degraded(lb_status)
            members = curr_pool.members
            for curr_member in members:
                if not curr_member.admin_state_up:
                    pool_status["members"].append(
                        self._disable_entity_and_children(curr_member))
                    continue
                member_opts = {"address": curr_member.address,
                               "protocol_port": curr_member.protocol_port}
                member_status = self._default_status(curr_member,
                                                     **member_opts)
                pool_status["members"].append(member_status)
                if self._is_degraded(curr_member):
                    self._set_degraded(pool_status, lb_status)
            healthmonitor = curr_pool.healthmonitor
            if healthmonitor:
                if not healthmonitor.admin_state_up:
                    dhm = self._disable_entity_and_children(healthmonitor)
                    hm_status = dhm
                else:
                    hm_status = self._default_status(healthmonitor,
                                exclude=[OS], type=healthmonitor.type)
                    if self._is_degraded(healthmonitor, exclude=[OS]):
                        self._set_degraded(pool_status, listener_status,
                                           lb_status)
            else:
                hm_status = {}
            pool_status["healthmonitor"] = hm_status
        return statuses

    def _set_degraded(self, *objects):
        for obj in objects:
            obj["operating_status"] = lb_const.DEGRADED

    def _is_degraded(self, obj, exclude=None):
        exclude = exclude or []
        if "provisioning_status" not in exclude:
            if obj.provisioning_status == n_constants.ERROR:
                return True
        if "operating_status" not in exclude:
            if ((obj.operating_status != lb_const.ONLINE) and
                (obj.operating_status != lb_const.NO_MONITOR)):
                return True
        return False

    # NOTE(brandon-logan): these need to be concrete methods because the
    # neutron request pipeline calls these methods before the plugin methods
    # are ever called
    def get_members(self, context, filters=None, fields=None):
        pass

    def get_member(self, context, id, fields=None):
        pass
