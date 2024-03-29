#
# Copyright 2014-2015 Rackspace.  All rights reserved
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

import re

import netaddr
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import ipv6_utils
from neutron.db import api as db_api
from neutron.db import common_db_mixin as base_db
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as pg_const
from neutron_lib.plugins import directory
from oslo_db import exception
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.orm import lazyload
from sqlalchemy.orm import subqueryload

from neutron_lbaas._i18n import _
from neutron_lbaas import agent_scheduler
from neutron_lbaas.db.loadbalancer import models
from neutron_lbaas.extensions import acl
from neutron_lbaas.extensions import l7
from neutron_lbaas.extensions import lb_network_vip
from neutron_lbaas.extensions import loadbalancerv2
from neutron_lbaas.extensions import sharedpools
from neutron_lbaas.extensions import lb_user_device_map
from neutron_lbaas.services.loadbalancer import constants as lb_const
from neutron_lbaas.services.loadbalancer import data_models


LOG = logging.getLogger(__name__)


class LoadBalancerPluginDbv2(base_db.CommonDbMixin,
                             agent_scheduler.LbaasAgentSchedulerDbMixin):
    """Wraps loadbalancer with SQLAlchemy models.

    A class that wraps the implementation of the Neutron loadbalancer
    plugin database access interface using SQLAlchemy models.
    """

    @property
    def _core_plugin(self):
        return directory.get_plugin()

    def _get_resource(self, context, model, id, for_update=False):
        resource = None
        try:
            if for_update:
                # To lock the instance for update, return a single
                # instance, instead of an instance with LEFT OUTER
                # JOINs that do not work in PostgreSQL
                query = self._model_query(context, model).options(
                    lazyload('*')
                ).filter(
                    model.id == id).with_lockmode('update')
                resource = query.one()
            else:
                resource = self._get_by_id(context, model, id)
        except exc.NoResultFound:
            with excutils.save_and_reraise_exception(reraise=False) as ctx:
                if issubclass(model, (models.LoadBalancer, models.Listener,
                                      models.L7Policy, models.L7Rule,
                                      models.PoolV2, models.MemberV2,
                                      models.HealthMonitorV2,
                                      models.LoadBalancerStatistics,
                                      models.SessionPersistenceV2)):
                    raise loadbalancerv2.EntityNotFound(name=model.NAME, id=id)
                ctx.reraise = True
        return resource

    def _resource_exists(self, context, model, id):
        try:
            self._get_by_id(context, model, id)
        except exc.NoResultFound:
            return False
        return True

    def _get_resources(self, context, model, filters=None, options=None):
        query = self._get_collection_query(context, model,
                                           filters=filters)
        if options:
            query = query.options(options)
        return [model_instance for model_instance in query]

    def _create_port_choose_fixed_ip(self, fixed_ips):
        # Neutron will try to allocate IPv4, IPv6, and IPv6 EUI-64 addresses.
        # We're most interested in the IPv4 address. An IPv4 vip can be
        # routable from IPv6. Creating a port by network can be used to manage
        # the dwindling, fragmented IPv4 address space. IPv6 has enough
        # addresses that a single subnet can always be created that's big
        # enough to allocate all vips.
        for fixed_ip in fixed_ips:
            ip_address = fixed_ip['ip_address']
            ip = netaddr.IPAddress(ip_address)
            if ip.version == 4:
                return fixed_ip
        # An EUI-64 address isn't useful as a vip
        for fixed_ip in fixed_ips:
            ip_address = fixed_ip['ip_address']
            ip = netaddr.IPAddress(ip_address)
            if ip.version == 6 and not ipv6_utils.is_eui64_address(ip_address):
                return fixed_ip
        for fixed_ip in fixed_ips:
            return fixed_ip

    def _create_port_for_load_balancer(self, context, lb_db, ip_address,
                                       network_id=None):
        if lb_db.vip_subnet_id:
            assign_subnet = False
            # resolve subnet and create port
            subnet = self._core_plugin.get_subnet(context, lb_db.vip_subnet_id)
            network_id = subnet['network_id']
            fixed_ip = {'subnet_id': subnet['id']}
            if ip_address and ip_address != n_const.ATTR_NOT_SPECIFIED:
                fixed_ip['ip_address'] = ip_address
            fixed_ips = [fixed_ip]
        elif network_id and network_id != n_const.ATTR_NOT_SPECIFIED:
            assign_subnet = True
            fixed_ips = n_const.ATTR_NOT_SPECIFIED
        else:
            attrs = _("vip_subnet_id or vip_network_id")
            raise loadbalancerv2.RequiredAttributeNotSpecified(attr_name=attrs)

        port_data = {
            'tenant_id': lb_db.tenant_id,
            'name': 'loadbalancer-' + lb_db.id,
            'network_id': network_id,
            'mac_address': n_const.ATTR_NOT_SPECIFIED,
            'admin_state_up': False,
            'device_id': lb_db.id,
            'device_owner': n_const.DEVICE_OWNER_LOADBALANCERV2,
            'fixed_ips': fixed_ips
        }

        port = self._core_plugin.create_port(context, {'port': port_data})
        lb_db.vip_port_id = port['id']

        if assign_subnet:
            fixed_ip = self._create_port_choose_fixed_ip(port['fixed_ips'])
            lb_db.vip_address = fixed_ip['ip_address']
            lb_db.vip_subnet_id = fixed_ip['subnet_id']
        else:
            for fixed_ip in port['fixed_ips']:
                if fixed_ip['subnet_id'] == lb_db.vip_subnet_id:
                    lb_db.vip_address = fixed_ip['ip_address']
                    break

    def _create_loadbalancer_stats(self, context, loadbalancer_id, data=None):
        # This is internal method to add load balancer statistics.  It won't
        # be exposed to API
        data = data or {}
        stats_db = models.LoadBalancerStatistics(
            loadbalancer_id=loadbalancer_id,
            bytes_in=data.get(lb_const.STATS_IN_BYTES, 0),
            bytes_out=data.get(lb_const.STATS_OUT_BYTES, 0),
            active_connections=data.get(lb_const.STATS_ACTIVE_CONNECTIONS, 0),
            total_connections=data.get(lb_const.STATS_TOTAL_CONNECTIONS, 0)
        )
        return stats_db

    def _delete_loadbalancer_stats(self, context, loadbalancer_id):
        # This is internal method to delete pool statistics. It won't
        # be exposed to API
        with context.session.begin(subtransactions=True):
            stats_qry = context.session.query(models.LoadBalancerStatistics)
            try:
                stats = stats_qry.filter_by(
                    loadbalancer_id=loadbalancer_id).one()
            except exc.NoResultFound:
                raise loadbalancerv2.EntityNotFound(
                    name=models.LoadBalancerStatistics.NAME,
                    id=loadbalancer_id)
            context.session.delete(stats)

    def _load_id(self, context, model_dict):
        model_dict['id'] = uuidutils.generate_uuid()

    def check_subnet_exists(self, context, subnet_id):
        try:
            self._core_plugin.get_subnet(context, subnet_id)
        except n_exc.SubnetNotFound:
            raise loadbalancerv2.EntityNotFound(name="Subnet", id=subnet_id)

    def _validate_and_return_vip_net(self, ctxt, lb):
        network_id = lb.pop('vip_network_id', None)

        if network_id != n_const.ATTR_NOT_SPECIFIED and network_id:
            subnets = self._core_plugin.get_subnets_by_network(ctxt,
                                                               network_id)
            if not subnets:
                raise lb_network_vip.VipNetworkInvalid(network=network_id)
            return network_id
        return

    def assert_modification_allowed(self, obj):
        status = getattr(obj, 'provisioning_status', None)
        if status in [n_const.PENDING_DELETE, n_const.PENDING_UPDATE,
                      n_const.PENDING_CREATE]:
            id = getattr(obj, 'id', None)
            raise loadbalancerv2.StateInvalid(id=id, state=status)

    def test_and_set_status(self, context, model, id, status):
        with context.session.begin(subtransactions=True):
            db_lb_child = None
            if model == models.LoadBalancer:
                db_lb = self._get_resource(context, model, id, for_update=True)
            else:
                db_lb_child = self._get_resource(context, model, id)
                db_lb = self._get_resource(context, models.LoadBalancer,
                                           db_lb_child.root_loadbalancer.id)
            # This method will raise an exception if modification is not
            # allowed.
            self.assert_modification_allowed(db_lb)

            # if the model passed in is not a load balancer then we will
            # set its root load balancer's provisioning status to
            # PENDING_UPDATE and the model's status to the status passed in
            # Otherwise we are just setting the load balancer's provisioning
            # status to the status passed in
            if db_lb_child:
                db_lb.provisioning_status = n_const.PENDING_UPDATE
                db_lb_child.provisioning_status = status
            else:
                db_lb.provisioning_status = status

    def update_loadbalancer_provisioning_status(self, context, lb_id,
                                                status=n_const.ACTIVE):
        self.update_status(context, models.LoadBalancer, lb_id,
                           provisioning_status=status)

    def update_status(self, context, model, id, provisioning_status=None,
                      operating_status=None):
        with context.session.begin(subtransactions=True):
            if issubclass(model, models.LoadBalancer):
                try:
                    model_db = (self._model_query(context, model).
                                filter(model.id == id).
                                options(orm.noload('vip_port')).
                                one())
                except exc.NoResultFound:
                    raise loadbalancerv2.EntityNotFound(
                        name=models.LoadBalancer.NAME, id=id)
            else:
                model_db = self._get_resource(context, model, id)
            if provisioning_status and (model_db.provisioning_status !=
                                        provisioning_status):
                model_db.provisioning_status = provisioning_status
            if (operating_status and hasattr(model_db, 'operating_status') and
                    model_db.operating_status != operating_status):
                model_db.operating_status = operating_status

    def create_loadbalancer_graph(self, context, loadbalancer,
                                  allocate_vip=True):
        l7policies_ids = []
        with context.session.begin(subtransactions=True):
            listeners = loadbalancer.pop('listeners', [])
            lb_db = self.create_loadbalancer(context, loadbalancer,
                                             allocate_vip=allocate_vip)
            for listener in listeners:
                listener['loadbalancer_id'] = lb_db.id
                default_pool = listener.pop('default_pool', None)
                if (default_pool and
                        default_pool != n_const.ATTR_NOT_SPECIFIED):
                    default_pool['loadbalancer_id'] = lb_db.id
                    hm = default_pool.pop('healthmonitor', None)
                    if hm and hm != n_const.ATTR_NOT_SPECIFIED:
                        hm_db = self.create_healthmonitor(context, hm)
                        default_pool['healthmonitor_id'] = hm_db.id
                    members = default_pool.pop('members', [])
                    pool_db = self.create_pool(context, default_pool)
                    listener['default_pool_id'] = pool_db.id
                    for member in members:
                        member['pool_id'] = pool_db.id
                        self.create_pool_member(context, member, pool_db.id)
                l7policies = listener.pop('l7policies', None)
                listener_db = self.create_listener(context, listener)
                if (l7policies and l7policies !=
                        n_const.ATTR_NOT_SPECIFIED):
                    for l7policy in l7policies:
                        l7policy['listener_id'] = listener_db.id
                        redirect_pool = l7policy.pop('redirect_pool', None)
                        l7rules = l7policy.pop('rules', [])
                        if (redirect_pool and redirect_pool !=
                                n_const.ATTR_NOT_SPECIFIED):
                            redirect_pool['loadbalancer_id'] = lb_db.id
                            rhm = redirect_pool.pop('healthmonitor', None)
                            rmembers = redirect_pool.pop('members', [])
                            if rhm and rhm != n_const.ATTR_NOT_SPECIFIED:
                                rhm_db = self.create_healthmonitor(context,
                                                                   rhm)
                                redirect_pool['healthmonitor_id'] = rhm_db.id
                            rpool_db = self.create_pool(context, redirect_pool)
                            l7policy['redirect_pool_id'] = rpool_db.id
                            for rmember in rmembers:
                                rmember['pool_id'] = rpool_db.id
                                self.create_pool_member(context, rmember,
                                                        rpool_db.id)
                        l7policy_db = self.create_l7policy(context, l7policy)
                        l7policies_ids.append(l7policy_db.id)
                        if (l7rules and l7rules !=
                                n_const.ATTR_NOT_SPECIFIED):
                            for l7rule in l7rules:
                                self.create_l7policy_rule(
                                    context, l7rule, l7policy_db.id)
        # SQL Alchemy cache issue where l7rules won't show up as intended.
        for l7policy_id in l7policies_ids:
            l7policy_db = self._get_resource(context, models.L7Policy,
                                           l7policy_id)
            context.session.expire(l7policy_db)
        return self.get_loadbalancer(context, lb_db.id)

    def create_acl_group(self, context, acl_group):
        self._load_id(context, acl_group)
        acl_group_db = models.ACLGroup(**acl_group)
        with context.session.begin(subtransactions=True):
            context.session.add(acl_group_db)
        return data_models.ACLGroup.from_sqlalchemy_model(acl_group_db)

    def delete_acl_group(self, context, id):
        with context.session.begin(subtransactions=True):
            acl_group_db = self._get_resource(context, models.ACLGroup, id)
            context.session.delete(acl_group_db)

    def update_acl_group(self, context, id, acl_group):
        with context.session.begin(subtransactions=True):
            group_db = self._get_resource(context, models.ACLGroup, id)
            group_db.update(acl_group)
        context.session.refresh(group_db)
        return data_models.ACLGroup.from_sqlalchemy_model(group_db)

    def get_acl_groups(self, context, filters=None):
        filters = filters or {}
        acl_group_dbs = self._get_resources(context, models.ACLGroup,
                                            filters=filters)
        return [data_models.ACLGroup.from_sqlalchemy_model(acl_group_db)
                for acl_group_db in acl_group_dbs]

    def get_acl_group(self, context, id):
        acl_group_db = self._get_resource(context, models.ACLGroup, id)
        return data_models.ACLGroup.from_sqlalchemy_model(acl_group_db)

    def create_acl_group_acl_rule(self, context, acl_group_id, acl_rule):
        self._load_id(context, acl_rule)
        with context.session.begin(subtransactions=True):
            acl_rule['acl_group_id'] = acl_group_id
            acl_rule_db = models.ACLRule(**acl_rule)
            context.session.add(acl_rule_db)
        return data_models.ACLRule.from_sqlalchemy_model(acl_rule_db)

    def delete_acl_group_acl_rule(self, context, id):
        with context.session.begin(subtransactions=True):
            acl_rule_db = self._get_resource(context, models.ACLRule, id)
            context.session.delete(acl_rule_db)

    def update_acl_group_acl_rule(self, context, id, acl_rule):
        with context.session.begin(subtransactions=True):
            rule_db = self._get_resource(context, models.ACLRule, id)
            rule_db.update(acl_rule)
        context.session.refresh(rule_db)
        return data_models.ACLRule.from_sqlalchemy_model(rule_db)

    def get_acl_group_acl_rules(self, context, filters=None):
        filters = filters or {}
        rule_dbs = self._get_resources(context, models.ACLRule,
                                       filters=filters)
        return [data_models.ACLRule.from_sqlalchemy_model(rule_db)
                for rule_db in rule_dbs]

    def get_acl_group_acl_rule(self, context, id):
        acl_rule_db = self._get_resource(context, models.ACLRule, id)
        return data_models.ACLRule.from_sqlalchemy_model(acl_rule_db)

    def add_listener(self, context, acl_group_id, binding_info):
        listener_id = binding_info.get('listener_id')
        filters = {'listener_id': [listener_id]}
        acl_lsnr_binding_info = self._get_resources(
            context, models.ACLGroupListenerBinding, filters=filters)
        if acl_lsnr_binding_info:
            raise acl.DuplicateBindListenerWithACL(
                listener_id=listener_id,
                acl_group_id=acl_lsnr_binding_info[0].acl_group_id)
        binding_info['acl_group_id'] = acl_group_id
        acl_group_listener_binding_db = models.ACLGroupListenerBinding(
            **binding_info)
        with context.session.begin(subtransactions=True):
            context.session.add(acl_group_listener_binding_db)
        return data_models.ACLGroupListenerBinding.\
            from_sqlalchemy_model(acl_group_listener_binding_db)

    def remove_listener(self, context, listener_id, acl_group_id):
        acl_group_listener_binding_db = None
        with context.session.begin(subtransactions=True):
            qry = context.session.query(
                models.ACLGroupListenerBinding)
            qry = qry.filter_by(
                listener_id=listener_id,
                acl_group_id=acl_group_id)
            try:
                acl_group_listener_binding_db = qry.one()
            except exc.NoResultFound:
                raise acl.NonexistentRelationShip(
                    listener_id=listener_id, acl_group_id=acl_group_id)
            context.session.delete(acl_group_listener_binding_db)
        return data_models.ACLGroupListenerBinding. \
            from_sqlalchemy_model(acl_group_listener_binding_db)

    def get_acl_listener_binding_info(
            self, context, listener_id, acl_group_id):
        acl_group_listener_binding_db = None
        with context.session.begin(subtransactions=True):
            qry = context.session.query(
                models.ACLGroupListenerBinding)
            qry = qry.filter_by(
                listener_id=listener_id,
                acl_group_id=acl_group_id)
            try:
                acl_group_listener_binding_db = qry.one()
            except exc.NoResultFound:
                raise acl.NonexistentRelationShip(
                    listener_id=listener_id, acl_group_id=acl_group_id)
        return data_models.ACLGroupListenerBinding. \
            from_sqlalchemy_model(acl_group_listener_binding_db)

    def get_acl_binding_info_by_acl_group_id(
            self, context, acl_group_id):

        filters = {'acl_group_id': [acl_group_id]}
        acl_group_listener_binding_dbs = self._get_resources(context, models.ACLGroupListenerBinding,
                                     filters=filters)
        return [data_models.ACLGroupListenerBinding.from_sqlalchemy_model(acl_group_listener_binding_db).to_api_dict()
                for acl_group_listener_binding_db in acl_group_listener_binding_dbs]

    def get_acl_listener_binding_by_listener_id(
            self, context, listener_id):
        acl_group_listener_binding_db = None
        with context.session.begin(subtransactions=True):
            qry = context.session.query(
                models.ACLGroupListenerBinding)
            qry = qry.filter_by(
                listener_id=listener_id)
            try:
                acl_group_listener_binding_db = qry.one()
            except exc.NoResultFound:
                return acl_group_listener_binding_db
        return data_models.ACLGroupListenerBinding. \
            from_sqlalchemy_model(acl_group_listener_binding_db)

    def create_loadbalancer(self, context, loadbalancer, allocate_vip=True):
        self._load_id(context, loadbalancer)
        vip_network_id = self._validate_and_return_vip_net(context,
                                                           loadbalancer)
        vip_subnet_id = loadbalancer.pop('vip_subnet_id', None)
        vip_address = loadbalancer.pop('vip_address')
        if vip_subnet_id and vip_subnet_id != n_const.ATTR_NOT_SPECIFIED:
            loadbalancer['vip_subnet_id'] = vip_subnet_id
        loadbalancer['provisioning_status'] = n_const.PENDING_CREATE
        loadbalancer['operating_status'] = lb_const.OFFLINE
        lb_db = models.LoadBalancer(**loadbalancer)

        # create port outside of lb create transaction since it can sometimes
        # cause lock wait timeouts
        if allocate_vip:
            LOG.debug("Plugin will allocate the vip as a neutron port.")
            self._create_port_for_load_balancer(context, lb_db,
                                                vip_address, vip_network_id)

        with context.session.begin(subtransactions=True):
            context.session.add(lb_db)
            context.session.flush()
            lb_db.stats = self._create_loadbalancer_stats(
                context, lb_db.id)
            context.session.add(lb_db)
            context.session.flush()
        return data_models.LoadBalancer.from_sqlalchemy_model(lb_db)

    def update_loadbalancer(self, context, id, loadbalancer):
        with context.session.begin(subtransactions=True):
            lb_db = self._get_resource(context, models.LoadBalancer, id)
            lb_db.update(loadbalancer)
        return data_models.LoadBalancer.from_sqlalchemy_model(lb_db)

    def delete_loadbalancer(self, context, id, delete_vip_port=True):
        with context.session.begin(subtransactions=True):
            lb_db = self._get_resource(context, models.LoadBalancer, id)
            context.session.delete(lb_db)
        if delete_vip_port and lb_db.vip_port:
            self._delete_vip_port(context, lb_db.vip_port_id)

    @db_api.retry_db_errors
    def _delete_vip_port(self, context, vip_port_id):
        self._core_plugin.delete_port(context, vip_port_id)

    def prevent_lbaasv2_port_deletion(self, context, port_id):
        try:
            port_db = self._core_plugin._get_port(context, port_id)
        except n_exc.PortNotFound:
            return
        if port_db['device_owner'] == n_const.DEVICE_OWNER_LOADBALANCERV2:
            filters = {'vip_port_id': [port_id]}
            if len(self.get_loadbalancer_ids(context, filters=filters)) > 0:
                reason = _('has device owner %s') % port_db['device_owner']
                raise n_exc.ServicePortInUse(port_id=port_db['id'],
                                             reason=reason)

    def subscribe(self):
        registry.subscribe(
            _prevent_lbaasv2_port_delete_callback, resources.PORT,
            events.BEFORE_DELETE)

    def get_loadbalancer_ids(self, context, filters=None):
        lb_dbs = self._get_resources(context, models.LoadBalancer,
                                     filters=filters)
        return [lb_db.id
                for lb_db in lb_dbs]

    def get_loadbalancers(self, context, filters=None):
        lb_dbs = self._get_resources(context, models.LoadBalancer,
                                     filters=filters)
        return [data_models.LoadBalancer.from_sqlalchemy_model(lb_db)
                for lb_db in lb_dbs]

    def get_loadbalancers_as_api_dict(self, context, filters=None):
        options = (
            subqueryload(models.LoadBalancer.listeners),
            subqueryload(models.LoadBalancer.pools),
            subqueryload(models.LoadBalancer.provider)
        )
        lb_dbs = self._get_resources(context, models.LoadBalancer,
                                     filters=filters, options=options)
        return [lb_db.to_api_dict
                for lb_db in lb_dbs]

    def get_provider_names_used_in_loadbalancers(self, context):
        lb_dbs = self._get_resources(context, models.LoadBalancer)
        return [lb_db.provider.provider_name for lb_db in lb_dbs]

    def get_loadbalancer(self, context, id):
        lb_db = self._get_resource(context, models.LoadBalancer, id)
        return data_models.LoadBalancer.from_sqlalchemy_model(lb_db)

    def get_loadbalancer_as_api_dict(self, context, id):
        lb_db = self._get_resource(context, models.LoadBalancer, id)
        return lb_db.to_api_dict

    def _validate_listener_data(self, context, listener):
        pool_id = listener.get('default_pool_id')
        lb_id = listener.get('loadbalancer_id')
        if lb_id:
            if not self._resource_exists(context, models.LoadBalancer,
                                         lb_id):
                raise loadbalancerv2.EntityNotFound(
                    name=models.LoadBalancer.NAME, id=lb_id)
        if pool_id:
            if not self._resource_exists(context, models.PoolV2, pool_id):
                raise loadbalancerv2.EntityNotFound(
                    name=models.PoolV2.NAME, id=pool_id)
            pool = self._get_resource(context, models.PoolV2, pool_id)
            if ((pool.protocol, listener.get('protocol'))
                not in lb_const.LISTENER_POOL_COMPATIBLE_PROTOCOLS):
                raise loadbalancerv2.ListenerPoolProtocolMismatch(
                    listener_proto=listener['protocol'],
                    pool_proto=pool.protocol)
        if lb_id and pool_id:
            pool = self._get_resource(context, models.PoolV2, pool_id)
            if pool.loadbalancer_id != lb_id:
                raise sharedpools.ListenerPoolLoadbalancerMismatch(
                    pool_id=pool_id,
                    lb_id=pool.loadbalancer_id)

    def _validate_l7policy_data(self, context, l7policy):
        if l7policy['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_POOL:
            if not l7policy['redirect_pool_id']:
                raise l7.L7PolicyRedirectPoolIdMissing()
            if not self._resource_exists(
                context, models.PoolV2, l7policy['redirect_pool_id']):
                raise loadbalancerv2.EntityNotFound(
                    name=models.PoolV2.NAME, id=l7policy['redirect_pool_id'])

            pool = self._get_resource(
                context, models.PoolV2, l7policy['redirect_pool_id'])

            listener = self._get_resource(
                context, models.Listener, l7policy['listener_id'])

            if pool.loadbalancer_id != listener.loadbalancer_id:
                raise sharedpools.ListenerAndPoolMustBeOnSameLoadbalancer()

        if (l7policy['action'] == lb_const.L7_POLICY_ACTION_REDIRECT_TO_URL
            and 'redirect_url' not in l7policy):
            raise l7.L7PolicyRedirectUrlMissing()

    def _validate_l7rule_data(self, context, rule):
        def _validate_regex(regex):
            try:
                re.compile(regex)
            except Exception as e:
                raise l7.L7RuleInvalidRegex(e=str(e))

        def _validate_key(key):
            p = re.compile(lb_const.HTTP_HEADER_COOKIE_NAME_REGEX)
            if not p.match(key):
                raise l7.L7RuleInvalidKey()

        def _validate_cookie_value(value):
            p = re.compile(lb_const.HTTP_COOKIE_VALUE_REGEX)
            if not p.match(value):
                raise l7.L7RuleInvalidCookieValue()

        def _validate_non_cookie_value(value):
            p = re.compile(lb_const.HTTP_HEADER_VALUE_REGEX)
            q = re.compile(lb_const.HTTP_QUOTED_HEADER_VALUE_REGEX)
            if not p.match(value) and not q.match(value):
                raise l7.L7RuleInvalidHeaderValue()

        if rule['compare_type'] == lb_const.L7_RULE_COMPARE_TYPE_REGEX:
            _validate_regex(rule['value'])

        if rule['type'] in [lb_const.L7_RULE_TYPE_HEADER,
                            lb_const.L7_RULE_TYPE_COOKIE]:
            if ('key' not in rule or not rule['key']):
                raise l7.L7RuleKeyMissing()
            _validate_key(rule['key'])

        if rule['compare_type'] != lb_const.L7_RULE_COMPARE_TYPE_REGEX:
            if rule['type'] == lb_const.L7_RULE_TYPE_COOKIE:
                _validate_cookie_value(rule['value'])
            else:
                if rule['type'] in [lb_const.L7_RULE_TYPE_HEADER,
                                  lb_const.L7_RULE_TYPE_HOST_NAME,
                                  lb_const.L7_RULE_TYPE_PATH]:
                    _validate_non_cookie_value(rule['value'])
                elif (rule['compare_type'] ==
                      lb_const.L7_RULE_COMPARE_TYPE_EQUAL_TO):
                    _validate_non_cookie_value(rule['value'])
                else:
                    raise l7.L7RuleUnsupportedCompareType(type=rule['type'])

    def _convert_api_to_db(self, listener):
        # NOTE(blogan): Converting the values for db models for now to
        # limit the scope of this change
        if 'default_tls_container_ref' in listener:
            tls_cref = listener.get('default_tls_container_ref')
            del listener['default_tls_container_ref']
            listener['default_tls_container_id'] = tls_cref
        if 'sni_container_refs' in listener:
            sni_crefs = listener.get('sni_container_refs')
            del listener['sni_container_refs']
            listener['sni_container_ids'] = sni_crefs

    def create_listener(self, context, listener):
        self._convert_api_to_db(listener)
        try:
            with context.session.begin(subtransactions=True):
                self._load_id(context, listener)
                listener['provisioning_status'] = n_const.PENDING_CREATE
                listener['operating_status'] = lb_const.OFFLINE
                # Check for unspecified loadbalancer_id and listener_id and
                # set to None
                for id in ['loadbalancer_id', 'default_pool_id']:
                    if listener.get(id) == n_const.ATTR_NOT_SPECIFIED:
                        listener[id] = None

                self._validate_listener_data(context, listener)
                sni_container_ids = []
                if 'sni_container_ids' in listener:
                    sni_container_ids = listener.pop('sni_container_ids')
                try:
                    listener_db_entry = models.Listener(**listener)
                except Exception as exc:
                    raise exc
                for container_id in sni_container_ids:
                    sni = models.SNI(listener_id=listener_db_entry.id,
                                     tls_container_id=container_id)
                    listener_db_entry.sni_containers.append(sni)
                context.session.add(listener_db_entry)
        except exception.DBDuplicateEntry:
            raise loadbalancerv2.LoadBalancerListenerProtocolPortExists(
                lb_id=listener['loadbalancer_id'],
                protocol_port=listener['protocol_port'])
        context.session.refresh(listener_db_entry.loadbalancer)
        return data_models.Listener.from_sqlalchemy_model(listener_db_entry)

    def update_listener(self, context, id, listener,
                        tls_containers_changed=False):
        self._convert_api_to_db(listener)
        with context.session.begin(subtransactions=True):
            listener_db = self._get_resource(context, models.Listener, id)

            if not listener.get('protocol'):
                # User did not intend to change the protocol so we will just
                # use the same protocol already stored so the validation knows
                listener['protocol'] = listener_db.protocol
            self._validate_listener_data(context, listener)

            if tls_containers_changed:
                listener_db.sni_containers = []
                for container_id in listener['sni_container_ids']:
                    sni = models.SNI(listener_id=id,
                                     tls_container_id=container_id)
                    listener_db.sni_containers.append(sni)

            listener_db.update(listener)

        context.session.refresh(listener_db)
        return data_models.Listener.from_sqlalchemy_model(listener_db)

    def delete_listener(self, context, id):
        listener_db_entry = self._get_resource(context, models.Listener, id)
        with context.session.begin(subtransactions=True):
            context.session.delete(listener_db_entry)

    def get_listeners(self, context, filters=None):
        listener_dbs = self._get_resources(context, models.Listener,
                                           filters=filters)
        return [data_models.Listener.from_sqlalchemy_model(listener_db)
                for listener_db in listener_dbs]

    def get_listeners_as_api_dict(self, context, filters=None):
        options = (
            subqueryload(models.Listener.sni_containers),
            subqueryload(models.Listener.loadbalancer),
            subqueryload(models.Listener.l7_policies)
        )
        listener_dbs = self._get_resources(context, models.Listener,
                                           filters=filters, options=options)
        return [listener_db.to_api_dict
                for listener_db in listener_dbs]

    def get_listener(self, context, id):
        listener_db = self._get_resource(context, models.Listener, id)
        return data_models.Listener.from_sqlalchemy_model(listener_db)

    def get_listener_as_api_dict(self, context, id):
        listener_db = self._get_resource(context, models.Listener, id)
        return listener_db.to_api_dict

    def _create_session_persistence_db(self, session_info, pool_id):
        session_info['pool_id'] = pool_id
        return models.SessionPersistenceV2(**session_info)

    def _update_pool_session_persistence(self, context, pool_id, info):
        # removing these keys as it is possible that they are passed in and
        # their existence will cause issues bc they are not acceptable as
        # dictionary values
        info.pop('pool', None)
        info.pop('pool_id', None)
        pool = self._get_resource(context, models.PoolV2, pool_id)
        with context.session.begin(subtransactions=True):
            # Update sessionPersistence table
            sess_qry = context.session.query(models.SessionPersistenceV2)
            sesspersist_db = sess_qry.filter_by(pool_id=pool_id).first()

            # Insert a None cookie_info if it is not present to overwrite an
            # existing value in the database.
            if 'cookie_name' not in info:
                info['cookie_name'] = None

            if sesspersist_db:
                sesspersist_db.update(info)
            else:
                info['pool_id'] = pool_id
                sesspersist_db = models.SessionPersistenceV2(**info)
                context.session.add(sesspersist_db)
                # Update pool table
                pool.session_persistence = sesspersist_db
            context.session.add(pool)

    def _delete_session_persistence(self, context, pool_id):
        with context.session.begin(subtransactions=True):
            sess_qry = context.session.query(models.SessionPersistenceV2)
            sess_qry.filter_by(pool_id=pool_id).delete()

    def create_pool(self, context, pool):
        with context.session.begin(subtransactions=True):
            self._load_id(context, pool)
            pool['provisioning_status'] = n_const.PENDING_CREATE
            pool['operating_status'] = lb_const.OFFLINE

            session_info = pool.pop('session_persistence', None)
            pool_db = models.PoolV2(**pool)

            if session_info:
                s_p = self._create_session_persistence_db(session_info,
                                                          pool_db.id)
                pool_db.session_persistence = s_p

            context.session.add(pool_db)
        context.session.refresh(pool_db.loadbalancer)
        return data_models.Pool.from_sqlalchemy_model(pool_db)

    def update_pool(self, context, id, pool):
        with context.session.begin(subtransactions=True):
            pool_db = self._get_resource(context, models.PoolV2, id)
            hm_id = pool.get('healthmonitor_id')
            if hm_id:
                if not self._resource_exists(context, models.HealthMonitorV2,
                                             hm_id):
                    raise loadbalancerv2.EntityNotFound(
                        name=models.HealthMonitorV2.NAME,
                        id=hm_id)
                filters = {'healthmonitor_id': [hm_id]}
                hmpools = self._get_resources(context,
                                              models.PoolV2,
                                              filters=filters)
                if hmpools:
                    raise loadbalancerv2.EntityInUse(
                        entity_using=models.PoolV2.NAME,
                        id=hmpools[0].id,
                        entity_in_use=models.HealthMonitorV2.NAME)

            # Only update or delete session persistence if it was part
            # of the API request.
            if 'session_persistence' in pool.keys():
                sp = pool.pop('session_persistence')
                if sp is None or sp == {}:
                    self._delete_session_persistence(context, id)
                else:
                    self._update_pool_session_persistence(context, id, sp)

            # sqlalchemy cries if listeners is defined.
            listeners = pool.get('listeners')
            if listeners:
                del pool['listeners']
            pool_db.update(pool)
        context.session.refresh(pool_db)
        return data_models.Pool.from_sqlalchemy_model(pool_db)

    def delete_pool(self, context, id):
        with context.session.begin(subtransactions=True):
            pool_db = self._get_resource(context, models.PoolV2, id)
            for l in pool_db.listeners:
                self.update_listener(context, l.id,
                                     {'default_pool_id': None})
            for l in pool_db.loadbalancer.listeners:
                for p in l.l7_policies:
                    if (p.action == lb_const.L7_POLICY_ACTION_REDIRECT_TO_POOL
                        and p.redirect_pool_id == id):
                        self.update_l7policy(
                            context, p.id,
                            {'redirect_pool_id': None,
                             'action': lb_const.L7_POLICY_ACTION_REJECT})
            context.session.delete(pool_db)

    def get_pools(self, context, filters=None):
        pool_dbs = self._get_resources(context, models.PoolV2, filters=filters)
        return [data_models.Pool.from_sqlalchemy_model(pool_db)
                for pool_db in pool_dbs]

    def get_pools_as_api_dict(self, context, filters=None):
        options = (
            subqueryload(models.PoolV2.members),
            subqueryload(models.PoolV2.listeners),
            subqueryload(models.PoolV2.l7_policies),
            subqueryload(models.PoolV2.loadbalancer),
            subqueryload(models.PoolV2.session_persistence)
        )
        pool_dbs = self._get_resources(context, models.PoolV2,
            filters=filters, options=options)
        return [pool_db.to_api_dict
                for pool_db in pool_dbs]

    def get_pool(self, context, id):
        pool_db = self._get_resource(context, models.PoolV2, id)
        return data_models.Pool.from_sqlalchemy_model(pool_db)

    def get_pool_as_api_dict(self, context, id):
        pool_db = self._get_resource(context, models.PoolV2, id)
        return pool_db.to_api_dict

    def create_pool_member(self, context, member, pool_id):
        try:
            with context.session.begin(subtransactions=True):
                self._load_id(context, member)
                member['pool_id'] = pool_id
                member['provisioning_status'] = n_const.PENDING_CREATE
                member['operating_status'] = lb_const.OFFLINE
                member_db = models.MemberV2(**member)
                context.session.add(member_db)
        except exception.DBDuplicateEntry:
            raise loadbalancerv2.MemberExists(address=member['address'],
                                              port=member['protocol_port'],
                                              pool=pool_id)
        context.session.refresh(member_db.pool)
        return data_models.Member.from_sqlalchemy_model(member_db)

    def create_pool_member_bulk(self, context, members, pool_id):
        member_dbs = []
        for member in members:
            member = member.get('member')
            self.check_subnet_exists(context, member['subnet_id'])
            self._load_id(context, member)
            member['pool_id'] = pool_id
            member['provisioning_status'] = n_const.PENDING_CREATE
            member['operating_status'] = lb_const.OFFLINE
            member_db = models.MemberV2(**member)
            member_dbs.append(member_db)
        try:
            with context.session.begin(subtransactions=True):
                context.session.add_all(member_dbs)
        except exception.DBDuplicateEntry:
            raise loadbalancerv2.MembersExists(pool=pool_id)
        if member_dbs:
            context.session.refresh(member_dbs[0].pool)
        members_list = []
        for member_db in member_dbs:
            mem = data_models.Member.from_sqlalchemy_model(member_db)
            members_list.append(mem)
        return members_list

    def update_pool_member(self, context, id, member):
        with context.session.begin(subtransactions=True):
            member_db = self._get_resource(context, models.MemberV2, id)
            member_db.update(member)
        context.session.refresh(member_db)
        return data_models.Member.from_sqlalchemy_model(member_db)

    def delete_pool_member(self, context, id):
        with context.session.begin(subtransactions=True):
            member_db = self._get_resource(context, models.MemberV2, id)
            context.session.delete(member_db)

    def get_pool_members(self, context, filters=None):
        filters = filters or {}
        member_dbs = self._get_resources(context, models.MemberV2,
                                         filters=filters)
        return [data_models.Member.from_sqlalchemy_model(member_db)
                for member_db in member_dbs]

    def get_pool_member_bulk_as_api_dict(self, context, ids):
        member_dbs = self._model_query(context, models.MemberV2).\
            filter(models.MemberV2.id.in_(ids)).all()
        return [member_db.to_api_dict
                for member_db in member_dbs]

    def get_pool_members_as_api_dict(self, context, filters=None):
        filters = filters or {}
        member_dbs = self._get_resources(context, models.MemberV2,
                                         filters=filters)
        return [member_db.to_api_dict
                for member_db in member_dbs]

    def get_pool_member(self, context, id):
        member_db = self._get_resource(context, models.MemberV2, id)
        return data_models.Member.from_sqlalchemy_model(member_db)

    def get_pool_member_as_api_dict(self, context, id):
        member_db = self._get_resource(context, models.MemberV2, id)
        return member_db.to_api_dict

    def delete_member(self, context, id):
        with context.session.begin(subtransactions=True):
            member_db = self._get_resource(context, models.MemberV2, id)
            context.session.delete(member_db)

    def create_healthmonitor_on_pool(self, context, pool_id, healthmonitor):
        with context.session.begin(subtransactions=True):
            hm_db = self.create_healthmonitor(context, healthmonitor)
            pool = self.get_pool(context, pool_id)
            # do not want listener, members, healthmonitor or loadbalancer
            # in dict
            pool_dict = pool.to_dict(listeners=False, members=False,
                                     healthmonitor=False, loadbalancer=False,
                                     listener=False, loadbalancer_id=False)
            pool_dict['healthmonitor_id'] = hm_db.id
            self.update_pool(context, pool_id, pool_dict)
            hm_db = self._get_resource(context, models.HealthMonitorV2,
                                       hm_db.id)
        return data_models.HealthMonitor.from_sqlalchemy_model(hm_db)

    def create_healthmonitor(self, context, healthmonitor):
        with context.session.begin(subtransactions=True):
            self._load_id(context, healthmonitor)
            healthmonitor['provisioning_status'] = n_const.PENDING_CREATE
            hm_db_entry = models.HealthMonitorV2(**healthmonitor)
            context.session.add(hm_db_entry)
        return data_models.HealthMonitor.from_sqlalchemy_model(hm_db_entry)

    def update_healthmonitor(self, context, id, healthmonitor):
        with context.session.begin(subtransactions=True):
            hm_db = self._get_resource(context, models.HealthMonitorV2, id)
            hm_db.update(healthmonitor)
        context.session.refresh(hm_db)
        return data_models.HealthMonitor.from_sqlalchemy_model(hm_db)

    def delete_healthmonitor(self, context, id):
        with context.session.begin(subtransactions=True):
            hm_db_entry = self._get_resource(context,
                                             models.HealthMonitorV2, id)
            # TODO(sbalukoff): Clear out pool.healthmonitor_ids referencing
            # old healthmonitor ID.
            context.session.delete(hm_db_entry)

    def get_healthmonitor(self, context, id):
        hm_db = self._get_resource(context, models.HealthMonitorV2, id)
        return data_models.HealthMonitor.from_sqlalchemy_model(hm_db)

    def get_healthmonitor_as_api_dict(self, context, id):
        hm_db = self._get_resource(context, models.HealthMonitorV2, id)
        return hm_db.to_api_dict

    def get_healthmonitors(self, context, filters=None):
        filters = filters or {}
        hm_dbs = self._get_resources(context, models.HealthMonitorV2,
                                     filters=filters)
        return [data_models.HealthMonitor.from_sqlalchemy_model(hm_db)
                for hm_db in hm_dbs]

    def get_healthmonitors_as_api_dict(self, context, filters=None):
        options = (
            subqueryload(models.HealthMonitorV2.pool)
        )
        filters = filters or {}
        hm_dbs = self._get_resources(context, models.HealthMonitorV2,
                                     filters=filters, options=options)
        return [hm_db.to_api_dict
                for hm_db in hm_dbs]

    def update_loadbalancer_stats(self, context, loadbalancer_id, stats_data):
        stats_data = stats_data or {}
        with context.session.begin(subtransactions=True):
            lb_db = self._get_resource(context, models.LoadBalancer,
                                       loadbalancer_id)
            lb_db.stats = self._create_loadbalancer_stats(context,
                                                          loadbalancer_id,
                                                          data=stats_data)

    def stats(self, context, loadbalancer_id):
        loadbalancer = self._get_resource(context, models.LoadBalancer,
                                          loadbalancer_id)
        return data_models.LoadBalancerStatistics.from_sqlalchemy_model(
            loadbalancer.stats)

    def create_l7policy(self, context, l7policy):
        if (l7policy.get('redirect_pool_id') and
                l7policy['redirect_pool_id'] == n_const.ATTR_NOT_SPECIFIED):
            l7policy['redirect_pool_id'] = None
        if not l7policy.get('position'):
            l7policy['position'] = 2147483647
        self._validate_l7policy_data(context, l7policy)

        with context.session.begin(subtransactions=True):
            listener_id = l7policy.get('listener_id')
            listener_db = self._get_resource(
                context, models.Listener, listener_id)

            self._load_id(context, l7policy)

            l7policy['provisioning_status'] = n_const.PENDING_CREATE

            l7policy_db = models.L7Policy(**l7policy)
            # MySQL int fields are by default 32-bit whereas handy system
            # constants like sys.maxsize are 64-bit on most platforms today.
            # Hence the reason this is 2147483647 (2^31 - 1) instead of an
            # elsewhere-defined constant.
            if l7policy['position'] == 2147483647:
                listener_db.l7_policies.append(l7policy_db)
            else:
                listener_db.l7_policies.insert(l7policy['position'] - 1,
                                               l7policy_db)

            listener_db.l7_policies.reorder()

        return data_models.L7Policy.from_sqlalchemy_model(l7policy_db)

    def update_l7policy(self, context, id, l7policy):
        with context.session.begin(subtransactions=True):

            l7policy_db = self._get_resource(context, models.L7Policy, id)

            if 'action' in l7policy:
                l7policy['listener_id'] = l7policy_db.listener_id
                self._validate_l7policy_data(context, l7policy)

            if ('position' not in l7policy or
                l7policy['position'] == 2147483647 or
                l7policy_db.position == l7policy['position']):
                l7policy_db.update(l7policy)
            else:
                listener_id = l7policy_db.listener_id
                listener_db = self._get_resource(
                    context, models.Listener, listener_id)
                l7policy_db = listener_db.l7_policies.pop(
                    l7policy_db.position - 1)

                l7policy_db.update(l7policy)
                listener_db.l7_policies.insert(l7policy['position'] - 1,
                                               l7policy_db)
                listener_db.l7_policies.reorder()

        context.session.refresh(l7policy_db)
        return data_models.L7Policy.from_sqlalchemy_model(l7policy_db)

    def delete_l7policy(self, context, id):
        with context.session.begin(subtransactions=True):
            l7policy_db = self._get_resource(context, models.L7Policy, id)
            listener_id = l7policy_db.listener_id
            listener_db = self._get_resource(
                context, models.Listener, listener_id)
            listener_db.l7_policies.remove(l7policy_db)

    def get_l7policy(self, context, id):
        l7policy_db = self._get_resource(context, models.L7Policy, id)
        return data_models.L7Policy.from_sqlalchemy_model(l7policy_db)

    def get_l7policy_as_api_dict(self, context, id):
        l7policy_db = self._get_resource(context, models.L7Policy, id)
        return l7policy_db.to_api_dict

    def get_l7policies(self, context, filters=None):
        l7policy_dbs = self._get_resources(context, models.L7Policy,
                                           filters=filters)
        return [data_models.L7Policy.from_sqlalchemy_model(l7policy_db)
                for l7policy_db in l7policy_dbs]

    def get_l7policies_as_api_dict(self, context, filters=None):
        options = (
            subqueryload(models.L7Policy.rules)
        )
        l7policy_dbs = self._get_resources(context, models.L7Policy,
                                           filters=filters, options=options)
        return [l7policy_db.to_api_dict
                for l7policy_db in l7policy_dbs]

    def create_l7policy_rule(self, context, rule, l7policy_id):
        with context.session.begin(subtransactions=True):
            if not self._resource_exists(context, models.L7Policy,
                                         l7policy_id):
                raise loadbalancerv2.EntityNotFound(
                    name=models.L7Policy.NAME, id=l7policy_id)
            self._validate_l7rule_data(context, rule)
            self._load_id(context, rule)
            rule['l7policy_id'] = l7policy_id
            rule['provisioning_status'] = n_const.PENDING_CREATE
            rule_db = models.L7Rule(**rule)
            context.session.add(rule_db)
        return data_models.L7Rule.from_sqlalchemy_model(rule_db)

    def update_l7policy_rule(self, context, id, rule, l7policy_id):
        with context.session.begin(subtransactions=True):
            if not self._resource_exists(context, models.L7Policy,
                                         l7policy_id):
                raise l7.RuleNotFoundForL7Policy(
                    l7policy_id=l7policy_id, rule_id=id)

            rule_db = self._get_resource(context, models.L7Rule, id)
            # If user did not intend to change all parameters,
            # already stored parameters will be used for validations
            if not rule.get('type'):
                rule['type'] = rule_db.type
            if not rule.get('value'):
                rule['value'] = rule_db.value
            if not rule.get('compare_type'):
                rule['compare_type'] = rule_db.compare_type

            self._validate_l7rule_data(context, rule)
            rule_db = self._get_resource(context, models.L7Rule, id)
            rule_db.update(rule)
        context.session.refresh(rule_db)
        return data_models.L7Rule.from_sqlalchemy_model(rule_db)

    def delete_l7policy_rule(self, context, id):
        with context.session.begin(subtransactions=True):
            rule_db_entry = self._get_resource(context, models.L7Rule, id)
            context.session.delete(rule_db_entry)

    def get_l7policy_rule(self, context, id, l7policy_id):
        rule_db = self._get_resource(context, models.L7Rule, id)
        if rule_db.l7policy_id != l7policy_id:
            raise l7.RuleNotFoundForL7Policy(
                l7policy_id=l7policy_id, rule_id=id)
        return data_models.L7Rule.from_sqlalchemy_model(rule_db)

    def get_l7policy_rule_as_api_dict(self, context, id, l7policy_id):
        rule_db = self._get_resource(context, models.L7Rule, id)
        if rule_db.l7policy_id != l7policy_id:
            raise l7.RuleNotFoundForL7Policy(
                l7policy_id=l7policy_id, rule_id=id)
        return rule_db.to_api_dict

    def get_l7policy_rules(self, context, l7policy_id, filters=None):
        if filters:
            filters.update(filters)
        else:
            filters = {'l7policy_id': [l7policy_id]}
        rule_dbs = self._get_resources(context, models.L7Rule,
                                       filters=filters)
        return [data_models.L7Rule.from_sqlalchemy_model(rule_db)
                for rule_db in rule_dbs]

    def get_l7policy_rules_as_api_dict(
            self, context, l7policy_id, filters=None):
        options = (
            subqueryload(models.L7Rule.policy)
        )
        if filters:
            filters.update(filters)
        else:
            filters = {'l7policy_id': [l7policy_id]}
        rule_dbs = self._get_resources(context, models.L7Rule,
                                       filters=filters, options=options)
        return [rule_db.to_api_dict
                for rule_db in rule_dbs]

    def create_user_device_map(self, context, user_device_map):
        self._load_id(context, user_device_map)
        map_db = models.UserDeviceMap(**user_device_map)
        with context.session.begin(subtransactions=True):
            context.session.add(map_db)
            context.session.flush()
        return data_models.UserDeviceMap.from_sqlalchemy_model(map_db)

    def update_user_device_map(self, context, id, user_device_map):
        with context.session.begin(subtransactions=True):
            map_db = self._get_resource(context, models.UserDeviceMap, id)
            map_db.update(user_device_map)
        context.session.refresh(map_db)
        return data_models.UserDeviceMap.from_sqlalchemy_model(map_db)

    def delete_user_device_map(self, context, id):
        with context.session.begin(subtransactions=True):
            map_db = self._get_resource(context, models.UserDeviceMap, id)
            context.session.delete(map_db)

    def get_user_device_maps_as_api_dict(self, context, filters=None):
        filters = filters or {}
        map_dbs = self._get_resources(context, models.UserDeviceMap, filters=filters)
        return [map_db.to_api_dict for map_db in map_dbs]

    def get_user_device_map_as_api_dict(self, context, id):
        map_db = self._get_resource(context, models.UserDeviceMap, id)
        return map_db.to_api_dict


def _prevent_lbaasv2_port_delete_callback(resource, event, trigger, **kwargs):
    context = kwargs['context']
    port_id = kwargs['port_id']
    port_check = kwargs['port_check']
    lbaasv2plugin = directory.get_plugin(pg_const.LOADBALANCERV2)
    if lbaasv2plugin and port_check:
        lbaasv2plugin.db.prevent_lbaasv2_port_deletion(context, port_id)
