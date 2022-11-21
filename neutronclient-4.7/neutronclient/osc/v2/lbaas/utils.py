#   Copyright 2017 GoDaddy
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

from osc_lib import exceptions

from openstackclient.identity import common as identity_common


def _map_attrs(args, source_attr_map):
    res = {}
    for k, v in args.items():
        if (v is None) or (k not in source_attr_map):
            continue
        source_val = source_attr_map[k]
        # Attributes with 2 values map directly to a callable
        if len(source_val) == 2:
            res[source_val[0]] = source_val[1](v)
        # Attributes with 3 values map directly to a resource
        elif len(source_val) == 3:
            if not isinstance(v, list):
                res[source_val[0]] = get_resource_id(
                    source_val[2],
                    source_val[1],
                    v,
                )
            else:
                res[source_val[0]] = [get_resource_id(
                    source_val[2],
                    source_val[1],
                    x,
                ) for x in v]

        # Attributes with 4 values map to a resource with a parent
        elif len(source_val) == 4:
            parent = source_attr_map[source_val[2]]
            parent_id = get_resource_id(
                parent[2],
                parent[1],
                args[source_val[2]],
            )
            child = source_val
            res[child[0]] = get_resource_id(
                child[3],
                child[1],
                {child[0]: str(v), parent[0]: str(parent_id)},
            )
    return res


def get_resource_id(resource, resource_name, name):
    """Converts a resource name into a UUID for consumption for the API

    :param callable resource:
        A client_manager callable
    :param resource_name:
        The resource key name for the dictonary returned
    :param name:
        The name of the resource to convert to UUID
    :return:
        The UUID of the found resource
    """
    try:
        # Allow None as a value
        if resource_name in ('policies',):
            if name.lower() in ('none', 'null', 'void'):
                return None

        # Projects can be non-uuid so we need to account for this
        if resource_name == 'project':
            if name != 'non-uuid':
                project_id = identity_common.find_project(
                    resource,
                    name
                ).id
                return project_id
            else:
                return 'non-uuid'
        elif resource_name == 'members':
            names = [re for re in resource(name['pool_id'])['members']
                     if re.get('id') == name['member_id']
                     or re.get('name') == name['member_id']]
            name = name['member_id']
            if len(names) > 1:
                msg = ("{0} {1} found with name or ID of {2}. Please try "
                       "again with UUID".format(len(names), resource_name,
                                                name))
                raise exceptions.CommandError(msg)
            else:
                return names[0].get('id')
        elif resource_name == 'l7rules':
            names = [re for re in resource(name['l7policy_id'])['rules']
                     if re.get('id') == name['l7rule_id']]
            name = name['l7rule_id']
            return names[0].get('id')
        else:
            names = [re for re in resource()[resource_name]
                     if re.get('name') == name or re.get('id') == name]
            if len(names) > 1:
                msg = ("{0} {1} found with name or ID of {2}. Please try "
                       "again with UUID".format(len(names), resource_name,
                                                name))
                raise exceptions.CommandError(msg)
            else:
                return names[0].get('id')
    except IndexError:
        msg = "Unable to locate {0} in {1}".format(name, resource_name)
        raise exceptions.CommandError(msg)


def get_loadbalancer_attrs(client_manager, parsed_args):
    attr_map = {
        'name': ('name', str),
        'description': ('description', str),
        'protocol': ('protocol', str),
        'loadbalancer': (
            'loadbalancer_id',
            'loadbalancers',
            client_manager.neutronclient.list_lbaas_loadbalancers
        ),
        'connection_limit': ('connection_limit', str),
        'protocol_port': ('protocol_port', int),
        'project': (
            'project_id',
            'project',
            client_manager.identity
        ),
        'vip_address': ('vip_address', str),
        'vip_subnet_id': (
            'vip_subnet_id',
            'subnets',
            client_manager.neutronclient.list_subnets
        ),
        'vip_network_id': (
            'vip_network_id',
            'networks',
            client_manager.neutronclient.list_networks
        ),
        'bandwidth': ('bandwidth', int),
        'enable': ('admin_state_up', lambda x: True),
        'disable': ('admin_state_up', lambda x: False),
        'cascade': ('cascade', lambda x: True),
        'provisioning_status': ('provisioning_status', str),
        'operating_status': ('operating_status', str),
        'provider': ('provider', str),
        'flavor': (
            'flavor_id',
            'flavors',
            client_manager.neutronclient.list_flavors
        ),
    }

    _attrs = vars(parsed_args)
    attrs = _map_attrs(_attrs, attr_map)

    return attrs


def get_listener_attrs(client_manager, parsed_args):
    attr_map = {
        'name': ('name', str),
        'description': ('description', str),
        'protocol': ('protocol', str),
        'listener': (
            'listener_id',
            'listeners',
            client_manager.neutronclient.list_listeners
        ),
        'loadbalancer': (
            'loadbalancer_id',
            'loadbalancers',
            client_manager.neutronclient.list_loadbalancers
        ),
        'connection_limit': ('connection_limit', str),
        'protocol_port': ('protocol_port', int),
        'default_pool': (
            'default_pool_id',
            'pools',
            client_manager.neutronclient.list_lbaas_pools
        ),
        'project': (
            'project_id',
            'project',
            client_manager.identity
        ),
        'enable': ('admin_state_up', lambda x: True),
        'disable': ('admin_state_up', lambda x: False),
        'default_tls_container_ref': ('default_tls_container_ref', str),
        'sni_container_refs': ('sni_container_refs', list),
    }

    _attrs = vars(parsed_args)
    attrs = _map_attrs(_attrs, attr_map)

    return attrs


def get_pool_attrs(client_manager, parsed_args):
    attr_map = {
        'name': ('name', str),
        'description': ('description', str),
        'protocol': ('protocol', str),
        'pool': (
            'pool_id',
            'pools',
            client_manager.neutronclient.list_lbaas_pools
        ),
        'loadbalancer': (
            'loadbalancer_id',
            'loadbalancers',
            client_manager.neutronclient.list_loadbalancers
        ),
        'lb_algorithm': ('lb_algorithm', str),
        'listener': (
            'listener_id',
            'listeners',
            client_manager.neutronclient.list_listeners
        ),
        'project': (
            'project_id',
            'project',
            client_manager.identity
        ),
        'session_persistence': ('session_persistence', _format_kv),
        'enable': ('admin_state_up', lambda x: True),
        'disable': ('admin_state_up', lambda x: False),
    }

    _attrs = vars(parsed_args)
    attrs = _map_attrs(_attrs, attr_map)

    return attrs


def get_member_attrs(client_manager, parsed_args):
    attr_map = {
        'name': ('name', str),
        'address': ('address', str),
        'protocol_port': ('protocol_port', int),
        'project_id': (
            'project_id',
            'project',
            client_manager.identity
        ),
        'pool': (
            'pool_id',
            'pools',
            client_manager.neutronclient.list_lbaas_pools
        ),
        'member': (
            'member_id',
            'members',
            'pool',
            client_manager.neutronclient.list_lbaas_members
        ),
        'weight': ('weight', int),
        'subnet_id': (
            'subnet_id',
            'subnets',
            client_manager.neutronclient.list_subnets
        ),
        'enable': ('admin_state_up', lambda x: True),
        'disable': ('admin_state_up', lambda x: False),
    }

    _attrs = vars(parsed_args)
    attrs = _map_attrs(_attrs, attr_map)

    return attrs


def get_l7policy_attrs(client_manager, parsed_args):
    attr_map = {
        'name': ('name', str),
        'description': ('description', str),
        'redirect_url': ('redirect_url', str),
        'l7policy': (
            'l7policy_id',
            'l7policies',
            client_manager.neutronclient.list_lbaas_l7policies
        ),
        'redirect_pool': (
            'redirect_pool_id',
            'pools',
            client_manager.neutronclient.list_lbaas_pools
        ),
        'listener': (
            'listener_id',
            'listeners',
            client_manager.neutronclient.list_listeners
        ),
        'action': ('action', str),
        'project': (
            'project_id',
            'projects',
            client_manager.identity
        ),
        'position': ('position', int),
        'enable': ('admin_state_up', lambda x: True),
        'disable': ('admin_state_up', lambda x: False)
    }

    _attrs = vars(parsed_args)
    attrs = _map_attrs(_attrs, attr_map)

    return attrs


def get_l7rule_attrs(client_manager, parsed_args):
    attr_map = {
        'action': ('action', str),
        'project': (
            'project_id',
            'project',
            client_manager.identity
        ),
        'invert': ('invert', lambda x: True),
        'l7rule': (
            'l7rule_id',
            'l7rules',
            'l7policy',  # parent attr
            client_manager.neutronclient.list_lbaas_l7rules
        ),
        'l7policy': (
            'l7policy_id',
            'l7policies',
            client_manager.neutronclient.list_lbaas_l7policies
        ),
        'value': ('value', str),
        'key': ('key', str),
        'type': ('type', str),
        'compare_type': ('compare_type', str),
        'enable': ('admin_state_up', lambda x: True),
        'disable': ('admin_state_up', lambda x: False)
    }

    _attrs = vars(parsed_args)
    attrs = _map_attrs(_attrs, attr_map)

    return attrs


def get_health_monitor_attrs(client_manager, parsed_args):
    attr_map = {
        'health_monitor': (
            'health_monitor_id',
            'healthmonitors',
            client_manager.neutronclient.list_lbaas_healthmonitors
        ),
        'project': (
            'project_id',
            'project',
            client_manager.identity
        ),
        'name': ('name', str),
        'pool': (
            'pool_id',
            'pools',
            client_manager.neutronclient.list_lbaas_pools
        ),
        'delay': ('delay', int),
        'expected_codes': ('expected_codes', str),
        'max_retries': ('max_retries', int),
        'http_method': ('http_method', str),
        'type': ('type', str),
        'timeout': ('timeout', int),
        'max_retries_down': ('max_retries_down', int),
        'url_path': ('url_path', str),
        'enable': ('admin_state_up', lambda x: True),
        'disable': ('admin_state_up', lambda x: False)
    }

    _attrs = vars(parsed_args)
    attrs = _map_attrs(_attrs, attr_map)

    return attrs


def format_list(data):
    return '\n'.join(i['id'] for i in data)


def format_hash(data):
    if data:
        return '\n'.join('{}={}'.format(k, v) for k, v in data.items())
    else:
        return None


def _format_kv(data):
    formatted_kv = {}
    values = data.split(',')
    for value in values:
        k, v = value.split('=')
        formatted_kv[k] = v

    return formatted_kv


def _format_str_if_need_treat_unset(data):
    if data.lower() in ('none', 'null', 'void'):
        return None
    return str(data)


def get_dict_properties(item, fields, mixed_case_fields=None, formatters=None):
    """Return a tuple containing the item properties.

    :param item: a single dict resource
    :param fields: tuple of strings with the desired field names
    :param mixed_case_fields: tuple of field names to preserve case
    :param formatters: dictionary mapping field names to callables
       to format the values
    """
    if mixed_case_fields is None:
        mixed_case_fields = []
    if formatters is None:
        formatters = {}

    row = []

    for field in fields:
        if field in mixed_case_fields:
            field_name = field.replace(' ', '_')
        else:
            field_name = field.lower().replace(' ', '_')
        if field_name == 'project_id':
            field_name = 'tenant_id'
        data = item[field_name] if field_name in item else ''
        if field in formatters and data is not None:
            row.append(formatters[field](data))
        else:
            row.append(data)
    return tuple(row)
