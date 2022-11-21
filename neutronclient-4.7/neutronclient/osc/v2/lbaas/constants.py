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

LOAD_BALANCER_ROWS = (
    'admin_state_up',
    'description',
    'id',
    'listeners',
    'name',
    'operating_status',
    'pools',
    'project_id',
    'provider',
    'bandwidth',
    'provisioning_status',
    'vip_address',
    'vip_port_id',
    'vip_subnet_id',
)

LOAD_BALANCER_COLUMNS = (
    'id',
    'name',
    'project_id',
    'vip_address',
    'provisioning_status',
    'provider')

LOAD_BALANCER_STATS_ROWS = (
    'active_connections',
    'bytes_in',
    'bytes_out',
    'request_errors',
    'total_connections')

LISTENER_ROWS = (
    'admin_state_up',
    'connection_limit',
    'default_pool_id',
    'default_tls_container_ref',
    'description',
    'id',
    'l7policies',
    'loadbalancers',
    'name',
    'project_id',
    'protocol',
    'protocol_port',
    'sni_container_refs')

LISTENER_COLUMNS = (
    'id',
    'default_pool_id',
    'name',
    'project_id',
    'protocol',
    'protocol_port',
    'admin_state_up')

POOL_ROWS = (
    'admin_state_up',
    'description',
    'healthmonitor_id',
    'id',
    'lb_algorithm',
    'listeners',
    'loadbalancers',
    'members',
    'name',
    'project_id',
    'protocol',
    'session_persistence')

POOL_COLUMNS = (
    'id',
    'name',
    'project_id',
    'protocol',
    'lb_algorithm',
    'admin_state_up')

MEMBER_ROWS = (
    'address',
    'admin_state_up',
    'id',
    'name',
    'project_id',
    'protocol_port',
    'subnet_id',
    'weight')

MEMBER_COLUMNS = (
    'id',
    'name',
    'project_id',
    'address',
    'protocol_port',
    'weight')

L7POLICY_ROWS = (
    'listener_id',
    'description',
    'admin_state_up',
    'rules',
    'project_id',
    'redirect_pool_id',
    'redirect_url',
    'action',
    'position',
    'id',
    'name')

L7POLICY_COLUMNS = (
    'id',
    'name',
    'project_id',
    'action',
    'position',
    'admin_state_up')

L7RULE_ROWS = (
    'compare_type',
    'invert',
    'admin_state_up',
    'value',
    'key',
    'project_id',
    'type',
    'id')

L7RULE_COLUMNS = (
    'id',
    'project_id',
    'compare_type',
    'type',
    'key',
    'value',
    'invert',
    'admin_state_up')

MONITOR_ROWS = (
    'project_id',
    'name',
    'admin_state_up',
    'pools',
    'delay',
    'expected_codes',
    'max_retries',
    'max_retries_down',
    'http_method',
    'timeout',
    'url_path',
    'type',
    'id')

MONITOR_COLUMNS = (
    'id',
    'name',
    'project_id',
    'type',
    'admin_state_up')

LBAASAGENTHOSTINGLB_COLUMNS = (
    'id',
    'host',
    'admin_state_up',
    'alive')
