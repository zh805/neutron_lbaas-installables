# Copyright 2013 Mirantis, Inc.
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

#FIXME(brandon-logan): change these to LB_ALGORITHM
LB_METHOD_ROUND_ROBIN = 'ROUND_ROBIN'
LB_METHOD_LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
LB_METHOD_SOURCE_IP = 'SOURCE_IP'
SUPPORTED_LB_ALGORITHMS = (LB_METHOD_LEAST_CONNECTIONS, LB_METHOD_ROUND_ROBIN,
                           LB_METHOD_SOURCE_IP)

LB_METHOD_ROUND_ROBIN_LOWER = 'rr'
LB_METHOD_LEAST_CONNECTIONS_LOWER = 'lc'
LB_METHOD_SOURCE_IP_LOWER = 'sh'

TLS_SERVER_CRT = 'server.crt'
TLS_SERVER_KEY = 'server.key'
CA_CRT = 'client.crt'

TLS_PRO_UP_10 = "tls1.0,tls1.1,tls1.2"
TLS_PRO_UP_11 = "tls1.1,tls1.2"
TLS_PRO_UP_12 = "tls1.2"
TLS_PRO_13 = "tls1.3"

TLS_PRO_UP_10_WITH_13 = "tls1.0,tls1.1,tls1.2,tls1.3"
TLS_PRO_UP_11_WITH_13 = "tls1.1,tls1.2,tls1.3"
TLS_PRO_UP_12_WITH_13 = "tls1.2,tls1.3"

TLS_PROTOCOLS = ['tls1.0', 'tls1.1', 'tls1.2', 'tls1.3', 'default']
TLS_PRO_LIST = [TLS_PRO_UP_10, TLS_PRO_UP_11, TLS_PRO_UP_12,
                TLS_PRO_UP_10_WITH_13, TLS_PRO_UP_11_WITH_13,
                TLS_PRO_UP_12_WITH_13, 'default']

TLS_POLICY = {TLS_PRO_UP_10: ['policy1'],
              TLS_PRO_UP_11: ['policy2'],
              TLS_PRO_UP_12: ['policy3', 'policy4'],
              TLS_PRO_UP_12_WITH_13: ['policy5']}

TLS_CIPHERS_USER_DEFINED = ['ECDHE-RSA-AES128-CBC-SHA', 'ECDHE-RSA-AES256-CBC-SHA',
                            'CAMELLIA128-SHA', 'CAMELLIA256-SHA',
                            'DHE-RSA-AES128-SHA', 'DHE-RSA-AES256-SHA',
                            'DHE-RSA-CAMELLIA128-SHA', 'DHE-RSA-CAMELLIA256-SHA',
                            'ECDHE-ECDSA-AES128-SHA', 'ECDHE-ECDSA-AES256-SHA',
                            'AES128-SHA', 'AES256-SHA',
                            'ECDH-RSA-AES128-SHA', 'ECDH-RSA-AES256-SHA',
                            'DES-CBC3-SHA', 'ECDHE-ECDSA-AES128-GCM-SHA256',
                            'ECDHE-ECDSA-AES256-GCM-SHA384', 'DHE-RSA-AES128-GCM-SHA256',
                            'DHE-RSA-AES128-SHA256', 'DHE-RSA-AES256-GCM-SHA384',
                            'DHE-RSA-AES256-SHA256', 'ECDHE-ECDSA-AES128-SHA256',
                            'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256',
                            'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-SHA256',
                            'ECDHE-RSA-AES256-SHA384', 'AES128-GCM-SHA256',
                            'AES256-GCM-SHA384', 'AES128-SHA256',
                            'AES256-SHA256', 'ECDH-ECDSA-AES128-GCM-SHA256',
                            'ECDH-ECDSA-AES256-GCM-SHA384']
TLS_CIPHERS_USER_DEFINED_13 = ['TLS13-AES128-GCM-SHA256', 'TLS13-AES256-GCM-SHA384',
                               'TLS13-CHACHA20-POLY1305-SHA256']

PROVIDER_ESLB = 'eslb'
FLAVOR_ESLB = 10
HOST_VPORT_PREFIX = 'hvport'
DEVICE_OWNER_ESLB_VIP = 'neutron:eslb'
DEVICE_OWNER_ESLB = 'neutron:cmcc'
VENDER_DEFAULT = 'default'
VENDER_NOKIA = 'nokia'

ADD = 'add'
UPDATE = 'update'
DELETE = 'delete'

MEMBER_STATUS_UP = 'up'
MEMBER_STATUS_DOWN = 'down'

PROTOCOL_UDP = 'UDP'
PROTOCOL_TCP = 'TCP'
PROTOCOL_UDP = 'UDP'
PROTOCOL_FTP = 'FTP'
PROTOCOL_HTTP = 'HTTP'
PROTOCOL_HTTPS = 'HTTPS'
PROTOCOL_TERMINATED_HTTPS = 'TERMINATED_HTTPS'
POOL_SUPPORTED_PROTOCOLS = (PROTOCOL_TCP, PROTOCOL_UDP,
                            PROTOCOL_HTTPS, PROTOCOL_HTTP)
LISTENER_SUPPORTED_PROTOCOLS = (PROTOCOL_TCP, PROTOCOL_UDP,
                                PROTOCOL_FTP, PROTOCOL_HTTPS,
                                PROTOCOL_HTTP, PROTOCOL_TERMINATED_HTTPS)

LISTENER_POOL_COMPATIBLE_PROTOCOLS = (
    (PROTOCOL_TCP, PROTOCOL_TCP),
    (PROTOCOL_UDP, PROTOCOL_UDP),
    (PROTOCOL_TCP, PROTOCOL_FTP),
    (PROTOCOL_HTTP, PROTOCOL_HTTP),
    (PROTOCOL_HTTPS, PROTOCOL_HTTPS),
    (PROTOCOL_HTTP, PROTOCOL_TERMINATED_HTTPS))


HEALTH_MONITOR_PING = 'PING'
HEALTH_MONITOR_TCP = 'TCP'
HEALTH_MONITOR_UDP = 'UDP'
HEALTH_MONITOR_HTTP = 'HTTP'
HEALTH_MONITOR_HTTPS = 'HTTPS'

SUPPORTED_HEALTH_MONITOR_TYPES = (HEALTH_MONITOR_HTTP, HEALTH_MONITOR_HTTPS,
                                  HEALTH_MONITOR_PING, HEALTH_MONITOR_TCP,
                                  HEALTH_MONITOR_UDP)

HTTP_METHOD_GET = 'GET'
HTTP_METHOD_HEAD = 'HEAD'
HTTP_METHOD_POST = 'POST'
HTTP_METHOD_PUT = 'PUT'
HTTP_METHOD_DELETE = 'DELETE'
HTTP_METHOD_TRACE = 'TRACE'
HTTP_METHOD_OPTIONS = 'OPTIONS'
HTTP_METHOD_CONNECT = 'CONNECT'
HTTP_METHOD_PATCH = 'PATCH'


SUPPORTED_HTTP_METHODS = (HTTP_METHOD_GET, HTTP_METHOD_HEAD, HTTP_METHOD_POST,
                          HTTP_METHOD_PUT, HTTP_METHOD_DELETE,
                          HTTP_METHOD_TRACE, HTTP_METHOD_OPTIONS,
                          HTTP_METHOD_CONNECT, HTTP_METHOD_PATCH)

# URL path regex according to RFC 3986
# Format: path = "/" *( "/" segment )
#         segment       = *pchar
#         pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
#         unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
#         pct-encoded   = "%" HEXDIG HEXDIG
#         sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
#                         / "*" / "+" / "," / ";" / "="
SUPPORTED_URL_PATH = (
    "^(/([a-zA-Z0-9-._~!$&\'()*+,;=:@]|(%[a-fA-F0-9]{2}))*)+$")

SESSION_PERSISTENCE_SOURCE_IP = 'SOURCE_IP'
SESSION_PERSISTENCE_HTTP_COOKIE = 'HTTP_COOKIE'
SESSION_PERSISTENCE_APP_COOKIE = 'APP_COOKIE'
SUPPORTED_SP_TYPES = (SESSION_PERSISTENCE_SOURCE_IP,
                      SESSION_PERSISTENCE_HTTP_COOKIE,
                      SESSION_PERSISTENCE_APP_COOKIE)

L7_RULE_TYPE_HOST_NAME = 'HOST_NAME'
L7_RULE_TYPE_PATH = 'PATH'
L7_RULE_TYPE_FILE_TYPE = 'FILE_TYPE'
L7_RULE_TYPE_HEADER = 'HEADER'
L7_RULE_TYPE_COOKIE = 'COOKIE'
SUPPORTED_L7_RULE_TYPES = (L7_RULE_TYPE_HOST_NAME,
                           L7_RULE_TYPE_PATH,
                           L7_RULE_TYPE_FILE_TYPE,
                           L7_RULE_TYPE_HEADER,
                           L7_RULE_TYPE_COOKIE)

L7_RULE_COMPARE_TYPE_REGEX = 'REGEX'
L7_RULE_COMPARE_TYPE_STARTS_WITH = 'STARTS_WITH'
L7_RULE_COMPARE_TYPE_ENDS_WITH = 'ENDS_WITH'
L7_RULE_COMPARE_TYPE_CONTAINS = 'CONTAINS'
L7_RULE_COMPARE_TYPE_EQUAL_TO = 'EQUAL_TO'
SUPPORTED_L7_RULE_COMPARE_TYPES = (L7_RULE_COMPARE_TYPE_REGEX,
                                   L7_RULE_COMPARE_TYPE_STARTS_WITH,
                                   L7_RULE_COMPARE_TYPE_ENDS_WITH,
                                   L7_RULE_COMPARE_TYPE_CONTAINS,
                                   L7_RULE_COMPARE_TYPE_EQUAL_TO)

L7_POLICY_ACTION_REJECT = 'REJECT'
L7_POLICY_ACTION_REDIRECT_TO_POOL = 'REDIRECT_TO_POOL'
L7_POLICY_ACTION_REDIRECT_TO_URL = 'REDIRECT_TO_URL'
SUPPORTED_L7_POLICY_ACTIONS = (L7_POLICY_ACTION_REJECT,
                               L7_POLICY_ACTION_REDIRECT_TO_POOL,
                               L7_POLICY_ACTION_REDIRECT_TO_URL)

URL_REGEX = "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|\
             (?:%[0-9a-fA-F][0-9a-fA-F]))+"

# See RFCs 2616, 2965, 6265, 7230: Should match characters valid in a
# http header or cookie name.
HTTP_HEADER_COOKIE_NAME_REGEX = r'\A[a-zA-Z0-9!#$%&\'*+-.^_`|~]+\Z'

# See RFCs 2616, 2965, 6265: Should match characters valid in a cookie value.
HTTP_COOKIE_VALUE_REGEX = r'\A[a-zA-Z0-9!#$%&\'()*+-./:<=>?@[\]^_`{|}~]+\Z'

# See RFC 7230: Should match characters valid in a header value.
HTTP_HEADER_VALUE_REGEX = (r'\A[a-zA-Z0-9'
                           r'!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~\\]+\Z')

# Also in RFC 7230: Should match characters valid in a header value
# when quoted with double quotes.
HTTP_QUOTED_HEADER_VALUE_REGEX = (r'\A"[a-zA-Z0-9 \t'
                                  r'!"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~\\]*"\Z')

STATS_ACTIVE_CONNECTIONS = 'active_connections'
STATS_MAX_CONNECTIONS = 'max_connections'
STATS_TOTAL_CONNECTIONS = 'total_connections'
STATS_CURRENT_SESSIONS = 'current_sessions'
STATS_MAX_SESSIONS = 'max_sessions'
STATS_TOTAL_SESSIONS = 'total_sessions'
STATS_IN_BYTES = 'bytes_in'
STATS_OUT_BYTES = 'bytes_out'
STATS_CONNECTION_ERRORS = 'connection_errors'
STATS_RESPONSE_ERRORS = 'response_errors'
STATS_STATUS = 'status'
STATS_HEALTH = 'health'
STATS_FAILED_CHECKS = 'failed_checks'

# Constants to extend status strings in neutron.plugins.common.constants
ONLINE = 'ONLINE'
OFFLINE = 'OFFLINE'
DEGRADED = 'DEGRADED'
DISABLED = 'DISABLED'
NO_MONITOR = 'NO_MONITOR'
OPERATING_STATUSES = (ONLINE, OFFLINE, DEGRADED, DISABLED, NO_MONITOR)

NO_CHECK = 'no check'

# LBaaS V2 Agent Constants
LBAAS_AGENT_SCHEDULER_V2_EXT_ALIAS = 'lbaas_agent_schedulerv2'
AGENT_TYPE_LOADBALANCERV2 = 'Loadbalancerv2 agent'
LOADBALANCER_PLUGINV2 = 'n-lbaasv2-plugin'
LOADBALANCER_AGENTV2 = 'n-lbaasv2_agent'

LOADBALANCER = "LOADBALANCER"
LOADBALANCERV2 = "LOADBALANCERV2"

# Used to check number of connections per second allowed
# for the LBaaS V1 vip and LBaaS V2 listeners. -1 indicates
# no limit, the value cannot be less than -1.
MIN_CONNECT_VALUE = -1

# LBaas V2 Table entities
LISTENER_EVENT = 'listener'
LISTENER_STATS_EVENT = 'listener_stats'
LOADBALANCER_EVENT = 'loadbalancer'
LOADBALANCER_STATS_EVENT = 'loadbalancer_stats'
MEMBER_EVENT = 'member'
OPERATING_STATUS = 'operating_status'
POOL_EVENT = 'pool'

# Used for ACL Control
ACL_IP_VERSIONS = ('IPv4', 'IPv6')
ACL_BLACKLIST = 'blacklist'
ACL_WHITELIST = 'whitelist'
ACL_CONTROL_TYPES = (ACL_BLACKLIST, ACL_WHITELIST)
