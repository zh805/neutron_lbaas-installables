# Copyright 2014 Blue Box Group, Inc.
# Copyright 2015 Hewlett-Packard Development Company, L.P.
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
from neutronclient.common import exceptions
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronV20


def _get_loadbalancer_id(client, lb_id_or_name):
    return neutronV20.find_resourceid_by_name_or_id(
        client, 'loadbalancer', lb_id_or_name,
        cmd_resource='lbaas_loadbalancer')


def _get_pool(client, pool_id_or_name):
    return neutronV20.find_resource_by_name_or_id(
        client, 'pool', pool_id_or_name, cmd_resource='lbaas_pool')


def _get_pool_id(client, pool_id_or_name):
    return neutronV20.find_resourceid_by_name_or_id(
        client, 'pool', pool_id_or_name, cmd_resource='lbaas_pool')


def _add_common_args(parser):
    parser.add_argument(
        '--description',
        help=_('Description of the listener.'))
    parser.add_argument(
        '--connection-limit',
        type=int,
        help=_('The maximum number of connections per second allowed for '
               'the listener. Positive integer or -1 '
               'for unlimited (default).'))
    parser.add_argument(
        '--default-pool',
        help=_('Default pool for the listener.'))


def _parse_common_args(body, parsed_args, client):
    neutronV20.update_dict(parsed_args, body,
                           ['name', 'description', 'connection_limit'])
    if parsed_args.default_pool:
        default_pool_id = _get_pool_id(
            client, parsed_args.default_pool)
        body['default_pool_id'] = default_pool_id


class ListListener(neutronV20.ListCommand):
    """LBaaS v2 List listeners that belong to a given tenant."""

    resource = 'listener'
    list_columns = ['id', 'default_pool_id', 'name', 'protocol',
                    'protocol_port', 'admin_state_up', 'status', 'transparent']
    pagination_support = True
    sorting_support = True


class ShowListener(neutronV20.ShowCommand):
    """LBaaS v2 Show information of a given listener."""

    resource = 'listener'


class CreateListener(neutronV20.CreateCommand):
    """LBaaS v2 Create a listener."""

    resource = 'listener'

    def add_known_arguments(self, parser):
        _add_common_args(parser)
        parser.add_argument(
            '--admin-state-down',
            dest='admin_state', action='store_false',
            help=_('Set admin state up to false.'))
        parser.add_argument(
            '--name',
            help=_('The name of the listener. At least one of --default-pool '
                   'or --loadbalancer must be specified.'))
        parser.add_argument(
            '--default-tls-container-ref',
            dest='default_tls_container_ref',
            help=_('Default TLS container reference'
                   ' to retrieve TLS information.'))
        parser.add_argument(
            '--sni-container-refs',
            dest='sni_container_refs',
            nargs='+',
            help=_('List of TLS container references for SNI.'))
        parser.add_argument(
            '--loadbalancer',
            metavar='LOADBALANCER',
            help=_('ID or name of the load balancer.'))
        parser.add_argument(
            '--protocol',
            required=True,
            choices=['TCP', 'FTP', 'HTTP', 'HTTPS', 'TERMINATED_HTTPS', 'UDP'],
            type=utils.convert_to_uppercase,
            help=_('Protocol for the listener.'))
        parser.add_argument(
            '--protocol-port',
            dest='protocol_port', required=True,
            metavar='PORT',
            help=_('Protocol port for the listener.'))
        parser.add_argument(
            '--transparent',
            dest='transparent',
            default=False,
            help=_('transparent for the listener.'))
        parser.add_argument(
            '--mutual-authentication-up',
            dest='mutual_authentication_up',
            default=False,
            help=_('Set mutual authentication.'))
        parser.add_argument(
            '--ca-container-id',
            dest='ca_container_id',
            help=_('Ca TLS container reference'
                   ' to retrieve TLS information.'))
        parser.add_argument(
            '--redirect-up',
            dest='redirect_up',
            default=False,
            help=_('Set redirect.'))
        parser.add_argument(
            '--redirect-protocol',
            choices=['TCP', 'HTTP', 'HTTPS', 'TERMINATED_HTTPS', 'UDP'],
            type=utils.convert_to_uppercase,
            help=_('Redirect protocol for the listener.'))
        parser.add_argument(
            '--redirect-port',
            dest='redirect_port',
            help=_('Redirect port for the listener.'))
        utils.add_boolean_argument(
            parser, '--http2',
            dest='http2',
            help=_('Whether to up http2. '
                   '(True meaning "Up")'))
        parser.add_argument(
            '--tls-protocols',
            dest='tls_protocols',
            type=utils.convert_to_uppercase,
            choices=['TLS1.0,TLS1.1,TLS1.2',
                     'TLS1.1,TLS1.2',
                     'TLS1.2',
                     'TLS1.0,TLS1.1,TLS1.2,TLS1.3',
                     'TLS1.1,TLS1.2,TLS1.3',
                     'TLS1.2,TLS1.3',
                     'DEFAULT'],
            help=_('Protocols for TLS. Choose from \"TLS1.0,TLS1.1,TLS1.2\", '
                   '\"TLS1.1,TLS1.2\", \"TLS1.2\", '
                   '\"TLS1.0,TLS1.1,TLS1.2,TLS1.3\", \"TLS1.1,TLS1.2,TLS1.3\", '
                   '\"TLS1.2,TLS1.3\", \"DEFAULT\".'))
        parser.add_argument(
            '--cipher-suites',
            dest='cipher_suites',
            type=utils.convert_to_uppercase,
            help=_('TLS cipher suite strings concatenated with colon or "default".'
                   'TLS protocols and cipher suites are as follows:'
                   '"TLS1.0,TLS1.1,TLS1.2", "TLS1.1,TLS1.2", "TLS1.2" '
                   'support "ECDHE-RSA-AES128-CBC-SHA:ECDHE-RSA-AES256-CBC-SHA:'
                   'CAMELLIA128-SHA:CAMELLIA256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:'
                   'DHE-RSA-CAMELLIA128-SHA:DHE-RSA-CAMELLIA256-SHA:ECDHE-ECDSA-AES128-SHA:'
                   'ECDHE-ECDSA-AES256-SHA:AES128-SHA:AES256-SHA:ECDH-RSA-AES128-SHA:'
                   'ECDH-RSA-AES256-SHA:DES-CBC3-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:'
                   'ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:'
                   'DHE-RSA-AES128-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:'
                   'ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:'
                   'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:'
                   'AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:'
                   'ECDH-ECDSA-AES128-GCM-SHA256:ECDH-ECDSA-AES256-GCM-SHA384". '
                   '"TLS1.3" supports "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384:'
                   'TLS13-CHACHA20-POLY1305-SHA256". '
                   'If TLS protocol is "DEFAULT", the cipher suites must be "DEFAULT". '
                   'If not specify TLS protocol and cipher suites, please do not set the parameters '
                   'tls_protocols and cipher_suites.'))


    def args2body(self, parsed_args):
        if not parsed_args.loadbalancer and not parsed_args.default_pool:
            message = _('Either --default-pool or --loadbalancer must be '
                        'specified.')
            raise exceptions.CommandError(message)
        body = {
            'protocol': parsed_args.protocol,
            'protocol_port': parsed_args.protocol_port,
            'admin_state_up': parsed_args.admin_state,
            'transparent': parsed_args.transparent,
            'mutual_authentication_up': parsed_args.mutual_authentication_up,
            'redirect_up': parsed_args.redirect_up
        }
        if parsed_args.loadbalancer:
            loadbalancer_id = _get_loadbalancer_id(
                self.get_client(), parsed_args.loadbalancer)
            body['loadbalancer_id'] = loadbalancer_id

        neutronV20.update_dict(parsed_args, body,
                               ['default_tls_container_ref',
                                'sni_container_refs', 'tenant_id',
                                'ca_container_id', 'redirect_protocol',
                                'redirect_port', 'http2',
                                'tls_protocols', 'cipher_suites'])
        _parse_common_args(body, parsed_args, self.get_client())
        return {self.resource: body}


class UpdateListener(neutronV20.UpdateCommand):
    """LBaaS v2 Update a given listener."""

    resource = 'listener'

    def add_known_arguments(self, parser):
        _add_common_args(parser)
        parser.add_argument(
            '--name',
            help=_('Name of the listener.'))
        utils.add_boolean_argument(
            parser, '--admin-state-up', dest='admin_state_up',
            help=_('Specify the administrative state of the listener. '
                   '(True meaning "Up")'))
        parser.add_argument(
            '--default-tls-container-ref',
            dest='default_tls_container_ref',
            help=_('Default TLS container reference'
                   ' to retrieve TLS information.'))
        parser.add_argument(
            '--sni-container-refs',
            dest='sni_container_refs',
            nargs='+',
            help=_('List of TLS container references for SNI.'))
        parser.add_argument(
            '--transparent',
            dest='transparent',
            help=_('transparent for the listener.'))
        parser.add_argument(
            '--mutual-authentication-up',
            dest='mutual_authentication_up',
            help=_('Set mutual authentication.'))
        parser.add_argument(
            '--ca-container-id',
            dest='ca_container_id',
            help=_('Ca TLS container reference'
                   ' to retrieve TLS information.'))
        parser.add_argument(
            '--redirect-up',
            dest='redirect_up',
            help=_('Set redirect.'))
        parser.add_argument(
            '--redirect-protocol',
            choices=['TCP', 'HTTP', 'HTTPS', 'TERMINATED_HTTPS', 'UDP'],
            type=utils.convert_to_uppercase,
            help=_('Redirect protocol for the listener.'))
        parser.add_argument(
            '--redirect-port',
            dest='redirect_port',
            metavar='PORT',
            help=_('Redirect port for the listener.'))
        utils.add_boolean_argument(
            parser, '--http2', dest='http2',
            help=_('Whether to up http2. '
                   '(True meaning "Up")'))
        parser.add_argument(
            '--tls-protocols',
            dest='tls_protocols',
            type=utils.convert_to_uppercase,
            choices=['TLS1.0,TLS1.1,TLS1.2',
                     'TLS1.1,TLS1.2',
                     'TLS1.2',
                     'TLS1.0,TLS1.1,TLS1.2,TLS1.3',
                     'TLS1.1,TLS1.2,TLS1.3',
                     'TLS1.2,TLS1.3',
                     'DEFAULT'],
            help=_('Protocols for TLS. Choose from \"TLS1.0,TLS1.1,TLS1.2\", '
                   '\"TLS1.1,TLS1.2\", \"TLS1.2\", '
                   '\"TLS1.0,TLS1.1,TLS1.2,TLS1.3\", \"TLS1.1,TLS1.2,TLS1.3\", '
                   '\"TLS1.2,TLS1.3\", \"DEFAULT\".'))
        parser.add_argument(
            '--cipher-suites',
            dest='cipher_suites',
            type=utils.convert_to_uppercase,
            help=_('TLS cipher suite strings concatenated with colon or "default".'
                   'TLS protocols and cipher suites are as follows:'
                   '"TLS1.0,TLS1.1,TLS1.2", "TLS1.1,TLS1.2", "TLS1.2" '
                   'support "ECDHE-RSA-AES128-CBC-SHA:ECDHE-RSA-AES256-CBC-SHA:'
                   'CAMELLIA128-SHA:CAMELLIA256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:'
                   'DHE-RSA-CAMELLIA128-SHA:DHE-RSA-CAMELLIA256-SHA:ECDHE-ECDSA-AES128-SHA:'
                   'ECDHE-ECDSA-AES256-SHA:AES128-SHA:AES256-SHA:ECDH-RSA-AES128-SHA:'
                   'ECDH-RSA-AES256-SHA:DES-CBC3-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:'
                   'ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:'
                   'DHE-RSA-AES128-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:'
                   'ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:'
                   'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:'
                   'AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:'
                   'ECDH-ECDSA-AES128-GCM-SHA256:ECDH-ECDSA-AES256-GCM-SHA384". '
                   '"TLS1.3" supports "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384:'
                   'TLS13-CHACHA20-POLY1305-SHA256". '
                   'If TLS protocol is "DEFAULT", the cipher suites must be "DEFAULT". '
                   'If not specify TLS protocol and cipher suites, please do not set the parameters '
                   'tls_protocols and cipher_suites.'))


    def args2body(self, parsed_args):
        body = {}
        neutronV20.update_dict(parsed_args, body,
                               ['admin_state_up', 'transparent',
                                'default_tls_container_ref',
                                'mutual_authentication_up', 'ca_container_id',
                                'redirect_up', 'redirect_protocol',
                                'redirect_port', 'sni_container_refs',
                                'http2', 'tls_protocols', 'cipher_suites'])
        _parse_common_args(body, parsed_args, self.get_client())
        return {self.resource: body}


class DeleteListener(neutronV20.DeleteCommand):
    """LBaaS v2 Delete a given listener."""

    resource = 'listener'
