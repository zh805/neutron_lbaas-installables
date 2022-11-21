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

"""Listener action implementation"""


from cliff import lister
from osc_lib.command import command

from neutronclient.osc.v2.lbaas import constants as const
from neutronclient.osc.v2.lbaas import utils as v2_utils

PROTOCOL_CHOICES = ['TCP', 'HTTP', 'HTTPS', 'TERMINATED_HTTPS', 'UDP']
CLIENT_AUTH_CHOICES = ['NONE', 'OPTIONAL', 'MANDATORY']


class CreateListener(command.ShowOne):
    """Create a listener"""

    def get_parser(self, prog_name):
        parser = super(CreateListener, self).get_parser(prog_name)

        parser.add_argument(
            'loadbalancer',
            metavar='<loadbalancer>',
            help="Load balancer for the listener (name or ID)."
        )
        parser.add_argument(
            '--name',
            metavar='<name>',
            help="Set the listener name."
        )
        parser.add_argument(
            '--description',
            metavar='<description>',
            help="Set the description of this listener."
        )
        parser.add_argument(
            '--project',
            metavar='<project>',
            help="Project for this listener (name or ID)."
        )
        parser.add_argument(
            '--protocol',
            metavar='{' + ','.join(PROTOCOL_CHOICES) + '}',
            choices=PROTOCOL_CHOICES,
            type=lambda s: s.upper(),  # case insensitive
            required=True,
            help="The protocol for the listener."
        )
        parser.add_argument(
            '--connection-limit',
            type=int,
            metavar='<limit>',
            help="Set the maximum number of connections permitted for this "
                 "listener."
        )
        parser.add_argument(
            '--default-pool',
            metavar='<pool>',
            help="Set the name or ID of the pool used by the listener if no "
                 "L7 policies match."
        )
        parser.add_argument(
            '--default-tls-container-ref',
            metavar='<container_ref>',
            help="The URI to the key manager service secrets container "
                 "containing the certificate and key for TERMINATED_TLS "
                 "listeners."
        )
        parser.add_argument(
            '--sni-container-refs',
            metavar='<container_ref>',
            nargs='*',
            help="A list of URIs to the key manager service secrets "
                 "containers containing the certificates and keys for "
                 "TERMINATED_TLS the listener using Server Name Indication."
        )
        parser.add_argument(
            '--protocol-port',
            metavar='<port>',
            required=True,
            help="Set the protocol port number for the listener."
        )
        admin_group = parser.add_mutually_exclusive_group()
        admin_group.add_argument(
            '--enable',
            action='store_true',
            default=True,
            help="Enable listener (default)."
        )
        admin_group.add_argument(
            '--disable',
            action='store_true',
            default=None,
            help="Disable listener."
        )
        return parser

    def take_action(self, parsed_args):
        rows = const.LISTENER_ROWS
        attrs = v2_utils.get_listener_attrs(self.app.client_manager,
                                            parsed_args)
        body = {"listener": attrs}
        data = self.app.client_manager.neutronclient.create_listener(
            body=body)
        formatters = {'loadbalancers': v2_utils.format_list,
                      'pools': v2_utils.format_list,
                      'l7policies': v2_utils.format_list,
                      'insert_headers': v2_utils.format_hash}

        return (rows,
                (v2_utils.get_dict_properties(
                    data['listener'],
                    rows,
                    formatters=formatters)))


class DeleteListener(command.Command):
    """Delete a listener"""

    def get_parser(self, prog_name):
        parser = super(DeleteListener, self).get_parser(prog_name)

        parser.add_argument(
            'listener',
            metavar="<listener>",
            help="Listener to delete (name or ID)"
        )

        return parser

    def take_action(self, parsed_args):
        attrs = v2_utils.get_listener_attrs(self.app.client_manager,
                                            parsed_args)

        listener_id = attrs.pop('listener_id')

        self.app.client_manager.neutronclient.delete_listener(
            listener_id)


class ListListener(lister.Lister):
    """List listeners"""

    def get_parser(self, prog_name):
        parser = super(ListListener, self).get_parser(prog_name)

        parser.add_argument(
            '--name',
            metavar='<name>',
            help="List listeners by listener name."
        )
        parser.add_argument(
            '--loadbalancer',
            metavar='<loadbalancer>',
            help="Filter by load balancer (name or ID).",
        )

        admin_group = parser.add_mutually_exclusive_group()
        admin_group.add_argument(
            '--enable',
            action='store_true',
            default=None,
            help="List enabled listeners."
        )
        admin_group.add_argument(
            '--disable',
            action='store_true',
            default=None,
            help="List disabled listeners."
        )

        parser.add_argument(
            '--project',
            metavar='<project>',
            help="List listeners by project ID."
        )
        return parser

    def take_action(self, parsed_args):
        columns = const.LISTENER_COLUMNS
        attrs = v2_utils.get_listener_attrs(self.app.client_manager,
                                            parsed_args)
        data = self.app.client_manager.neutronclient.list_listeners(**attrs)
        formatters = {'loadbalancers': v2_utils.format_list}
        return (
            columns,
            (v2_utils.get_dict_properties(
                s, columns, formatters=formatters)
                for s in data['listeners']))


class ShowListener(command.ShowOne):
    """Show the details of a single listener"""

    def get_parser(self, prog_name):
        parser = super(ShowListener, self).get_parser(prog_name)

        parser.add_argument(
            'listener',
            metavar='<listener>',
            help='Name or UUID of the listener'
        )

        return parser

    def take_action(self, parsed_args):
        rows = const.LISTENER_ROWS
        attrs = v2_utils.get_listener_attrs(self.app.client_manager,
                                            parsed_args)

        listener_id = attrs.pop('listener_id')

        data = self.app.client_manager.neutronclient.show_listener(
            listener_id)
        formatters = {'loadbalancers': v2_utils.format_list,
                      'pools': v2_utils.format_list,
                      'l7policies': v2_utils.format_list}

        return rows, v2_utils.get_dict_properties(
            data['listener'], rows, formatters=formatters)


class SetListener(command.Command):
    """Update a listener"""

    def get_parser(self, prog_name):
        parser = super(SetListener, self).get_parser(prog_name)

        parser.add_argument(
            'listener',
            metavar="<listener>",
            help="Listener to modify (name or ID)."
        )
        parser.add_argument(
            '--name',
            metavar='<name>',
            help="Set the listener name."
        )
        parser.add_argument(
            '--description',
            metavar='<description>',
            help="Set the description of this listener."
        )
        parser.add_argument(
            '--connection-limit',
            metavar='<limit>',
            help="The maximum number of connections permitted for this "
                 "listener. Default value is -1 which represents infinite "
                 "connections."
        )
        parser.add_argument(
            '--default-pool',
            metavar='<pool>',
            help="The ID of the pool used by the listener if no L7 policies "
                 "match."
        )
        parser.add_argument(
            '--default-tls-container-ref',
            metavar='<container-ref>',
            help="The URI to the key manager service secrets container "
                 "containing the certificate and key for TERMINATED_TLS"
                 "listeners."
        )
        parser.add_argument(
            '--sni-container-refs',
            metavar='<container-ref>',
            nargs='*',
            help="A list of URIs to the key manager service secrets "
                 "containers containing the certificates and keys for "
                 "TERMINATED_TLS the listener using Server Name Indication."
        )
        admin_group = parser.add_mutually_exclusive_group()
        admin_group.add_argument(
            '--enable',
            action='store_true',
            default=None,
            help="Enable listener."
        )
        admin_group.add_argument(
            '--disable',
            action='store_true',
            default=None,
            help="Disable listener."
        )
        return parser

    def take_action(self, parsed_args):
        attrs = v2_utils.get_listener_attrs(self.app.client_manager,
                                            parsed_args)

        listener_id = attrs.pop('listener_id')

        body = {'listener': attrs}

        self.app.client_manager.neutronclient.update_listener(
            listener_id, body=body)
