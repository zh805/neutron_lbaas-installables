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

"""Pool action implementation"""

from cliff import lister
from osc_lib.command import command

from neutronclient.osc.v2.lbaas import constants as const
from neutronclient.osc.v2.lbaas import utils as v2_utils

PROTOCOL_CHOICES = ['TCP', 'HTTP', 'HTTPS', 'TERMINATED_HTTPS', 'PROXY',
                    'UDP']
ALGORITHM_CHOICES = ['SOURCE_IP', 'ROUND_ROBIN', 'LEAST_CONNECTIONS']


class CreatePool(command.ShowOne):
    """Create a pool"""

    def get_parser(self, prog_name):
        parser = super(CreatePool, self).get_parser(prog_name)

        parser.add_argument(
            '--name',
            metavar='<name>',
            help="Set pool name."
        )
        parser.add_argument(
            '--description',
            metavar='<description>',
            help="Set pool description."
        )
        parser.add_argument(
            '--project',
            metavar='<project>',
            help="Project for the pool (name or ID)."
        )
        parser.add_argument(
            '--protocol',
            metavar='{' + ','.join(PROTOCOL_CHOICES) + '}',
            required=True,
            choices=PROTOCOL_CHOICES,
            type=lambda s: s.upper(),  # case insensitive
            help="Set the pool protocol."
        )
        parent_group = parser.add_mutually_exclusive_group(required=True)
        parent_group.add_argument(
            '--listener',
            metavar='<listener>',
            help="Listener to add the pool to (name or ID)."
        )
        parser.add_argument(
            '--session-persistence',
            metavar='<session persistence>',
            help="Set the session persistence for the listener (key=value)."
        )
        parser.add_argument(
            '--lb-algorithm',
            metavar='{' + ','.join(ALGORITHM_CHOICES) + '}',
            required=True,
            choices=ALGORITHM_CHOICES,
            type=lambda s: s.upper(),  # case insensitive
            help="Load balancing algorithm to use."
        )
        admin_group = parser.add_mutually_exclusive_group()
        admin_group.add_argument(
            '--enable',
            action='store_true',
            default=True,
            help="Enable pool (default)."
        )
        admin_group.add_argument(
            '--disable',
            action='store_true',
            default=None,
            help="Disable pool."
        )

        return parser

    def take_action(self, parsed_args):
        rows = const.POOL_ROWS
        attrs = v2_utils.get_pool_attrs(self.app.client_manager, parsed_args)

        body = {"pool": attrs}
        data = self.app.client_manager.neutronclient.create_lbaas_pool(
            body=body)
        formatters = {'loadbalancers': v2_utils.format_list,
                      'members': v2_utils.format_list,
                      'listeners': v2_utils.format_list,
                      'session_persistence': v2_utils.format_hash}

        return (rows, (v2_utils.get_dict_properties(
            data['pool'], rows, formatters=formatters)))


class DeletePool(command.Command):
    """Delete a pool"""

    def get_parser(self, prog_name):
        parser = super(DeletePool, self).get_parser(prog_name)

        parser.add_argument(
            'pool',
            metavar="<pool>",
            help="Pool to delete (name or ID)."
        )

        return parser

    def take_action(self, parsed_args):
        attrs = v2_utils.get_pool_attrs(self.app.client_manager, parsed_args)
        pool_id = attrs.pop('pool_id')
        self.app.client_manager.neutronclient.delete_lbaas_pool(
            pool_id)


class ListPool(lister.Lister):
    """List pools"""

    def get_parser(self, prog_name):
        parser = super(ListPool, self).get_parser(prog_name)

        parser.add_argument(
            '--loadbalancer',
            metavar='<loadbalancer>',
            help="Filter by load balancer (name or ID).",
        )

        return parser

    def take_action(self, parsed_args):
        columns = const.POOL_COLUMNS
        attrs = v2_utils.get_pool_attrs(self.app.client_manager, parsed_args)
        data = self.app.client_manager.neutronclient.list_lbaas_pools(**attrs)
        formatters = {'loadbalancers': v2_utils.format_list,
                      'members': v2_utils.format_list,
                      'listeners': v2_utils.format_list}

        return (columns,
                (v2_utils.get_dict_properties(
                    s, columns, formatters=formatters) for s in data['pools']))


class ShowPool(command.ShowOne):
    """Show the details of a single pool"""

    def get_parser(self, prog_name):
        parser = super(ShowPool, self).get_parser(prog_name)

        parser.add_argument(
            'pool',
            metavar='<pool>',
            help='Name or UUID of the pool.'
        )

        return parser

    def take_action(self, parsed_args):
        rows = const.POOL_ROWS

        attrs = v2_utils.get_pool_attrs(self.app.client_manager, parsed_args)
        pool_id = attrs.pop('pool_id')

        data = self.app.client_manager.neutronclient.show_lbaas_pool(
            pool_id)
        formatters = {'loadbalancers': v2_utils.format_list,
                      'members': v2_utils.format_list,
                      'listeners': v2_utils.format_list,
                      'session_persistence': v2_utils.format_hash}

        return (rows, (v2_utils.get_dict_properties(
            data['pool'], rows, formatters=formatters)))


class SetPool(command.Command):
    """Update a pool"""

    def get_parser(self, prog_name):
        parser = super(SetPool, self).get_parser(prog_name)

        parser.add_argument(
            'pool',
            metavar="<pool>",
            help="Pool to update (name or ID)."
        )
        parser.add_argument(
            '--name',
            metavar='<name>',
            help="Set the name of the pool."
        )
        parser.add_argument(
            '--description',
            metavar='<description>',
            help="Set the description of the pool."
        )
        parser.add_argument(
            '--session-persistence',
            metavar='<session_persistence>',
            help="Set the session persistence for the listener (key=value)."
        )
        parser.add_argument(
            '--no-session-persistence',
            action='store_true',
            help="Clear session persistence for the pool."
        )
        parser.add_argument(
            '--lb-algorithm',
            metavar='{' + ','.join(ALGORITHM_CHOICES) + '}',
            choices=ALGORITHM_CHOICES,
            type=lambda s: s.upper(),  # case insensitive
            help="Set the load balancing algorithm to use."
        )
        admin_group = parser.add_mutually_exclusive_group()
        admin_group.add_argument(
            '--enable',
            action='store_true',
            default=None,
            help="Enable pool."
        )
        admin_group.add_argument(
            '--disable',
            action='store_true',
            default=None,
            help="Disable pool."
        )

        return parser

    def take_action(self, parsed_args):
        attrs = v2_utils.get_pool_attrs(self.app.client_manager, parsed_args)
        pool_id = attrs.pop('pool_id')
        if parsed_args.no_session_persistence:
            attrs['session_persistence'] = None

        body = {'pool': attrs}

        self.app.client_manager.neutronclient.update_lbaas_pool(
            pool_id, body=body)
