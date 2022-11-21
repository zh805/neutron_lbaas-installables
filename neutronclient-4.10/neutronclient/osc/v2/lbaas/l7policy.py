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

"""L7policy action implementation"""

from cliff import lister
from osc_lib.command import command

from neutronclient.osc.v2.lbaas import constants as const
from neutronclient.osc.v2.lbaas import utils as v2_utils
from neutronclient.osc.v2.lbaas import validate

ACTION_CHOICES = ['REDIRECT_TO_URL', 'REDIRECT_TO_POOL',
                  'REJECT']


class CreateL7Policy(command.ShowOne):
    """Create a l7policy"""

    def get_parser(self, prog_name):
        parser = super(CreateL7Policy, self).get_parser(prog_name)

        parser.add_argument(
            'listener',
            metavar='<listener>',
            help="Listener to add l7policy to (name or ID)."
        )
        parser.add_argument(
            '--name',
            metavar='<name>',
            help="Set the l7policy name."
        )
        parser.add_argument(
            '--description',
            metavar='<description>',
            help="Set l7policy description."
        )
        parser.add_argument(
            '--project',
            metavar='<project>',
            help="Project for the l7policy (name or ID)."
        )

        parser.add_argument(
            '--action',
            metavar='{' + ','.join(ACTION_CHOICES) + '}',
            required=True,
            choices=ACTION_CHOICES,
            type=lambda s: s.upper(),  # case insensitive
            help="Set the action of the policy."
        )

        redirect_group = parser.add_mutually_exclusive_group()
        redirect_group.add_argument(
            '--redirect-pool',
            metavar='<pool>',
            help="Set the pool to redirect requests to (name or ID)."
        )
        redirect_group.add_argument(
            '--redirect-url',
            metavar='<url>',
            help="Set the URL to redirect requests to."
        )
        parser.add_argument(
            '--position',
            metavar='<position>',
            type=int,
            help="Sequence number of this L7 Policy."
        )
        admin_group = parser.add_mutually_exclusive_group()
        admin_group.add_argument(
            '--enable',
            action='store_true',
            default=True,
            help="Enable l7policy (default)."
        )
        admin_group.add_argument(
            '--disable',
            action='store_true',
            default=None,
            help="Disable l7policy."
        )

        return parser

    def take_action(self, parsed_args):
        rows = const.L7POLICY_ROWS
        attrs = v2_utils.get_l7policy_attrs(self.app.client_manager,
                                            parsed_args)
        validate.check_l7policy_attrs(attrs)
        body = {"l7policy": attrs}

        data = self.app.client_manager.neutronclient.create_lbaas_l7policy(
            body=body)

        formatters = {'rules': v2_utils.format_list}

        return (rows, (v2_utils.get_dict_properties(
            data['l7policy'], rows, formatters=formatters)))


class DeleteL7Policy(command.Command):
    """Delete a l7policy"""

    def get_parser(self, prog_name):
        parser = super(DeleteL7Policy, self).get_parser(prog_name)

        parser.add_argument(
            'l7policy',
            metavar="<policy>",
            help="l7policy to delete (name or ID)."
        )

        return parser

    def take_action(self, parsed_args):
        attrs = v2_utils.get_l7policy_attrs(self.app.client_manager,
                                            parsed_args)

        l7policy_id = attrs.pop('l7policy_id')

        self.app.client_manager.neutronclient.delete_lbaas_l7policy(
            l7policy_id)


class ListL7Policy(lister.Lister):
    """List l7policies"""

    def get_parser(self, prog_name):
        parser = super(ListL7Policy, self).get_parser(prog_name)

        return parser

    def take_action(self, parsed_args):
        columns = const.L7POLICY_COLUMNS

        data = self.app.client_manager.neutronclient.list_lbaas_l7policies()
        formatters = {'rules': v2_utils.format_list}

        return (columns,
                (v2_utils.get_dict_properties(
                    s, columns,
                    formatters=formatters) for s in data['l7policies']))


class ShowL7Policy(command.ShowOne):
    """Show the details of a single l7policy"""

    def get_parser(self, prog_name):
        parser = super(ShowL7Policy, self).get_parser(prog_name)

        parser.add_argument(
            'l7policy',
            metavar='<policy>',
            help='Name or UUID of the l7policy.'
        )

        return parser

    def take_action(self, parsed_args):
        rows = const.L7POLICY_ROWS
        attrs = v2_utils.get_l7policy_attrs(self.app.client_manager,
                                            parsed_args)

        l7policy_id = attrs.pop('l7policy_id')

        data = self.app.client_manager.neutronclient.show_lbaas_l7policy(
            l7policy_id)

        formatters = {'rules': v2_utils.format_list}

        return (rows, (v2_utils.get_dict_properties(
            data['l7policy'], rows, formatters=formatters)))


class SetL7Policy(command.Command):
    """Update a l7policy"""

    def get_parser(self, prog_name):
        parser = super(SetL7Policy, self).get_parser(prog_name)

        parser.add_argument(
            'l7policy',
            metavar='<policy>',
            help="L7policy to update (name or ID)."
        )
        parser.add_argument(
            '--name',
            metavar='<name>',
            help="Set l7policy name."
        )
        parser.add_argument(
            '--description',
            metavar='<description>',
            help="Set l7policy description."
        )
        parser.add_argument(
            '--action',
            metavar='{' + ','.join(ACTION_CHOICES) + '}',
            choices=ACTION_CHOICES,
            type=lambda s: s.upper(),  # case insensitive
            help="Set the action of the policy."
        )

        redirect_group = parser.add_mutually_exclusive_group()
        redirect_group.add_argument(
            '--redirect-pool',
            metavar='<pool>',
            help="Set the pool to redirect requests to (name or ID)."
        )
        redirect_group.add_argument(
            '--redirect-url',
            metavar='<url>',
            help="Set the URL to redirect requests to."
        )
        parser.add_argument(
            '--position',
            metavar='<position>',
            type=int,
            help="Set sequence number of this L7 Policy."
        )
        admin_group = parser.add_mutually_exclusive_group()
        admin_group.add_argument(
            '--enable',
            action='store_true',
            default=None,
            help="Enable l7policy."
        )
        admin_group.add_argument(
            '--disable',
            action='store_true',
            default=None,
            help="Disable l7policy."
        )

        return parser

    def take_action(self, parsed_args):
        attrs = v2_utils.get_l7policy_attrs(self.app.client_manager,
                                            parsed_args)

        validate.check_l7policy_attrs(attrs)
        l7policy_id = attrs.pop('l7policy_id')

        body = {'l7policy': attrs}

        self.app.client_manager.neutronclient.update_lbaas_l7policy(
            l7policy_id, body=body)
