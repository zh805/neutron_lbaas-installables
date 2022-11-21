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

"""Load Balancer action implementation"""

from cliff import lister
from osc_lib.command import command
from osc_lib import exceptions
from oslo_serialization import jsonutils

from neutronclient.neutron import v2_0 as neutronV20
from neutronclient.osc.v2.lbaas import constants as const
from neutronclient.osc.v2.lbaas import utils as v2_utils


PROVISIONING_STATUS = ['ACTIVE', 'DELETED', 'ERROR', 'PENDING_CREATE',
                       'PENDING_UPDATE', 'PENDING_DELETE']

OPERATING_STATUS = ['ONLINE', 'DRAINING', 'OFFLINE', 'DEGRADED', 'ERROR',
                    'NO_MONITOR']


def _format_alive(alive):
    return ":-)" if alive else "XXX"


def _format_admin_state(state):
    return 'UP' if state else 'DOWN'


class CreateLoadBalancer(command.ShowOne):
    """Create a load balancer"""

    @staticmethod
    def _check_attrs(attrs):
        verify_args = ['vip_subnet_id', 'vip_network_id']
        if not any(i in attrs for i in verify_args):
            msg = ("Missing required argument: Requires one of "
                   "--vip-subnet-id, --vip-network-id")
            raise exceptions.CommandError(msg)

    def get_parser(self, prog_name):
        parser = super(CreateLoadBalancer, self).get_parser(prog_name)

        parser.add_argument(
            '--name',
            metavar='<name>',
            help="New load balancer name."
        )
        parser.add_argument(
            '--description',
            metavar='<description>',
            help="Set load balancer description."
        )
        parser.add_argument(
            '--vip-address',
            metavar='<vip_address>',
            help="Set the VIP IP Address."
        )

        vip_group = parser.add_argument_group(
            "VIP Network",
            description="At least one of the following arguments is required."
        )
        vip_group.add_argument(
            '--vip-subnet-id',
            metavar='<vip_subnet_id>',
            help="Set subnet for the load balancer (name or ID)."
        )
        vip_group.add_argument(
            '--vip-network-id',
            metavar='<vip_network_id>',
            help="Set network for the load balancer (name or ID)."
        )

        parser.add_argument(
            '--project',
            metavar='<project>',
            help="Project for the load balancer (name or ID)."
        )

        parser.add_argument(
            '--provider',
            metavar='<provider>',
            help="Provider name for the load balancer."
        )
        parser.add_argument(
            '--bandwidth',
            metavar='bandwidth',
            help='Bandwidth for the load balancer.'
        )

        admin_group = parser.add_mutually_exclusive_group()
        admin_group.add_argument(
            '--enable',
            action='store_true',
            default=True,
            help="Enable load balancer (default)."
        )
        admin_group.add_argument(
            '--disable',
            action='store_true',
            default=None,
            help="Disable load balancer."
        )
        parser.add_argument(
            '--flavor',
            metavar='<flavor>',
            help="The name or ID of the flavor for the load balancer."
        )

        return parser

    def take_action(self, parsed_args):
        rows = const.LOAD_BALANCER_ROWS
        attrs = v2_utils.get_loadbalancer_attrs(self.app.client_manager,
                                                parsed_args)
        self._check_attrs(attrs)
        body = {'loadbalancer': attrs}

        data = self.app.client_manager.neutronclient.create_loadbalancer(
            body=body)

        formatters = {
            'listeners': v2_utils.format_list,
            'pools': v2_utils.format_list,
            'l7policies': v2_utils.format_list
        }

        return (rows,
                (v2_utils.get_dict_properties(
                    data['loadbalancer'], rows, formatters=formatters)))


class DeleteLoadBalancer(command.Command):
    """Delete a load balancer"""

    def get_parser(self, prog_name):
        parser = super(DeleteLoadBalancer, self).get_parser(prog_name)

        parser.add_argument(
            'loadbalancer',
            metavar='<load_balancer>',
            help="Load balancers to delete (name or ID)"
        )

        return parser

    def take_action(self, parsed_args):
        attrs = v2_utils.get_loadbalancer_attrs(self.app.client_manager,
                                                parsed_args)
        lb_id = attrs.pop('loadbalancer_id')

        self.app.client_manager.neutronclient.delete_loadbalancer(
            lb_id)


class ListLoadBalancer(lister.Lister):
    """List load balancers"""

    def get_parser(self, prog_name):
        parser = super(ListLoadBalancer, self).get_parser(prog_name)

        parser.add_argument(
            '--name',
            metavar='<name>',
            help="List load balancers according to their name."
        )
        admin_state_group = parser.add_mutually_exclusive_group()
        admin_state_group.add_argument(
            '--enable',
            action='store_true',
            default=None,
            help="List enabled load balancers."
        )
        admin_state_group.add_argument(
            '--disable',
            action='store_true',
            default=None,
            help="List disabled load balancers."
        )
        parser.add_argument(
            '--project',
            metavar='<project-id>',
            help="List load balancers according to their project (name or ID)."
        )
        parser.add_argument(
            '--vip-network-id',
            metavar='<vip_network_id>',
            help="List load balancers according to their VIP network "
                 "(name or ID)."
        )
        parser.add_argument(
            '--vip-subnet-id',
            metavar='<vip_subnet_id>',
            help="List load balancers according to their VIP subnet "
                 "(name or ID)."
        )
        parser.add_argument(
            '--vip-qos-policy-id',
            metavar='<vip_qos_policy_id>',
            help="List load balancers according to their VIP Qos policy "
                 "(name or ID)."
        )
        parser.add_argument(
            '--vip-port-id',
            metavar='<vip_port_id>',
            help="List load balancers according to their VIP port "
                 "(name or ID)."
        )
        parser.add_argument(
            '--provisioning-status',
            metavar='{' + ','.join(PROVISIONING_STATUS) + '}',
            choices=PROVISIONING_STATUS,
            type=lambda s: s.upper(),
            help="List load balancers according to their provisioning status."
        )
        parser.add_argument(
            '--operating-status',
            metavar='{' + ','.join(OPERATING_STATUS) + '}',
            choices=OPERATING_STATUS,
            type=lambda s: s.upper(),
            help="List load balancers according to their operating status."
        )
        parser.add_argument(
            '--provider',
            metavar='<provider>',
            help="List load balancers according to their provider."
        )
        parser.add_argument(
            '--flavor',
            metavar='<flavor>',
            help="List load balancers according to their flavor."
        )

        return parser

    def take_action(self, parsed_args):
        columns = const.LOAD_BALANCER_COLUMNS
        attrs = v2_utils.get_loadbalancer_attrs(self.app.client_manager,
                                                parsed_args)

        data = self.app.client_manager.neutronclient.list_lbaas_loadbalancers(
            **attrs)

        return (columns,
                (v2_utils.get_dict_properties(
                    s, columns,
                    formatters={},
                ) for s in data['loadbalancers']))


class ShowLoadBalancer(command.ShowOne):
    """Show the details for a single load balancer"""

    def get_parser(self, prog_name):
        parser = super(ShowLoadBalancer, self).get_parser(prog_name)

        parser.add_argument(
            'loadbalancer',
            metavar='<load_balancer>',
            help="Name or UUID of the load balancer."
        )

        return parser

    def take_action(self, parsed_args):
        rows = const.LOAD_BALANCER_ROWS
        attrs = v2_utils.get_loadbalancer_attrs(self.app.client_manager,
                                                parsed_args)
        lb_id = attrs.pop('loadbalancer_id')

        data = self.app.client_manager.neutronclient.show_loadbalancer(
            lb_id)

        formatters = {
            'listeners': v2_utils.format_list,
            'pools': v2_utils.format_list,
            'l7policies': v2_utils.format_list
        }

        return (rows, (v2_utils.get_dict_properties(
            data['loadbalancer'], rows, formatters=formatters)))


class SetLoadBalancer(command.Command):
    """Update a load balancer"""

    def get_parser(self, prog_name):
        parser = super(SetLoadBalancer, self).get_parser(prog_name)

        parser.add_argument(
            'loadbalancer',
            metavar='<load_balancer>',
            help='Name or UUID of the load balancer to update.'
        )
        parser.add_argument(
            '--name',
            metavar='<name>',
            help="Set load balancer name."
        )
        parser.add_argument(
            '--description',
            metavar='<description>',
            help="Set load balancer description."
        )
        parser.add_argument(
            '--bandwidth',
            metavar='bandwidth',
            help='Bandwidth for the load balancer.'
        )

        admin_group = parser.add_mutually_exclusive_group()
        admin_group.add_argument(
            '--enable',
            action='store_true',
            default=None,
            help="Enable load balancer."
        )
        admin_group.add_argument(
            '--disable',
            action='store_true',
            default=None,
            help="Disable load balancer."
        )

        return parser

    def take_action(self, parsed_args):
        attrs = v2_utils.get_loadbalancer_attrs(self.app.client_manager,
                                                parsed_args)
        lb_id = attrs.pop('loadbalancer_id')
        body = {'loadbalancer': attrs}

        self.app.client_manager.neutronclient.update_loadbalancer(
            lb_id, body=body)


class ShowLoadBalancerStats(command.ShowOne):
    """Shows the current statistics for a load balancer"""

    def get_parser(self, prog_name):
        parser = super(ShowLoadBalancerStats, self).get_parser(prog_name)

        parser.add_argument(
            'loadbalancer',
            metavar='<load_balancer>',
            help="Name or UUID of the load balancer."
        )

        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        rows = const.LOAD_BALANCER_STATS_ROWS
        attrs = v2_utils.get_loadbalancer_attrs(self.app.client_manager,
                                                parsed_args)
        lb_id = attrs.pop('loadbalancer_id')

        data = client.retrieve_loadbalancer_stats(lb_id)

        return (rows, (v2_utils.get_dict_properties(
            data['stats'], rows, formatters={})))


class ShowLoadBalancerStatus(command.Command):
    """Display load balancer status tree in json format"""

    def get_parser(self, prog_name):
        parser = super(ShowLoadBalancerStatus, self).get_parser(prog_name)

        parser.add_argument(
            'loadbalancer',
            metavar='<load_balancer>',
            help="Name or UUID of the load balancer."
        )

        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        attrs = v2_utils.get_loadbalancer_attrs(self.app.client_manager,
                                                parsed_args)
        lb_id = attrs.pop('loadbalancer_id')

        data = client.retrieve_loadbalancer_status(lb_id)
        res = data.get('statuses', {})
        print(jsonutils.dumps(res, indent=4))


class ListLoadBalancersOnLbaasAgent(lister.Lister):
    """List the loadbalancers on a loadbalancer v2 agent."""

    def get_parser(self, prog_name):
        parser = super(ListLoadBalancersOnLbaasAgent, self).get_parser(
            prog_name)
        parser.add_argument(
            'lbaas_agent',
            metavar='<lbaas_agent>',
            help="ID of the loadbalancer agent to query."
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        columns = const.LOAD_BALANCER_COLUMNS
        lbaas_agent = parsed_args.lbaas_agent
        data = client.list_loadbalancers_on_lbaas_agent(lbaas_agent)

        return (columns,
                (v2_utils.get_dict_properties(
                    s, columns,
                    formatters={},
                ) for s in data['loadbalancers']))


class GetLbaasAgentHostingLoadBalancer(command.ShowOne):
    """Get lbaas v2 agent hosting a loadbalancer.

    Deriving from ListCommand though server will return only one agent
    to keep common output format for all agent schedulers
    """

    def get_parser(self, prog_name):
        parser = super(GetLbaasAgentHostingLoadBalancer,
                       self).get_parser(prog_name)
        parser.add_argument(
            'loadbalancer',
            metavar='<loadbalancer>',
            help="LoadBalancer to query."
        )
        return parser

    def take_action(self, parsed_args):
        client = self.app.client_manager.neutronclient
        columns = const.LBAASAGENTHOSTINGLB_COLUMNS
        search_opts = {}
        _id = neutronV20.find_resourceid_by_name_or_id(
            self.app.client_manager.neutronclient,
            'loadbalancer', parsed_args.loadbalancer)
        search_opts['loadbalancer'] = _id
        agent = client.get_lbaas_agent_hosting_loadbalancer(
            **search_opts)
        formatters = {
            'alive': _format_alive,
            'admin_state_up': _format_admin_state
        }
        return (columns,
                (v2_utils.get_dict_properties(
                    agent['agent'], columns,
                    formatters=formatters,
                )))
