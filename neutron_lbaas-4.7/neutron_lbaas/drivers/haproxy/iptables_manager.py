# Copyright 2019 cmss, Inc.  All rights reserved.
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

from neutron.agent.linux import utils as linux_utils
from neutron_lbaas.extensions import loadbalancerv2
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class IptablesManager(object):

    def __init__(self, namespace=None):

        self.namespace = namespace

        if namespace:
            self.cmd_ns_prefix = ['ip', 'netns', 'exec'] + [namespace]
        else:
            self.cmd_ns_prefix = []

        self.cmd_prefix = self.cmd_ns_prefix + ['iptables']

    def add_chain(self, table, chain):
        self._handle_chain(table, chain, True)

    def del_chain(self, table, chain):
        self._handle_chain(table, chain, False)

    def add_rule(self, table, chain, rule):
        self._handle_rule(table, chain, rule, True)

    def del_rule(self, table, chain, rule):
        self._handle_rule(table, chain, rule, False)

    def _handle_chain(self, table, chain, add_or_del):
        cmd = [] + self.cmd_prefix
        if table:
            cmd += ['-t', table]
        if add_or_del:
            cmd += ['-N', chain]
        else:
            cmd += ['-X', chain]
        try:
            linux_utils.execute(cmd, run_as_root=True)
        except RuntimeError:
            command = ''
            for x in cmd:
                command = command + x + ' '
            if not add_or_del:
                LOG.warning(
                    'Fail to clear chain with command %s, '
                    'if it`s initial creation of the listener, '
                    'ignore this warning' % command)
            else:
                raise loadbalancerv2.NamespaceIptablesConfigFail(cmd=command)

    def _handle_rule(self, table, chain, rule, add_or_del):
        cmd = [] + self.cmd_prefix
        if table:
            cmd += ['-t', table]
        if add_or_del:
            cmd += ['-A']
        else:
            cmd += ['-D']
        cmd = cmd + [chain] + rule
        try:
            linux_utils.execute(cmd, run_as_root=True)
        except RuntimeError:
            command = ''
            for x in cmd:
                command = command + x + ' '
            if not add_or_del:
                LOG.warning(
                    'Fail to clear rule by command %s, '
                    'if it`s initial creation of the listener, '
                    'ignore this warning' % command)
            else:
                raise loadbalancerv2.NamespaceIptablesConfigFail(cmd=command)
