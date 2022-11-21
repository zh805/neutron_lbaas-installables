# Copyright 2020 cmss, Inc.  All rights reserved.
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
from __future__ import print_function

from neutronclient._i18n import _
from neutronclient.neutron import v2_0 as neutronv20
from oslo_log import log as logging
from oslo_utils import uuidutils
from oslo_serialization import jsonutils
from neutronclient.common import utils
from neutronclient.neutron.v2_0 import find_resourceid_by_name_or_id, find_resourceid_by_id
from neutronclient.common import exceptions

LOG = logging.getLogger(__name__)

def _format_mapping_detail(vgw):
    try:
        return jsonutils.dumps(vgw['mapping_detail'])
    except (TypeError, KeyError):
        return ''

class ListVgwmappingdetail(neutronv20.ListCommand):
    """List all vgw mapping."""

    resource = 'vgw_mapping_detail'
    list_columns = ['id', 'name', 'vrouter_id', 'mapping_detail']
    _formatters = {"mapping_detail": _format_mapping_detail}
    pagination_support = True
    sorting_support = True

class ShowVgwmappingdetail(neutronv20.ShowCommand):
    """Show details of a given vgw mapping."""
    allow_names = True

    resource = 'vgw_mapping_detail'

class CreateVgwmappingdetail(neutronv20.UpdateCommand):
    """Update a given vgw mapping."""

    resource = 'vgw_mapping_detail'
    help_resource = 'vgw_mapping'
    parent_resource = 'vgw_mapping'

    def get_parser(self, prog_name):
        parser = super(neutronv20.UpdateCommand, self).get_parser(prog_name)
        if self.allow_names:
            help_str = _('ID or name of %s to update.')
        else:
            help_str = _('ID of %s to update.')
        if not self.help_resource:
            self.help_resource = self.resource
        parser.add_argument(
            'id', metavar=self.help_resource.upper(),
            help=help_str % self.help_resource)
        self.add_known_arguments(parser)
        return parser

    def add_known_arguments(self, parser):
        mapping_detail = parser.add_mutually_exclusive_group()
        mapping_detail.add_argument(
            '--detail', action='append', dest='mapping_detail',
            type=utils.str2dict_type(required_keys=['type', 'real_ip', 'mapping_ip'],
                                     optional_keys=['real_port', 'mapping_port'],),
            help=_('Mapping detail to associate with the vgw_mapping.'
                   ' You can repeat this option.'))

    def args2body(self, parsed_args):
        body = {}
        neutronv20.update_dict(parsed_args, body, ['mapping_detail'])
        if 'mapping_detail' in body:
            for detail in body['mapping_detail']:
                detail['id'] = uuidutils.generate_uuid()
                keys = detail.keys()
                if 'type' in keys:
                    detail['type'] = int(detail['type'])
                if 'real_port' in keys:
                    detail['real_port'] = int(detail['real_port'])
                if 'mapping_port' in keys:
                    detail['mapping_port'] = int(detail['mapping_port'])
        return {self.resource: body}

    def take_action(self, parsed_args):
        neutron_client = self.get_client()
        body = self.args2body(parsed_args)
        if not body[self.resource]:
            raise exceptions.CommandError(
                _("Must specify new values to update %s") %
                self.cmd_resource)
        if self.allow_names:
            _id = find_resourceid_by_name_or_id(
                neutron_client, self.parent_resource, parsed_args.id,
                cmd_resource=self.cmd_resource, parent_id=self.parent_id)
        else:
            _id = find_resourceid_by_id(
                neutron_client, self.parent_resource, parsed_args.id,
                self.cmd_resource, self.parent_id)
        obj_updater = getattr(neutron_client,
                              "update_%s" % self.resource)
        if self.parent_id:
            obj_updater(_id, self.parent_id, body)
        else:
            obj_updater(_id, body)
        print((_('Updated %(resource)s: %(id)s') %
               {'id': parsed_args.id, 'resource': self.resource}), file=self.app.stdout)
        return


class DeleteVgwmappingdetail(neutronv20.UpdateCommand):
    """Delete a given vgwmapping."""

    resource = 'vgw_mapping_detail'
    help_resource = 'vgw_mapping'
    parent_resource = 'vgw_mapping'

    def get_parser(self, prog_name):
        parser = super(neutronv20.UpdateCommand, self).get_parser(prog_name)
        if self.allow_names:
            help_str = _('ID or name of %s to update.')
        else:
            help_str = _('ID of %s to update.')
        if not self.help_resource:
            self.help_resource = self.resource
        parser.add_argument(
            'id', metavar=self.help_resource.upper(),
            help=help_str % self.help_resource)
        self.add_known_arguments(parser)
        return parser

    def add_known_arguments(self, parser):
        detail_ids = parser.add_mutually_exclusive_group()
        detail_ids.add_argument(
            '--detail', action='append', dest='detail_ids',
            type=utils.str2dict_type(required_keys=['id']),
            help=_('Mapping detail to remove from vgw_mapping.'
                   ' You can repeat this option.'))

    def args2body(self, parsed_args):
        body = {}
        neutronv20.update_dict(parsed_args, body, ['detail_ids'])
        return {self.resource: body}

    def take_action(self, parsed_args):
        neutron_client = self.get_client()
        body = self.args2body(parsed_args)
        if not body[self.resource]:
            raise exceptions.CommandError(
                _("Must specify new values to update %s") %
                self.cmd_resource)
        if self.allow_names:
            _id = find_resourceid_by_name_or_id(
                neutron_client, self.parent_resource, parsed_args.id,
                cmd_resource=self.cmd_resource, parent_id=self.parent_id)
        else:
            _id = find_resourceid_by_id(
                neutron_client, self.parent_resource, parsed_args.id,
                self.cmd_resource, self.parent_id)
        obj_updater = getattr(neutron_client,
                              "update_%s" % self.resource)
        if self.parent_id:
            obj_updater(_id, self.parent_id, body)
        else:
            obj_updater(_id, body)
        print((_('Updated %(resource)s: %(id)s') %
               {'id': parsed_args.id, 'resource': self.resource}), file=self.app.stdout)
        return