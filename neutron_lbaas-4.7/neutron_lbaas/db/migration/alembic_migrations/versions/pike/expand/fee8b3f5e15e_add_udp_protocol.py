# Copyright 2019 cmss, Inc.  All rights reserved
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

"""add_udp_protocol

Revision ID: fee8b3f5e15e
Revises: 7cd8aa996931
Create Date: 2019-10-12 00:19:27.107301

"""

# revision identifiers, used by Alembic.
revision = 'fee8b3f5e15e'
down_revision = '7cd8aa996931'

from alembic import op
import sqlalchemy as sa


new_listener_protocols = sa.Enum("HTTP", "HTTPS", "TCP",
                                 "UDP", "TERMINATED_HTTPS",
                                 name="listener_protocolsv2")


new_pool_protocols = sa.Enum("HTTP", "HTTPS", "TCP", "UDP",
                             name="pool_protocolsv2")


new_healthmonitor_types = sa.Enum("PING", "TCP", "HTTP",
                                  "HTTPS", "UDP",
                                  name="healthmonitor_typesv2")


def upgrade():
    op.alter_column('lbaas_listeners', 'protocol',
                    type_=new_listener_protocols,
                    existing_nullable=False)

    op.alter_column('lbaas_pools', 'protocol',
                    type_=new_pool_protocols,
                    existing_nullable=False)

    op.alter_column('lbaas_healthmonitors', 'type',
                    type_=new_healthmonitor_types,
                    existing_nullable=False)
