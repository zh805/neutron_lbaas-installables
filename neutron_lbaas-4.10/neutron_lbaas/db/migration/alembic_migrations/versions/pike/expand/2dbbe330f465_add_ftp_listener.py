# Copyright 2020 cmss, Inc.  All rights reserved.
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

"""add_ftp_listener

Revision ID: 2dbbe330f465
Revises: 36d0c64e839b
Create Date: 2020-11-06 12:30:31.277580

"""

# revision identifiers, used by Alembic.
revision = '2dbbe330f465'
down_revision = '36d0c64e839b'

from alembic import op
import sqlalchemy as sa


new_listener_protocols = sa.Enum("HTTP", "HTTPS", "TCP",
                                 "UDP", "TERMINATED_HTTPS",
                                 "FTP",
                                 name="listener_protocolsv2")


def upgrade():
    op.alter_column('lbaas_listeners', 'protocol',
                    type_=new_listener_protocols,
                    nullable=False,
                    existing_type=sa.Enum())
