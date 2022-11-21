# Copyright 2020 cmss, Inc.
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

"""mutual_authentication_enable

Revision ID: cc53da4ba9ea
Revises: 5404f632f179
Create Date: 2020-05-07 09:13:34.283787

"""

# revision identifiers, used by Alembic.
revision = 'cc53da4ba9ea'
down_revision = '5404f632f179'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('lbaas_listeners',
                  sa.Column(u'mutual_authentication_up', sa.Boolean,
                            default=False, nullable=False))
    op.add_column('lbaas_listeners',
                  sa.Column(u'ca_container_id', sa.String(128),
                            default=None, nullable=True))


def downgrade():
    pass
