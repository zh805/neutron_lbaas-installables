# Copyright 2020 <PUT YOUR NAME/COMPANY HERE>
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

"""add_flavor_to_lb

Revision ID: 5404f632f179
Revises: 78ba7a743ea5
Create Date: 2020-03-12 10:29:33.478419

"""

# revision identifiers, used by Alembic.
revision = '5404f632f179'
down_revision = '78ba7a743ea5'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('lbaas_loadbalancers',
                  sa.Column(u'flavor', sa.Integer,
                            nullable=False))


def downgrade():
    op.drop_column(u'lbaas_loadbalancers', 'flavor')
