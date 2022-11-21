# Copyright 2019 <PUT YOUR NAME/COMPANY HERE>
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

"""Add availability zone into lb service

Revision ID: 78ba7a743ea5
Revises: 7cd8aa996931
Create Date: 2019-11-22 17:07:18.226660

"""

# revision identifiers, used by Alembic.
revision = '78ba7a743ea5'
down_revision = 'fee8b3f5e15e'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'lbaas_loadbalancers',
        sa.Column('availability_zone_hints', sa.String(length=255),
                  default=None,
                  nullable=True))
