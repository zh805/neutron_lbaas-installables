# Copyright 2018 <PUT YOUR NAME/COMPANY HERE>
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

"""enable_bw

Revision ID: 6ab3bf450ca6
Revises: 844352f9fe6f
Create Date: 2018-12-25 02:48:52.577363

"""

# revision identifiers, used by Alembic.
revision = '6ab3bf450ca6'
down_revision = '844352f9fe6f'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('lbaas_loadbalancers',
        sa.Column('bandwidth',
        sa.Integer(), nullable=True))
