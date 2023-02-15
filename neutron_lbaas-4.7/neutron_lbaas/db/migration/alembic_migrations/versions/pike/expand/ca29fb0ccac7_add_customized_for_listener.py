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

"""add_customized_for_listener

Revision ID: ca29fb0ccac7
Revises: 2dbbe330f465
Create Date: 2020-11-22 09:14:31.313399

"""

# revision identifiers, used by Alembic.
revision = 'ca29fb0ccac7'
down_revision = '2dbbe330f465'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('lbaas_listeners',
                  sa.Column('customized',
                            sa.String(1024)))
