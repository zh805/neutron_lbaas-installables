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

"""add_timeout_for_session_persistence

Revision ID: 36d0c64e839b
Revises: bafb4b9a34dc
Create Date: 2020-10-25 18:01:47.085768

"""

# revision identifiers, used by Alembic.
revision = '36d0c64e839b'
down_revision = 'bafb4b9a34dc'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('lbaas_sessionpersistences',
                  sa.Column('persistence_timeout',
                            sa.Integer(),
                            nullable=True))
