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

"""enable_tcp_transparent

Revision ID: 5b74f35933b6
Revises: 6ab3bf450ca6
Create Date: 2019-07-19 14:03:17.353615

"""

# revision identifiers, used by Alembic.
revision = '5b74f35933b6'
down_revision = '6ab3bf450ca6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('lbaas_listeners',
                  sa.Column(u'tcp_transparent', sa.Boolean,
                            nullable=False))


def downgrade():
    pass
