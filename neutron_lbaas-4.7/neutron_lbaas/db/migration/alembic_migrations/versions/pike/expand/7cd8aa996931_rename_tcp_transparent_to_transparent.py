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

"""rename_tcp_transparent_to_transparent

Revision ID: 7cd8aa996931
Revises: 5b74f35933b6
Create Date: 2019-08-29 10:55:43.496108

"""

# revision identifiers, used by Alembic.
revision = '7cd8aa996931'
down_revision = '5b74f35933b6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column(
        table_name='lbaas_listeners',
        column_name='tcp_transparent',
        new_column_name='transparent',
        existing_type=sa.BOOLEAN(),
        nullable=False
    )
