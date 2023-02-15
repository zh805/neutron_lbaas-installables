# Copyright 2020 CMSS.
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

"""lbaasv2_acl

Revision ID: bafb4b9a34dc
Revises: cc53da4ba9ea
Create Date: 2020-04-03 00:19:26.742514

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'bafb4b9a34dc'
down_revision = 'cc53da4ba9ea'


acl_control_types = sa.Enum("blacklist", "whitelist",
                            name="acl_control_types")

acl_rule_ip_versions = sa.Enum("IPv4", "IPv6", name="acl_rule_ip_versions")


def upgrade():
    op.create_table(
        'lbaas_acl_groups',
        sa.Column('project_id', sa.String(255), nullable=True),
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('name', sa.String(255), nullable=True),
        sa.Column('description', sa.String(255), nullable=True),
        sa.Column('region', sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'lbaas_acl_rules',
        sa.Column('project_id', sa.String(255), nullable=True),
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('description', sa.String(255), nullable=True),
        sa.Column('ip_address', sa.String(255), nullable=False),
        sa.Column('ip_version', acl_rule_ip_versions, nullable=False),
        sa.Column('acl_group_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['acl_group_id'],
                                ['lbaas_acl_groups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'lbaas_acl_group_listener_bindings',
        sa.Column('listener_id', sa.String(length=36), nullable=False),
        sa.Column('acl_group_id', sa.String(length=36), nullable=False),
        sa.Column('type', acl_control_types, nullable=False),
        sa.Column('enabled', sa.Boolean, nullable=False),
        sa.ForeignKeyConstraint(['listener_id'],
                                ['lbaas_listeners.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['acl_group_id'],
                                ['lbaas_acl_groups.id']),
        sa.PrimaryKeyConstraint('listener_id'))


def downgrade():
    op.drop_table('lbaas_acl_group_listener_bindings')
    op.drop_table('lbaas_acl_rules')
    op.drop_table('lbaas_acl_groups')
