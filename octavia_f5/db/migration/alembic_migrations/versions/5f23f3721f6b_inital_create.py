"""initial_create

Revision ID: 5f23f3721f6b
Revises: None
Create Date: 2019-04-08 15:38:36.415727

"""

# revision identifiers, used by Alembic.
revision = '5f23f3721f6b'
down_revision = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        u'f5_esd',
        sa.Column(u'name', sa.String(63), nullable=False),
        sa.PrimaryKeyConstraint(u'name')
    )

    op.create_table(
        u'f5_esd_attributes',
        sa.Column(u'f5_esd_name', sa.String(36), nullable=False),
        sa.Column(u'name', sa.String(255), nullable=False),
        sa.Column(u'type', sa.String(255), nullable=False),
        sa.ForeignKeyConstraint([u'f5_esd_name'], [u'f5_esd.name'],
                                name=u'fk_f5_esd_attributes_f5_esd_name')
    )

    insert_table = sa.table(
        u'f5_esd',
        sa.column(u'name', sa.String)
    )

    op.bulk_insert(
        insert_table,
        [
            {'name': 'proxy_protocol_2edF_v1_0'},
            {'name': 'proxy_protocol_V2_e8f6_v1_0'},
            {'name': 'standard_tcp_a3de_v1_0'},
            {'name': 'x_forward_5b6e_v1_0'},
            {'name': 'one_connect_dd5c_v1_0'},
            {'name': 'no_one_connect_3caB_v1_0'},
            {'name': 'http_compression_e4a2_v1_0'},
            {'name': 'cookie_encryption_b82a_v1_0'},
            {'name': 'sso_22b0_v1_0'},
            {'name': 'sso_required_f544_v1_0'},
            {'name': 'http_redirect_a26c_v1_0'}
        ]
    )

    insert_table = sa.table(
        u'f5_esd_attributes',
        sa.column(u'f5_esd_name', sa.String),
        sa.column(u'name', sa.String),
        sa.column(u'type', sa.String),
    )

    op.bulk_insert(
        insert_table,
        [
            {'f5_esd_name': 'proxy_protocol_2edF_v1_0',
             'type': 'fastl4', 'name': ''},
            {'f5_esd_name': 'proxy_protocol_2edF_v1_0',
             'type': 'ctcp', 'name': 'tcp'},
            {'f5_esd_name': 'proxy_protocol_2edF_v1_0',
             'type': 'irule', 'name': 'proxy_protocol_2edF_v1_0'},
            {'f5_esd_name': 'proxy_protocol_2edF_v1_0',
             'type': 'one_connect', 'name': ''},
            {'f5_esd_name': 'proxy_protocol_V2_e8f6_v1_0',
             'type': 'fastl4', 'name': ''},
            {'f5_esd_name': 'proxy_protocol_V2_e8f6_v1_0',
             'type': 'ctcp', 'name': 'tcp'},
            {'f5_esd_name': 'proxy_protocol_V2_e8f6_v1_0',
             'type': 'irule', 'name': 'cc_proxy_protocol_V2_e8f6_v1_0'},
            {'f5_esd_name': 'proxy_protocol_V2_e8f6_v1_0',
             'type': 'one_connect', 'name': ''},
            {'f5_esd_name': 'standard_tcp_a3de_v1_0',
             'type': 'fastl4', 'name': ''},
            {'f5_esd_name': 'standard_tcp_a3de_v1_0',
             'type': 'ctcp', 'name': 'tcp'},
            {'f5_esd_name': 'standard_tcp_a3de_v1_0',
             'type': 'one_connect', 'name': ''},
            {'f5_esd_name': 'x_forward_5b6e_v1_0',
             'type': 'irule', 'name': 'cc_x_forward_5b6e_v1_0'},
            {'f5_esd_name': 'one_connect_dd5c_v1_0',
             'type': 'one_connect', 'name': 'oneconnect'},
        ]
    )
