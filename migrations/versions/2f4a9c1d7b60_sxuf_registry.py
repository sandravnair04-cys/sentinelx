"""Add SXUF endpoint/forwarder registry, agent credentials, receipts and saved searches.

Revision ID: 2f4a9c1d7b60
Revises: 1cc9f928f332
Create Date: 2026-11-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "2f4a9c1d7b60"
down_revision = "1cc9f928f332"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("os_type", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("os_version", sa.String(120), nullable=False, server_default=""),
        sa.Column("ip_address", sa.String(64), nullable=False, server_default=""),
        sa.Column("agent_id", sa.String(100), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("last_heartbeat", sa.DateTime(), nullable=True),
        sa.Column("events_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("health", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_endpoints_hostname", "endpoints", ["hostname"], unique=True)
    op.create_index("ix_endpoints_agent_id", "endpoints", ["agent_id"], unique=True)
    op.create_index("ix_endpoints_last_seen", "endpoints", ["last_seen"])

    op.create_table(
        "forwarders",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("agent_id", sa.String(100), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False, server_default=""),
        sa.Column("version", sa.String(40), nullable=False, server_default="unknown"),
        sa.Column("status", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("config_fingerprint", sa.String(64), nullable=False, server_default=""),
        sa.Column("sources", sa.JSON(), nullable=True),
        sa.Column("events_sent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("buffer_depth", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_heartbeat", sa.DateTime(), nullable=True),
        sa.Column("registered_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_forwarders_agent_id", "forwarders", ["agent_id"], unique=True)
    op.create_index("ix_forwarders_hostname", "forwarders", ["hostname"])
    op.create_index("ix_forwarders_last_heartbeat", "forwarders", ["last_heartbeat"])

    op.create_table(
        "agent_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("agent_id", sa.String(100), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("key_prefix", sa.String(16), nullable=False, server_default=""),
        sa.Column("scopes", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("rotated_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_agent_credentials_agent_id", "agent_credentials", ["agent_id"], unique=True)

    op.create_table(
        "ingest_receipts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("agent_id", sa.String(100), nullable=False),
        sa.Column("client_event_id", sa.String(128), nullable=False),
        sa.Column("event_uid", sa.String(64), nullable=False, server_default=""),
        sa.Column("batch_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("status", sa.String(20), nullable=False, server_default="accepted"),
        sa.Column("received_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("agent_id", "client_event_id", name="uq_agent_client_event"),
    )
    op.create_index("ix_ingest_receipts_agent_id", "ingest_receipts", ["agent_id"])
    op.create_index("ix_ingest_receipts_client_event_id", "ingest_receipts", ["client_event_id"])
    op.create_index("ix_ingest_receipts_received_at", "ingest_receipts", ["received_at"])

    op.create_table(
        "saved_searches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("owner", sa.String(100), nullable=False),
        sa.Column("query_text", sa.Text(), nullable=False, server_default=""),
        sa.Column("filters", sa.JSON(), nullable=True),
        sa.Column("is_shared", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("owner", "name", name="uq_saved_search_owner_name"),
    )
    op.create_index("ix_saved_searches_owner", "saved_searches", ["owner"])


def downgrade() -> None:
    op.drop_table("saved_searches")
    op.drop_table("ingest_receipts")
    op.drop_table("agent_credentials")
    op.drop_table("forwarders")
    op.drop_table("endpoints")
