"""Column helpers shared by the models (uuid PKs, timestamptz defaults, jsonb/text[] defaults)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import mapped_column

UUID_T = UUID(as_uuid=True)
TSTZ = DateTime(timezone=True)
TEXT_ARRAY = ARRAY(Text())


def uuid_pk() -> Any:
    return mapped_column(UUID_T, primary_key=True, server_default=text("gen_random_uuid()"))


def created_at() -> Any:
    return mapped_column(TSTZ, nullable=False, server_default=text("now()"))


def jsonb_obj(nullable: bool = False) -> Any:
    return mapped_column(JSONB, nullable=nullable, server_default=text("'{}'::jsonb"))


def text_array() -> Any:
    return mapped_column(TEXT_ARRAY, nullable=False, server_default=text("'{}'::text[]"))


__all__ = [
    "TEXT_ARRAY",
    "TSTZ",
    "UUID_T",
    "created_at",
    "datetime",
    "jsonb_obj",
    "text_array",
    "uuid",
    "uuid_pk",
]
