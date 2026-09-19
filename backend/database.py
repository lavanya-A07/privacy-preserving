"""MongoDB connection and collection accessors."""
from __future__ import annotations

import logging
from typing import Any

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

from backend.config import get_settings

logger = logging.getLogger(__name__)

# Collection names — single source of truth
COLL_SOURCE = "source_customers"
COLL_PROTECTED = "protected_customers"
COLL_VAULT = "secure_vault"
COLL_POLICIES = "protection_policies"
COLL_BATCHES = "batch_runs"
COLL_DISCOVERY = "discovery_results"
COLL_AUDIT = "audit_events"
COLL_EMAIL = "email_events"

_client: MongoClient | None = None
_db: Database | None = None


def connect() -> Database:
    """Idempotently connect to MongoDB and return the database handle."""
    global _client, _db  # noqa: PLW0603
    if _db is not None:
        return _db

    settings = get_settings()
    # Fail fast if the server is unreachable
    _client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=3000)
    # Trigger an actual connection attempt
    _client.admin.command("ping")
    _db = _client[settings.database_name]
    logger.info("Connected to MongoDB at %s (db=%s)", settings.mongo_uri, settings.database_name)
    _ensure_indexes(_db)
    return _db


def get_db() -> Database:
    if _db is None:
        return connect()
    return _db


def get_collection(name: str) -> Collection:
    return get_db()[name]


def ping() -> bool:
    try:
        client = _client
        if client is None:
            client = MongoClient(get_settings().mongo_uri, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("MongoDB ping failed: %s", exc)
        return False


def _ensure_indexes(db: Database) -> None:
    """Create indexes idempotently. Safe to call multiple times."""
    try:
        db[COLL_SOURCE].create_index("customer_id", unique=True, sparse=True)
        db[COLL_PROTECTED].create_index("customer_id", unique=True, sparse=True)
        db[COLL_VAULT].create_index("token", unique=True, sparse=True)
        db[COLL_VAULT].create_index([("field_type", 1), ("token", 1)])
        db[COLL_POLICIES].create_index("field", unique=True)
        db[COLL_BATCHES].create_index("batch_id", unique=True)
        db[COLL_AUDIT].create_index("event_id", unique=True)
        db[COLL_AUDIT].create_index("timestamp")
        db[COLL_EMAIL].create_index("event_id", unique=True)
        db[COLL_DISCOVERY].create_index("run_id", unique=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Index creation warning: %s", exc)


def to_json_safe(doc: Any) -> Any:
    """Strip Mongo _id from documents so FastAPI can serialize them."""
    if isinstance(doc, list):
        return [to_json_safe(d) for d in doc]
    if isinstance(doc, dict):
        out = {k: v for k, v in doc.items() if k != "_id"}
        return out
    return doc
