"""Pydantic request/response schemas for the API."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


# ------------------------------------------------------------------ source
class SourceCustomer(BaseModel):
    customer_id: str
    name: str | None = None
    email: str | None = None
    mobile: str | None = None
    city: str | None = None
    segment: str | None = None


class SourceCustomerPage(BaseModel):
    page: int
    limit: int
    total: int
    customers: list[dict[str, Any]]


# --------------------------------------------------------------- discovery
class DiscoveryField(BaseModel):
    field: str
    detected_type: str
    pii_category: str
    confidence: float
    recommendation: str
    status: str


class DiscoveryResponse(BaseModel):
    run_id: str
    total_fields: int
    pii_count: int
    processing_time_ms: int
    status: str
    fields: list[DiscoveryField]


# ---------------------------------------------------------------- policies
class PolicyRule(BaseModel):
    field: str
    method: Literal["TOKENIZATION", "FPE", "MASKING", "HASHING", "ENCRYPTION"]
    enabled: bool = True
    stable: bool = True
    format: str | None = None


class PolicyUpdate(BaseModel):
    policies: dict[str, dict[str, Any]]


class PolicyResponse(BaseModel):
    policies: dict[str, dict[str, Any]]


# ----------------------------------------------------------------- batches
class BatchRunRequest(BaseModel):
    source: str = "mongo_source"
    batch_size: int = Field(default=100, ge=1, le=5000)
    mode: Literal["full", "discovery_only", "tokenize"] = "full"


class BatchRunResponse(BaseModel):
    batch_id: str
    source: str
    batch_size: int
    status: str
    created_at: str
    records_processed: int = 0
    records_protected: int = 0
    errors: int = 0


# -------------------------------------------------------------- marketing
class SendEmailRequest(BaseModel):
    customer_id: str
    purpose: str = "Newsletter"
    subject: str
    message: str


class SendEmailResponse(BaseModel):
    status: str
    protected_recipient: str
    audit_event_id: str


# ----------------------------------------------------------------- bounce
class BounceWebhookRequest(BaseModel):
    protected_recipient: str | None = None
    email: str | None = None  # provider may send plaintext
    event_type: str = "BOUNCE"
    reason: str = "Mailbox unavailable"


class BounceWebhookResponse(BaseModel):
    event_id: str
    protected_recipient: str
    event_type: str
    reason: str
    timestamp: str
    status: str


# ----------------------------------------------------------------- reveal
class RevealRequest(BaseModel):
    subject_id: str
    field: Literal["name", "email", "mobile"]
    purpose: str
    reference: str


class RevealResponse(BaseModel):
    status: str
    reason: str | None = None
    value: str | None = None
    purpose: str | None = None
    reference: str | None = None
