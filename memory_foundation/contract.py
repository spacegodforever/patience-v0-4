"""Memory record contract. Validation fails closed: unknown class, scope, classification
or extra fields are rejected."""
from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class RecordType(str, Enum):
    working = "working"; project = "project"; episodic = "episodic"
    long_term = "long_term"; pattern = "pattern"; governance = "governance"


class SharingScope(str, Enum):
    device = "device"; user = "user"; project = "project"; team = "team"


class Classification(str, Enum):
    public = "public"; internal = "internal"; confidential = "confidential"; restricted = "restricted"


class MemoryRecordIn(BaseModel):
    """What a client may submit. memory_id/timestamps/version/provenance are server-assigned."""
    model_config = ConfigDict(extra="forbid", strict=True)
    record_type: RecordType
    content: str = Field(min_length=1, max_length=20000)
    source: str = Field(min_length=1, max_length=200)
    confidence: float = Field(ge=0, le=1)
    classification: Classification
    sharing_scope: SharingScope
    project_id: Optional[str] = Field(None, max_length=200)
    review_required: bool = False
    expires_at: Optional[str] = Field(None, max_length=40)

    @model_validator(mode="after")
    def _rules(self):
        if self.sharing_scope == SharingScope.project and not self.project_id:
            raise ValueError("sharing_scope=project requires project_id")
        if self.record_type == RecordType.project and not self.project_id:
            raise ValueError("record_type=project requires project_id")
        # governance and pattern memory influence decisions: always human-reviewed
        if self.record_type in (RecordType.governance, RecordType.pattern):
            self.review_required = True
        return self


RECORD_FIELDS = ("memory_id", "record_type", "content", "source", "confidence", "classification",
                 "sharing_scope", "project_id", "created_at", "updated_at", "version",
                 "review_required", "expires_at")
