from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class GenerateRequest(BaseModel):
    document_type: str = Field(..., min_length=1, max_length=100)
    first_party_name: str = Field(..., min_length=1, max_length=255)
    first_party_role: str = Field(..., min_length=1, max_length=255)
    second_party_name: str = Field(..., min_length=1, max_length=255)
    second_party_role: str = Field(..., min_length=1, max_length=255)
    additional_parties: Optional[str] = Field(None, max_length=1000)
    effective_date: Optional[str] = Field(None, max_length=50)
    terms_and_conditions: str = Field(..., min_length=10, max_length=20000)
    jurisdiction: Optional[str] = Field(None, max_length=255)
    optional_company_name: Optional[str] = Field(None, max_length=255)

    @field_validator(
        "document_type",
        "first_party_name",
        "first_party_role",
        "second_party_name",
        "second_party_role",
        "terms_and_conditions",
    )
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("This field cannot be blank.")
        return value


class GenerateResponse(BaseModel):
    title: str
    document_type: str
    generated_content: str
    metadata: dict[str, Any]


class DocumentBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    document_type: str = Field(..., min_length=1, max_length=100)
    party_details: str = Field(..., min_length=10, max_length=12000)
    terms: str = Field(..., min_length=10, max_length=12000)
    effective_date: Optional[str] = Field(None, max_length=50)
    jurisdiction: Optional[str] = Field(None, max_length=255)
    generated_content: str = Field(..., min_length=10, max_length=60000)

    @field_validator("title", "document_type", "party_details", "terms", "generated_content")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("This field cannot be blank.")
        return value


class DocumentCreate(DocumentBase):
    organization_id: Optional[int] = Field(None, gt=0)


class DocumentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    document_type: Optional[str] = Field(None, min_length=1, max_length=100)
    party_details: Optional[str] = Field(None, min_length=10, max_length=12000)
    terms: Optional[str] = Field(None, min_length=10, max_length=12000)
    effective_date: Optional[str] = Field(None, max_length=50)
    jurisdiction: Optional[str] = Field(None, max_length=255)
    generated_content: Optional[str] = Field(None, min_length=10, max_length=60000)

    @model_validator(mode="after")
    def require_update_fields(self) -> "DocumentUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one document field must be supplied.")
        for field in self.model_fields_set - {"effective_date", "jurisdiction"}:
            value = getattr(self, field)
            if value is None or (isinstance(value, str) and not value.strip()):
                raise ValueError(f"{field} cannot be blank or null.")
        return self


class DocumentOut(DocumentBase):
    id: int
    owner_id: int
    organization_id: Optional[int]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=6, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(..., min_length=12, max_length=256)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=6, max_length=320)
    password: str = Field(..., min_length=1, max_length=256)


class TokenInput(BaseModel):
    token: str = Field(..., min_length=20, max_length=512)


class PasswordResetRequest(BaseModel):
    email: str = Field(..., min_length=6, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class PasswordResetConfirm(BaseModel):
    token: str = Field(..., min_length=20, max_length=512)
    new_password: str = Field(..., min_length=12, max_length=256)


class AuthUserOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: AuthUserOut


class ShareCreate(BaseModel):
    email: str = Field(..., min_length=6, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    permission: str = Field(..., pattern=r"^(viewer|reviewer|editor)$")


class ReviewInput(BaseModel):
    status: str = Field(..., pattern=r"^(approved|changes_requested)$")
    comment: str = Field(..., min_length=1, max_length=5000)


class ShareOut(BaseModel):
    id: int
    document_id: int
    user_id: int
    permission: str
    review_status: str
    review_comment: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)

    @field_validator("name")
    @classmethod
    def reject_blank_name(cls, value: str) -> str:
        if len(value.strip()) < 2:
            raise ValueError("Organization name must contain at least two non-space characters.")
        return value


class OrganizationOut(BaseModel):
    id: int
    name: str
    created_by_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AdminUserUpdate(BaseModel):
    role: Optional[str] = Field(None, pattern=r"^(user|legal_reviewer|admin)$")
    is_active: Optional[bool] = None


class AdminUserOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
