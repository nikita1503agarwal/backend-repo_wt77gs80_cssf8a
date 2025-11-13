"""
Database Schemas for Mental Health Platform

Each Pydantic model represents a MongoDB collection. Collection name is the lowercased class name.

Key collections:
- User (roles: parent, doctor, hospital_admin, super_admin)
- Hospital
- Doctor
- Assessment
- Appointment
- TherapyPlan
- Message (for live support/chat)
- Testimonial
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal, Dict
from datetime import datetime

Role = Literal["parent", "doctor", "hospital_admin", "super_admin"]

class User(BaseModel):
    name: str
    email: EmailStr
    role: Role
    password_hash: str
    verified: bool = False
    language: Optional[str] = "en"

class Hospital(BaseModel):
    name: str
    location: str
    specialization: Optional[List[str]] = []
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    description: Optional[str] = None
    services: Optional[List[str]] = []

class Doctor(BaseModel):
    user_id: str
    hospital_id: str
    specialization: List[str]
    experience_years: int = Field(ge=0, default=0)
    qualifications: Optional[List[str]] = []
    languages: Optional[List[str]] = ["en"]
    bio: Optional[str] = None
    photo_url: Optional[str] = None
    verified: bool = False
    ratings: Optional[List[int]] = []

class Assessment(BaseModel):
    parent_id: str
    child_name: str
    child_age: int = Field(ge=0, le=18)
    age_group: Literal["infant", "child", "adolescent"]
    condition: Literal["autism", "adhd", "dyslexia", "other"]
    responses: Dict[str, str]
    voice_transcript: Optional[str] = None
    language: Optional[str] = "en"
    encrypted: bool = True
    risk_score: Optional[float] = None
    assigned_doctor_id: Optional[str] = None
    assigned_hospital_id: Optional[str] = None
    status: Literal["submitted", "assigned", "in_review", "completed"] = "submitted"

class Appointment(BaseModel):
    parent_id: str
    doctor_id: str
    hospital_id: str
    assessment_id: Optional[str] = None
    mode: Literal["online", "in_person"] = "online"
    slot: str  # ISO datetime string
    period: Literal["morning", "afternoon", "evening"]
    status: Literal["pending", "confirmed", "cancelled", "completed"] = "pending"
    payment_status: Literal["unpaid", "paid", "refunded"] = "unpaid"
    payment_provider: Optional[Literal["stripe", "razorpay"]] = None
    notes: Optional[str] = None

class TherapyPlan(BaseModel):
    doctor_id: str
    parent_id: str
    assessment_id: str
    suggestions: List[str] = []  # OT/ST/BT suggestions
    approved: bool = False

class Message(BaseModel):
    from_user_id: str
    to_user_id: str
    content: str
    created_at: Optional[datetime] = None

class Testimonial(BaseModel):
    doctor_id: str
    parent_id: str
    rating: int = Field(ge=1, le=5)
    comment: Optional[str] = None
