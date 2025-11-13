import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents
from schemas import User, Hospital, Doctor, Assessment, Appointment, TherapyPlan, Message, Testimonial

# App setup
app = FastAPI(title="Mental Health Assessment & Therapy API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change")
JWT_ALG = "HS256"
JWT_EXP_MIN = int(os.getenv("JWT_EXP_MIN", "1440"))

# Utility helpers

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_token(user_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MIN),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


class AuthUser(BaseModel):
    id: str
    email: EmailStr
    role: str


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> AuthUser:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        role = payload.get("role")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": {"$eq": db.client.get_default_database().codec_options.document_class.ObjectId if False else None}})
        # Fetch minimal fields by id
        from bson import ObjectId
        doc = db["user"].find_one({"_id": ObjectId(user_id)})
        if not doc:
            raise HTTPException(status_code=401, detail="User not found")
        return AuthUser(id=user_id, email=doc.get("email"), role=role)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# Public endpoints
@app.get("/")
def root():
    return {"message": "Mental Health API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            collections = db.list_collection_names()
            response["collections"] = collections
            response["database"] = "✅ Connected & Working"
            response["connection_status"] = "Connected"
    except Exception as e:
        response["database"] = f"⚠️  Connected but Error: {str(e)[:80]}"

    return response


# Auth models
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# Auth endpoints
@app.post("/auth/register", response_model=TokenResponse)
def register(req: RegisterRequest):
    if req.role not in ["parent", "doctor", "hospital_admin", "super_admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")

    existing = db["user"].find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        name=req.name,
        email=req.email,
        role=req.role,
        password_hash=hash_password(req.password),
        verified=True if req.role in ("hospital_admin", "super_admin") else False,
    )
    user_id = create_document("user", user)

    token = create_token(user_id, user.role)
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest):
    from bson import ObjectId
    doc = db["user"].find_one({"email": req.email})
    if not doc or not verify_password(req.password, doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(str(doc["_id"]), doc.get("role"))
    return TokenResponse(access_token=token)


# Hospitals
class HospitalCreate(BaseModel):
    name: str
    location: str
    specialization: Optional[List[str]] = None
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    description: Optional[str] = None
    services: Optional[List[str]] = None


@app.post("/hospitals")
def create_hospital(payload: HospitalCreate, user: AuthUser = Depends(get_current_user)):
    if user.role not in ("hospital_admin", "super_admin"):
        raise HTTPException(status_code=403, detail="Forbidden")
    hospital = Hospital(**payload.model_dump())
    hid = create_document("hospital", hospital)
    return {"id": hid}


@app.get("/hospitals")
def list_hospitals():
    items = get_documents("hospital")
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


@app.get("/hospitals/{hospital_id}")
def get_hospital(hospital_id: str):
    from bson import ObjectId
    doc = db["hospital"].find_one({"_id": ObjectId(hospital_id)})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    doc["id"] = str(doc.pop("_id"))
    # doctors in this hospital
    doctors = list(db["doctor"].find({"hospital_id": hospital_id, "verified": True}))
    for d in doctors:
        d["id"] = str(d.pop("_id"))
    doc["doctors"] = doctors
    return doc


# Doctors
class DoctorCreate(BaseModel):
    user_id: str
    hospital_id: str
    specialization: List[str]
    experience_years: int = 0
    qualifications: Optional[List[str]] = None
    languages: Optional[List[str]] = None
    bio: Optional[str] = None
    photo_url: Optional[str] = None


@app.post("/doctors")
def create_doctor(payload: DoctorCreate, user: AuthUser = Depends(get_current_user)):
    if user.role not in ("hospital_admin", "super_admin"):
        raise HTTPException(status_code=403, detail="Forbidden")
    doc = Doctor(**payload.model_dump(), verified=True)
    did = create_document("doctor", doc)
    return {"id": did}


@app.get("/doctors/{doctor_id}")
def get_doctor(doctor_id: str):
    from bson import ObjectId
    d = db["doctor"].find_one({"_id": ObjectId(doctor_id)})
    if not d:
        raise HTTPException(status_code=404, detail="Not found")
    d["id"] = str(d.pop("_id"))
    # testimonials
    testimonials = list(db["testimonial"].find({"doctor_id": doctor_id}))
    for t in testimonials:
        t["id"] = str(t.pop("_id"))
    d["testimonials"] = testimonials
    # basic mock availability slots (server-side)
    now = datetime.now(timezone.utc)
    slots = []
    for i in range(1, 8):
        dt = now + timedelta(days=i)
        for hour, period in [(9, "morning"), (14, "afternoon"), (18, "evening")]:
            slot_time = dt.replace(hour=hour, minute=0, second=0, microsecond=0)
            slots.append({"time": slot_time.isoformat(), "period": period})
    d["availability"] = slots
    return d


# Assessments
class AssessmentCreate(BaseModel):
    child_name: str
    child_age: int
    age_group: str
    condition: str
    responses: Dict[str, str]
    voice_transcript: Optional[str] = None
    language: Optional[str] = "en"


@app.post("/assessments")
def submit_assessment(payload: AssessmentCreate, user: AuthUser = Depends(get_current_user)):
    if user.role != "parent":
        raise HTTPException(status_code=403, detail="Only parents can submit assessments")

    # Basic risk scoring (placeholder analytic)
    score = min(100.0, float(len(" ".join(payload.responses.values()))) / 10.0)

    # Find an available verified doctor in any hospital matching condition specialization
    spec_map = {
        "autism": "autism",
        "adhd": "adhd",
        "dyslexia": "dyslexia",
        "other": "general"
    }
    spec = spec_map.get(payload.condition, "general")
    candidate = db["doctor"].find_one({"verified": True, "specialization": {"$in": [spec]}})

    assessment = Assessment(
        parent_id=user.id,
        child_name=payload.child_name,
        child_age=payload.child_age,
        age_group=payload.age_group,
        condition=payload.condition,
        responses=payload.responses,
        voice_transcript=payload.voice_transcript,
        language=payload.language,
        risk_score=score,
        assigned_doctor_id=str(candidate["_id"]) if candidate else None,
        assigned_hospital_id=candidate.get("hospital_id") if candidate else None,
        status="assigned" if candidate else "submitted",
    )
    aid = create_document("assessment", assessment)

    # Simple real-time notification stub (can be extended to websockets)
    notif = Message(from_user_id=user.id, to_user_id=assessment.assigned_doctor_id or "", content=f"New assessment {aid} assigned")
    create_document("message", notif)

    return {"id": aid, "assigned_doctor_id": assessment.assigned_doctor_id, "risk_score": score}


@app.get("/parent/assessments")
def list_parent_assessments(user: AuthUser = Depends(get_current_user)):
    if user.role != "parent":
        raise HTTPException(status_code=403, detail="Forbidden")
    items = list(db["assessment"].find({"parent_id": user.id}).sort("created_at", -1))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# Appointments
class AppointmentCreate(BaseModel):
    doctor_id: str
    hospital_id: str
    slot: str
    period: str
    mode: Optional[str] = "online"
    assessment_id: Optional[str] = None


@app.post("/appointments")
def create_appointment(payload: AppointmentCreate, user: AuthUser = Depends(get_current_user)):
    if user.role != "parent":
        raise HTTPException(status_code=403, detail="Only parents can book")
    appt = Appointment(parent_id=user.id, **payload.model_dump())
    appt_id = create_document("appointment", appt)
    return {"id": appt_id, "status": "pending"}


@app.get("/doctor/assessments")
def doctor_assessments(user: AuthUser = Depends(get_current_user)):
    if user.role != "doctor":
        raise HTTPException(status_code=403, detail="Forbidden")
    items = list(db["assessment"].find({"assigned_doctor_id": user.id}).sort("created_at", -1))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


@app.get("/schema")
def get_schema_overview():
    # For the viewer/debugger
    return {
        "collections": [
            "user", "hospital", "doctor", "assessment", "appointment", "therapyplan", "message", "testimonial"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
