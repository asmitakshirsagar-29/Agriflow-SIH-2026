# agriflow_procurement.py
import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import (
    create_engine, String, Integer, DateTime, ForeignKey, Text,
    Numeric, Boolean, select, func
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session, sessionmaker
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://postgres:postgres@localhost:5432/agriflow"
)
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "480"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is missing. Put it in your .env file.")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
ph = PasswordHasher()

class Base(DeclarativeBase):
    pass

class Role(str, Enum):
    FARMER = "FARMER"
    ADMIN = "ADMIN"

class RequestStatus(str, Enum):
    SUBMITTED = "SUBMITTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    SCHEDULED = "SCHEDULED"
    READY_FOR_PROCUREMENT = "READY_FOR_PROCUREMENT"
    PROCURED = "PROCURED"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(150))
    mobile: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(500))
    state: Mapped[str] = mapped_column(String(100))
    district: Mapped[str] = mapped_column(String(100))
    village: Mapped[str] = mapped_column(String(200))
    farmer_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    role: Mapped[str] = mapped_column(String(20), default=Role.FARMER.value, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    requests: Mapped[list["ProcurementRequest"]] = relationship(back_populates="farmer")

class ProcurementCenter(Base):
    __tablename__ = "procurement_centers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    district: Mapped[str] = mapped_column(String(100), index=True)
    address: Mapped[str] = mapped_column(String(300))
    active: Mapped[bool] = mapped_column(Boolean, default=True)

class ProcurementSchedule(Base):
    __tablename__ = "procurement_schedules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    center_id: Mapped[int] = mapped_column(ForeignKey("procurement_centers.id", ondelete="CASCADE"), index=True)
    crop: Mapped[str] = mapped_column(String(100), index=True)
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    time_window: Mapped[str] = mapped_column(String(100))
    capacity_kg: Mapped[float] = mapped_column(Numeric(12, 2))
    status: Mapped[str] = mapped_column(String(30), default="OPEN", index=True)
    center: Mapped["ProcurementCenter"] = relationship()

class ProcurementRequest(Base):
    __tablename__ = "procurement_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    farmer_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    crop: Mapped[str] = mapped_column(String(100), index=True)
    quantity_kg: Mapped[float] = mapped_column(Numeric(12, 2))
    center_id: Mapped[int] = mapped_column(ForeignKey("procurement_centers.id"), index=True)
    schedule_id: Mapped[Optional[int]] = mapped_column(ForeignKey("procurement_schedules.id"), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(40), default=RequestStatus.SUBMITTED.value, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    farmer: Mapped["User"] = relationship(back_populates="requests")
    center: Mapped["ProcurementCenter"] = relationship()
    schedule: Mapped[Optional["ProcurementSchedule"]] = relationship()

class FarmerCheckIn(Base):
    __tablename__ = "farmer_checkins"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(
        ForeignKey("procurement_requests.id", ondelete="CASCADE"),
        unique=True,
        index=True
    )
    checked_in_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

class StatusHistory(Base):
    __tablename__ = "procurement_status_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("procurement_requests.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(40))
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text)
    read: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class RegisterIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    mobile: str = Field(min_length=10, max_length=20)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    state: str = Field(min_length=2, max_length=100)
    district: str = Field(min_length=2, max_length=100)
    village: str = Field(min_length=2, max_length=200)
    farmer_id: Optional[str] = Field(default=None, max_length=100)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class RequestCreate(BaseModel):
    crop: str = Field(min_length=2, max_length=100)
    quantity_kg: float = Field(gt=0, le=10000000)
    center_id: int
    schedule_id: Optional[int] = None
    details: Optional[str] = Field(default=None, max_length=1500)

class StatusUpdate(BaseModel):
    status: RequestStatus
    note: Optional[str] = Field(default=None, max_length=1000)
    schedule_id: Optional[int] = None

class CenterCreate(BaseModel):
    name: str
    district: str
    address: str

class ScheduleCreate(BaseModel):
    center_id: int
    crop: str
    scheduled_at: datetime
    time_window: str
    capacity_kg: float = Field(gt=0)
    status: str = "OPEN"

app = FastAPI(title="AgriFlow Procurement Platform", version="1.0.0")

def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

def make_token(user: User):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(request: Request, session: Session = Depends(db)) -> User:
    token = request.cookies.get("agriflow_token")
    if not token:
        raise HTTPException(401, "Authentication required")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        uid = int(payload["sub"])
    except Exception:
        raise HTTPException(401, "Invalid or expired session")
    user = session.get(User, uid)
    if not user:
        raise HTTPException(401, "User not found")
    return user

def admin_only(user: User = Depends(get_current_user)):
    if user.role != Role.ADMIN.value:
        raise HTTPException(403, "Admin access required")
    return user

def serialize_user(u: User):
    return {
        "id": u.id, "full_name": u.full_name, "mobile": u.mobile,
        "email": u.email, "state": u.state, "district": u.district,
        "village": u.village, "farmer_id": u.farmer_id, "role": u.role
    }

def serialize_request(r: ProcurementRequest):
    return {
        "id": r.id,
        "crop": r.crop,
        "quantity_kg": float(r.quantity_kg),
        "status": r.status,
        "details": r.details,
        "created_at": r.created_at.isoformat(),
        "updated_at": r.updated_at.isoformat(),
        "center": {"id": r.center.id, "name": r.center.name, "district": r.center.district},
        "schedule": None if not r.schedule else {
            "id": r.schedule.id,
            "scheduled_at": r.schedule.scheduled_at.isoformat(),
            "time_window": r.schedule.time_window,
            "status": r.schedule.status
        },
        "farmer": {"id": r.farmer.id, "full_name": r.farmer.full_name, "district": r.farmer.district}
    }

def add_notification(session: Session, user_id: int, title: str, message: str):
    session.add(Notification(user_id=user_id, title=title, message=message))


def calculate_queue_metrics(session: Session, schedule: ProcurementSchedule):
    active_statuses = [
        RequestStatus.SCHEDULED.value,
        RequestStatus.READY_FOR_PROCUREMENT.value,
        RequestStatus.PROCURED.value,
    ]

    requests = session.scalars(
        select(ProcurementRequest).where(
            ProcurementRequest.schedule_id == schedule.id,
            ProcurementRequest.status.in_(active_statuses)
        )
    ).all()

    farmer_count = len(requests)
    booked_kg = sum(float(r.quantity_kg) for r in requests)
    capacity_kg = float(schedule.capacity_kg)
    remaining_capacity_kg = max(capacity_kg - booked_kg, 0)

    utilization = booked_kg / capacity_kg if capacity_kg > 0 else 1
    utilization_percent = round(utilization * 100, 1)

    base_wait = farmer_count * 8

    if utilization < 0.50:
        congestion = "LOW"
        predicted_wait_minutes = round(base_wait * 0.6)
    elif utilization < 0.80:
        congestion = "MODERATE"
        predicted_wait_minutes = round(base_wait)
    elif utilization <= 1.00:
        congestion = "HIGH"
        predicted_wait_minutes = round(base_wait * 1.5)
    else:
        congestion = "OVERLOADED"
        overload = utilization - 1
        predicted_wait_minutes = round(base_wait * (1.5 + overload))

    return {
        "farmers_scheduled": farmer_count,
        "booked_kg": round(booked_kg, 2),
        "capacity_kg": round(capacity_kg, 2),
        "remaining_capacity_kg": round(remaining_capacity_kg, 2),
        "utilization_percent": utilization_percent,
        "congestion": congestion,
        "predicted_wait_minutes": max(predicted_wait_minutes, 0)
    }

    

@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    with SessionLocal() as session:
        if session.scalar(select(func.count()).select_from(ProcurementCenter)) == 0:
            session.add_all([
                ProcurementCenter(name="Gangakhed Agricultural Procurement Center", district="Parbhani", address="Gangakhed, Parbhani, Maharashtra"),
                ProcurementCenter(name="Nanded Market Procurement Center", district="Nanded", address="Nanded, Maharashtra"),
            ])
            session.commit()

        if ADMIN_EMAIL and ADMIN_PASSWORD:
            existing = session.scalar(select(User).where(User.email == ADMIN_EMAIL.lower()))
            if not existing:
                session.add(User(
                    full_name="Procurement Officer",
                    mobile="9999999999",
                    email=ADMIN_EMAIL.lower(),
                    password_hash=ph.hash(ADMIN_PASSWORD),
                    state="Maharashtra",
                    district="Administration",
                    village="Head Office",
                    role=Role.ADMIN.value
                ))
                session.commit()

@app.get("/", response_class=HTMLResponse)
def home():
    return HTML

@app.post("/api/auth/register")
def register(body: RegisterIn, response: Response, session: Session = Depends(db)):
    email = body.email.lower().strip()
    if session.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Email already registered")
    if session.scalar(select(User).where(User.mobile == body.mobile.strip())):
        raise HTTPException(409, "Mobile number already registered")
    user = User(
        full_name=body.full_name.strip(),
        mobile=body.mobile.strip(),
        email=email,
        password_hash=ph.hash(body.password),
        state=body.state.strip(),
        district=body.district.strip(),
        village=body.village.strip(),
        farmer_id=(body.farmer_id or "").strip() or None,
        role=Role.FARMER.value
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    token = make_token(user)
    response.set_cookie("agriflow_token", token, httponly=True, samesite="lax", secure=COOKIE_SECURE, max_age=ACCESS_TOKEN_MINUTES * 60)
    return {"user": serialize_user(user)}

@app.post("/api/auth/login")
def login(body: LoginIn, response: Response, session: Session = Depends(db)):
    user = session.scalar(select(User).where(User.email == body.email.lower().strip()))
    if not user:
        raise HTTPException(401, "Invalid email or password")
    try:
        ph.verify(user.password_hash, body.password)
    except VerifyMismatchError:
        raise HTTPException(401, "Invalid email or password")
    token = make_token(user)
    response.set_cookie("agriflow_token", token, httponly=True, samesite="lax", secure=COOKIE_SECURE, max_age=ACCESS_TOKEN_MINUTES * 60)
    return {"user": serialize_user(user)}

@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("agriflow_token")
    return {"ok": True}

@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    return serialize_user(user)

@app.get("/api/centers")
def centers(session: Session = Depends(db)):
    rows = session.scalars(select(ProcurementCenter).where(ProcurementCenter.active == True).order_by(ProcurementCenter.name)).all()
    return [{"id": c.id, "name": c.name, "district": c.district, "address": c.address} for c in rows]

@app.get("/api/schedules")
def schedules(session: Session = Depends(db)):
    rows = session.scalars(
        select(ProcurementSchedule)
        .where(ProcurementSchedule.scheduled_at >= datetime.now(timezone.utc) - timedelta(days=1))
        .order_by(ProcurementSchedule.scheduled_at)
    ).all()
    return [{
        "id": s.id, "crop": s.crop, "scheduled_at": s.scheduled_at.isoformat(),
        "time_window": s.time_window, "capacity_kg": float(s.capacity_kg),
        "status": s.status,
        "center": {"id": s.center.id, "name": s.center.name, "district": s.center.district},
        "queue": calculate_queue_metrics(session, s)
    } for s in rows]

@app.post("/api/requests")
def create_request(body: RequestCreate, user: User = Depends(get_current_user), session: Session = Depends(db)):
    if user.role != Role.FARMER.value:
        raise HTTPException(403, "Only farmer accounts can create procurement requests")
    center = session.get(ProcurementCenter, body.center_id)
    if not center or not center.active:
        raise HTTPException(404, "Procurement center not found")
    schedule = None
    if body.schedule_id:
        schedule = session.get(ProcurementSchedule, body.schedule_id)
        if not schedule or schedule.center_id != center.id:
            raise HTTPException(400, "Selected schedule does not belong to selected center")

    r = ProcurementRequest(
        farmer_id=user.id,
        crop=body.crop.strip(),
        quantity_kg=body.quantity_kg,
        center_id=center.id,
        schedule_id=schedule.id if schedule else None,
        details=(body.details or "").strip() or None,
        status=RequestStatus.SUBMITTED.value
    )
    session.add(r)
    session.flush()
    session.add(StatusHistory(request_id=r.id, status=r.status, note="Procurement request submitted"))
    add_notification(session, user.id, "Request submitted", f"Your {r.crop} procurement request #{r.id} was submitted successfully.")
    session.commit()
    session.refresh(r)
    return serialize_request(r)

@app.get("/api/requests")
def my_requests(user: User = Depends(get_current_user), session: Session = Depends(db)):
    q = select(ProcurementRequest).order_by(ProcurementRequest.created_at.desc())
    if user.role != Role.ADMIN.value:
        q = q.where(ProcurementRequest.farmer_id == user.id)
    return [serialize_request(r) for r in session.scalars(q).all()]

@app.get("/api/requests/{request_id}")
def request_detail(request_id: int, user: User = Depends(get_current_user), session: Session = Depends(db)):
    r = session.get(ProcurementRequest, request_id)
    if not r:
        raise HTTPException(404, "Request not found")
    if user.role != Role.ADMIN.value and r.farmer_id != user.id:
        raise HTTPException(403, "You cannot access another farmer's request")
    histories = session.scalars(
        select(StatusHistory).where(StatusHistory.request_id == r.id).order_by(StatusHistory.changed_at)
    ).all()
    out = serialize_request(r)
    out["history"] = [{
        "status": h.status, "note": h.note, "changed_at": h.changed_at.isoformat()
    } for h in histories]
    return out


@app.get("/api/requests/{request_id}/queue")
def request_queue(
    request_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(db)
):
    from datetime import timedelta

    r = session.get(ProcurementRequest, request_id)

    if not r:
        raise HTTPException(404, "Request not found")

    # Farmers can only view their own queue information.
    # Admin/officer can view any request.
    if user.role != "ADMIN" and r.farmer_id != user.id:
        raise HTTPException(403, "Not allowed")

    if not r.schedule_id or not r.schedule:
        return {
            "available": False,
            "message": "Queue token will be generated after a schedule is assigned."
        }

    active_statuses = [
        RequestStatus.SCHEDULED.value,
        RequestStatus.READY_FOR_PROCUREMENT.value,
        RequestStatus.PROCURED.value,
    ]

    queue = session.scalars(
        select(ProcurementRequest)
        .where(
            ProcurementRequest.schedule_id == r.schedule_id,
            ProcurementRequest.status.in_(active_statuses)
        )
        .order_by(
            ProcurementRequest.created_at.asc(),
            ProcurementRequest.id.asc()
        )
    ).all()

    queue_ids = [item.id for item in queue]

    if r.id not in queue_ids:
        return {
            "available": False,
            "message": "This request is no longer in the active procurement queue."
        }

    position = queue_ids.index(r.id) + 1
    farmers_ahead = position - 1

    # Initial service-time model: approximately 5 minutes per farmer.
    service_minutes = 5
    estimated_service = (
        r.schedule.scheduled_at +
        timedelta(minutes=farmers_ahead * service_minutes)
    )

    token = f"AF-{r.schedule_id:03d}-{position:03d}"

    return {
        "available": True,
        "token": token,
        "queue_position": position,
        "farmers_ahead": farmers_ahead,
        "total_in_queue": len(queue),
        "estimated_service_time": estimated_service.isoformat(),
        "estimated_wait_minutes": farmers_ahead * service_minutes,
        "schedule_id": r.schedule_id,
        "center": r.center.name,
        "scheduled_at": r.schedule.scheduled_at.isoformat(),
        "time_window": r.schedule.time_window
    }


@app.post("/api/requests/{request_id}/check-in")
def farmer_check_in(
    request_id: int,
    user: User = Depends(get_current_user),
    session: Session = Depends(db)
):
    r = session.get(ProcurementRequest, request_id)

    if not r:
        raise HTTPException(404, "Request not found")

    if user.role == Role.ADMIN.value:
        raise HTTPException(403, "Only farmers can check in")

    if r.farmer_id != user.id:
        raise HTTPException(403, "You cannot check in another farmer's request")

    if not r.schedule_id:
        raise HTTPException(400, "A procurement schedule must be assigned before check-in")

    allowed_statuses = [
        RequestStatus.SCHEDULED.value,
        RequestStatus.READY_FOR_PROCUREMENT.value,
    ]

    if r.status not in allowed_statuses:
        raise HTTPException(400, "This request is not currently eligible for check-in")

    existing = session.scalar(
        select(FarmerCheckIn).where(FarmerCheckIn.request_id == r.id)
    )

    if existing:
        return {
            "success": True,
            "already_checked_in": True,
            "checked_in_at": existing.checked_in_at.isoformat()
        }

    checkin = FarmerCheckIn(request_id=r.id)
    session.add(checkin)
    session.commit()
    session.refresh(checkin)

    return {
        "success": True,
        "already_checked_in": False,
        "checked_in_at": checkin.checked_in_at.isoformat()
    }


@app.get("/api/admin/live-queue")
def admin_live_queue(
    user: User = Depends(get_current_user),
    session: Session = Depends(db)
):
    if user.role != Role.ADMIN.value:
        raise HTTPException(403, "Admin access required")

    checkins = session.scalars(
        select(FarmerCheckIn).order_by(FarmerCheckIn.checked_in_at.asc())
    ).all()

    rows = []

    for c in checkins:
        r = session.get(ProcurementRequest, c.request_id)

        if not r:
            continue

        if r.status in [
            RequestStatus.COMPLETED.value,
            RequestStatus.REJECTED.value,
            RequestStatus.CANCELLED.value,
        ]:
            continue

        position = len(rows) + 1

        rows.append({
            "request_id": r.id,
            "farmer_name": r.farmer.full_name,
            "crop": r.crop,
            "quantity_kg": float(r.quantity_kg),
            "center": r.center.name,
            "schedule_id": r.schedule_id,
            "token": f"AF-{r.schedule_id:03d}-{position:03d}" if r.schedule_id else None,
            "queue_position": position,
            "checked_in_at": c.checked_in_at.isoformat(),
            "status": r.status
        })

    return rows


@app.get("/api/notifications")
def notifications(user: User = Depends(get_current_user), session: Session = Depends(db)):
    rows = session.scalars(
        select(Notification).where(Notification.user_id == user.id).order_by(Notification.created_at.desc()).limit(50)
    ).all()
    return [{
        "id": n.id, "title": n.title, "message": n.message,
        "read": n.read, "created_at": n.created_at.isoformat()
    } for n in rows]

@app.post("/api/notifications/{notification_id}/read")
def mark_read(notification_id: int, user: User = Depends(get_current_user), session: Session = Depends(db)):
    n = session.get(Notification, notification_id)
    if not n or n.user_id != user.id:
        raise HTTPException(404, "Notification not found")
    n.read = True
    session.commit()
    return {"ok": True}

@app.get("/api/dashboard")
def dashboard(user: User = Depends(get_current_user), session: Session = Depends(db)):
    q = select(ProcurementRequest)
    if user.role != Role.ADMIN.value:
        q = q.where(ProcurementRequest.farmer_id == user.id)
    rows = session.scalars(q).all()
    statuses = {}
    for r in rows:
        statuses[r.status] = statuses.get(r.status, 0) + 1
    upcoming = session.scalars(
        select(ProcurementSchedule)
        .where(ProcurementSchedule.scheduled_at >= datetime.now(timezone.utc))
        .order_by(ProcurementSchedule.scheduled_at)
        .limit(5)
    ).all()
    return {
        "total_requests": len(rows),
        "status_counts": statuses,
        "upcoming_schedules": [{
            "id": s.id, "crop": s.crop, "scheduled_at": s.scheduled_at.isoformat(),
            "time_window": s.time_window, "center": s.center.name
        } for s in upcoming],
        "recent_requests": [serialize_request(r) for r in sorted(rows, key=lambda x: x.created_at, reverse=True)[:5]]
    }

@app.get("/api/admin/requests")
def admin_requests(
    status: Optional[str] = None,
    crop: Optional[str] = None,
    district: Optional[str] = None,
    _: User = Depends(admin_only),
    session: Session = Depends(db)
):
    q = select(ProcurementRequest).order_by(ProcurementRequest.created_at.desc())
    if status:
        q = q.where(ProcurementRequest.status == status)
    if crop:
        q = q.where(ProcurementRequest.crop.ilike(f"%{crop}%"))
    rows = session.scalars(q).all()
    if district:
        rows = [r for r in rows if r.farmer.district.lower() == district.lower()]
    return [serialize_request(r) for r in rows]

@app.patch("/api/admin/requests/{request_id}/status")
def update_status(
    request_id: int,
    body: StatusUpdate,
    _: User = Depends(admin_only),
    session: Session = Depends(db)
):
    r = session.get(ProcurementRequest, request_id)
    if not r:
        raise HTTPException(404, "Request not found")
    if body.schedule_id is not None:
        schedule = session.get(ProcurementSchedule, body.schedule_id)
        if not schedule:
            raise HTTPException(404, "Schedule not found")
        r.schedule_id = schedule.id
    r.status = body.status.value
    r.updated_at = datetime.now(timezone.utc)
    session.add(StatusHistory(request_id=r.id, status=r.status, note=body.note))
    add_notification(session, r.farmer_id, "Procurement status updated", f"Request #{r.id} is now {r.status.replace('_', ' ').title()}.")
    session.commit()
    return serialize_request(r)

@app.post("/api/admin/centers")
def create_center(body: CenterCreate, _: User = Depends(admin_only), session: Session = Depends(db)):
    c = ProcurementCenter(name=body.name.strip(), district=body.district.strip(), address=body.address.strip())
    session.add(c)
    session.commit()
    session.refresh(c)
    return {"id": c.id, "name": c.name, "district": c.district, "address": c.address}

@app.post("/api/admin/schedules")
def create_schedule(body: ScheduleCreate, _: User = Depends(admin_only), session: Session = Depends(db)):
    center = session.get(ProcurementCenter, body.center_id)
    if not center:
        raise HTTPException(404, "Center not found")
    s = ProcurementSchedule(
        center_id=body.center_id,
        crop=body.crop.strip(),
        scheduled_at=body.scheduled_at,
        time_window=body.time_window.strip(),
        capacity_kg=body.capacity_kg,
        status=body.status.strip().upper()
    )
    session.add(s)
    session.commit()
    session.refresh(s)
    return {"id": s.id}

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgriFlow Procurement</title>
<style>
:root{--bg:#f6f8f7;--card:#fff;--text:#122019;--muted:#647067;--brand:#1f7a4c;--brand2:#155d3a;--line:#dfe7e2;--danger:#b42318;--warn:#9a6700;--shadow:0 12px 32px rgba(16,24,20,.08)}
body.dark{--bg:#0e1512;--card:#15201b;--text:#e8f2ec;--muted:#9fb0a6;--brand:#44c07a;--brand2:#2b9c60;--line:#293a31;--shadow:0 12px 32px rgba(0,0,0,.25)}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}button,input,select,textarea{font:inherit}
a{color:inherit}.container{width:min(1160px,92%);margin:auto}.nav{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
.navin{height:68px;display:flex;align-items:center;justify-content:space-between;gap:18px}.brand{font-weight:800;font-size:21px}.brand span{color:var(--brand)}.actions{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.btn{border:1px solid var(--line);background:var(--card);color:var(--text);padding:10px 14px;border-radius:10px;cursor:pointer;font-weight:650}.btn:hover{transform:translateY(-1px)}.btn.primary{background:var(--brand);color:white;border-color:var(--brand)}.btn.danger{color:#fff;background:var(--danger);border-color:var(--danger)}
.hero{padding:86px 0 64px;display:grid;grid-template-columns:1.2fr .8fr;gap:48px;align-items:center}.kicker{color:var(--brand);font-weight:800;letter-spacing:.08em;text-transform:uppercase;font-size:13px}.hero h1{font-size:clamp(38px,6vw,70px);line-height:1.02;margin:13px 0 18px;letter-spacing:-.04em}.hero p{font-size:18px;color:var(--muted);line-height:1.7}
.heroCard,.card{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow)}.heroCard{padding:24px}.steps{display:grid;gap:12px}.step{display:flex;gap:14px;padding:13px;border-radius:12px;background:var(--bg)}.num{width:34px;height:34px;border-radius:50%;display:grid;place-items:center;background:var(--brand);color:white;font-weight:800}
.section{padding:42px 0}.section h2{font-size:30px;margin:0 0 8px}.muted{color:var(--muted)}.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.card{padding:20px}.card h3{margin-top:0}
.authwrap{max-width:560px;margin:44px auto}.form{display:grid;gap:13px}.field label{display:block;font-size:13px;font-weight:700;margin-bottom:6px}.field input,.field select,.field textarea{width:100%;padding:12px;border-radius:9px;border:1px solid var(--line);background:var(--bg);color:var(--text);outline:none}.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--brand)}
.app{padding:28px 0 60px}.topline{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:20px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.stat{padding:18px}.stat b{font-size:30px;display:block;margin-top:8px}.layout{display:grid;grid-template-columns:1.35fr .65fr;gap:16px;margin-top:16px}
.tablewrap{overflow:auto}.table{width:100%;border-collapse:collapse;min-width:760px}.table th,.table td{text-align:left;padding:12px;border-bottom:1px solid var(--line);font-size:14px}.badge{display:inline-flex;padding:5px 9px;border-radius:999px;background:var(--bg);border:1px solid var(--line);font-size:12px;font-weight:800}.timeline{border-left:2px solid var(--line);padding-left:18px}.event{position:relative;padding:0 0 18px}.event:before{content:"";position:absolute;left:-24px;top:4px;width:10px;height:10px;border-radius:50%;background:var(--brand)}
.notice{padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);margin:8px 0}.toast{position:fixed;right:18px;bottom:18px;max-width:360px;padding:13px 16px;background:var(--text);color:var(--bg);border-radius:10px;z-index:50;box-shadow:var(--shadow)}.hidden{display:none!important}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.48);display:grid;place-items:center;padding:18px;z-index:40}.modalbox{width:min(620px,100%);max-height:90vh;overflow:auto;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px}
.footer{border-top:1px solid var(--line);padding:28px 0;color:var(--muted);margin-top:30px}
@media(max-width:850px){.hero,.layout{grid-template-columns:1fr}.grid3,.stats{grid-template-columns:repeat(2,1fr)}.hero{padding-top:45px}.navin{height:auto;padding:12px 0;align-items:flex-start}}
@media(max-width:540px){.grid3,.stats{grid-template-columns:1fr}.actions{gap:6px}.btn{padding:9px 10px}.hero h1{font-size:42px}}
</style>
</head>
<body>
<div id="nav"></div>
<main id="root"></main>
<div id="modal" class="hidden"></div>
<script>
const root=document.getElementById('root'), nav=document.getElementById('nav'), modal=document.getElementById('modal');
let currentUser=null;
const qs=s=>document.querySelector(s);
const fmt=d=>new Date(d).toLocaleString();
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
const displayCropName=value=>{
  const crop=String(value??'').trim();
  if(crop.toLowerCase()==='soyabean' || crop.toLowerCase()==='soybean') return 'Soybean';
  return crop ? crop.charAt(0).toUpperCase()+crop.slice(1).toLowerCase() : '';
};
function toast(msg){let e=document.createElement('div');e.className='toast';e.textContent=msg;document.body.appendChild(e);setTimeout(()=>e.remove(),3000)}
async function api(url,opts={}){opts.headers={...(opts.body?{'Content-Type':'application/json'}:{}),...(opts.headers||{})};let r=await fetch(url,{credentials:'include',...opts});let data=null;try{data=await r.json()}catch{} if(!r.ok)throw new Error(data?.detail||'Request failed');return data}
const translations = {
  en: {
    dashboard: "Dashboard",
    logout: "Logout",
    new_request: "New Request",
    total_requests: "Total requests",
    active: "Active",
    completed: "Completed",
    unread_alerts: "Unread alerts",
    your_journey: "Your Procurement Journey",
    procurement_completed: "Procurement completed",
    no_action: "Your procurement process is complete. No further action is required.",
    your_requests: "Your procurement requests",
    upcoming_schedules: "Upcoming procurement schedules",
    notifications: "Notifications"
  },
  mr: {
    dashboard: "डॅशबोर्ड",
    logout: "लॉगआउट",
    new_request: "नवीन विनंती",
    total_requests: "एकूण विनंत्या",
    active: "सक्रिय",
    completed: "पूर्ण",
    unread_alerts: "न वाचलेल्या सूचना",
    your_journey: "तुमचा खरेदी प्रवास",
    procurement_completed: "खरेदी प्रक्रिया पूर्ण",
    no_action: "तुमची खरेदी प्रक्रिया पूर्ण झाली आहे. पुढील कृती आवश्यक नाही.",
    your_requests: "तुमच्या खरेदी विनंत्या",
    upcoming_schedules: "आगामी खरेदी वेळापत्रक",
    notifications: "सूचना"
  },
  hi: {
    dashboard: "डैशबोर्ड",
    logout: "लॉगआउट",
    new_request: "नई अनुरोध",
    total_requests: "कुल अनुरोध",
    active: "सक्रिय",
    completed: "पूर्ण",
    unread_alerts: "अपठित सूचनाएँ",
    your_journey: "आपकी खरीद यात्रा",
    procurement_completed: "खरीद प्रक्रिया पूर्ण",
    no_action: "आपकी खरीद प्रक्रिया पूरी हो गई है। आगे कोई कार्रवाई आवश्यक नहीं है।",
    your_requests: "आपके खरीद अनुरोध",
    upcoming_schedules: "आगामी खरीद समय-सारणी",
    notifications: "सूचनाएँ"
  }
};

let currentLang = localStorage.getItem("agriflow_lang") || "en";

function t(key){
  return translations[currentLang]?.[key] || translations.en[key] || key;
}

function setLanguage(lang){
  currentLang = lang;
  localStorage.setItem("agriflow_lang", lang);
  renderNav();
  route();
}


const pageText = {
 en:{
  dark:"Dark", light:"Light",
  dashboard:"Dashboard", logout:"Logout",
  kicker:"Transparent farmer procurement",
  hero:"Know your procurement status before you reach the center.",
  intro:"AgriFlow gives farmers a secure way to submit procurement requests, view upcoming schedules, track approvals and receive status notifications from procurement officers.",
  register_farmer:"Register as Farmer", login:"Login",
  how:"How procurement works",
  register:"Register", register_desc:"Create a verified farmer account.",
  submit:"Submit request", submit_desc:"Choose crop, quantity and center.",
  scheduled:"Get scheduled", scheduled_desc:"Officer assigns or confirms the slot.",
  track:"Track completion", track_desc:"Follow every status change.",
  clarity:"Built for clarity",
  clarity_desc:"Your dashboard reflects the records stored in the database.",
  visibility:"Schedule visibility",
  visibility_desc:"See center, crop, date, time window and available procurement capacity.",
  status_tracking:"Status tracking",
  status_desc:"View a real timeline from submission through procurement and completion.",
  alerts:"Persistent alerts",
  alerts_desc:"Notifications are stored in the backend rather than disappearing after refresh."
 },
 mr:{
  dark:"डार्क", light:"लाईट",
  dashboard:"डॅशबोर्ड", logout:"लॉगआउट",
  kicker:"पारदर्शक शेतकरी खरेदी व्यवस्था",
  hero:"खरेदी केंद्रावर पोहोचण्यापूर्वी तुमच्या खरेदी विनंतीची स्थिती जाणून घ्या.",
  intro:"AgriFlow द्वारे शेतकरी खरेदी विनंती सादर करू शकतात, वेळापत्रक पाहू शकतात, मंजुरीची स्थिती तपासू शकतात आणि खरेदी अधिकाऱ्यांकडून सूचना मिळवू शकतात.",
  register_farmer:"शेतकरी नोंदणी", login:"लॉगिन",
  how:"खरेदी प्रक्रिया कशी चालते",
  register:"नोंदणी", register_desc:"शेतकरी खाते तयार करा.",
  submit:"विनंती सादर करा", submit_desc:"पीक, प्रमाण आणि केंद्र निवडा.",
  scheduled:"वेळ निश्चित करा", scheduled_desc:"अधिकारी खरेदीची वेळ निश्चित करतो.",
  track:"स्थिती तपासा", track_desc:"प्रत्येक टप्प्याची स्थिती पाहा.",
  clarity:"स्पष्ट आणि सोपी माहिती",
  clarity_desc:"डॅशबोर्डमध्ये डेटाबेसमधील वास्तविक माहिती दिसते.",
  visibility:"वेळापत्रकाची माहिती",
  visibility_desc:"केंद्र, पीक, तारीख, वेळ आणि उपलब्ध क्षमता पाहा.",
  status_tracking:"स्थिती ट्रॅकिंग",
  status_desc:"विनंतीपासून खरेदी पूर्ण होईपर्यंत सर्व टप्पे पाहा.",
  alerts:"कायम सूचना",
  alerts_desc:"सूचना रिफ्रेश केल्यानंतरही उपलब्ध राहतात."
 },
 hi:{
  dark:"डार्क", light:"लाइट",
  dashboard:"डैशबोर्ड", logout:"लॉगआउट",
  kicker:"पारदर्शी किसान खरीद व्यवस्था",
  hero:"खरीद केंद्र पहुँचने से पहले अपनी खरीद अनुरोध की स्थिति जानें।",
  intro:"AgriFlow किसानों को खरीद अनुरोध जमा करने, समय-सारणी देखने, मंजूरी की स्थिति जांचने और खरीद अधिकारियों से सूचनाएँ प्राप्त करने की सुविधा देता है।",
  register_farmer:"किसान पंजीकरण", login:"लॉगिन",
  how:"खरीद प्रक्रिया कैसे काम करती है",
  register:"पंजीकरण", register_desc:"किसान खाता बनाएं।",
  submit:"अनुरोध जमा करें", submit_desc:"फसल, मात्रा और केंद्र चुनें।",
  scheduled:"समय निर्धारित करें", scheduled_desc:"अधिकारी खरीद का समय निर्धारित करता है।",
  track:"स्थिति देखें", track_desc:"हर चरण की स्थिति देखें।",
  clarity:"स्पष्ट और सरल जानकारी",
  clarity_desc:"डैशबोर्ड डेटाबेस में मौजूद वास्तविक जानकारी दिखाता है।",
  visibility:"समय-सारणी की जानकारी",
  visibility_desc:"केंद्र, फसल, तारीख, समय और उपलब्ध क्षमता देखें।",
  status_tracking:"स्थिति ट्रैकिंग",
  status_desc:"अनुरोध से खरीद पूरी होने तक सभी चरण देखें।",
  alerts:"स्थायी सूचनाएँ",
  alerts_desc:"रिफ्रेश के बाद भी सूचनाएँ उपलब्ध रहती हैं।"
 }
};

function pt(key){
 return pageText[currentLang]?.[key] || pageText.en[key] || key;
}


const dashboardText = {
  en:{
    officer_dashboard:"Procurement Officer Dashboard",
    farmer_dashboard:"Farmer Procurement Dashboard",
    total_requests:"Total requests",
    active:"Active",
    completed:"Completed",
    unread_alerts:"Unread alerts",
    ops_snapshot:"Upcoming Operations Snapshot",
    live_summary:"Live summary from current procurement records",
    scheduled_farmers:"Scheduled farmers",
    booked_quantity:"Booked quantity",
    remaining_capacity:"Remaining capacity",
    estimated_wait:"Estimated wait",
    queue_status:"Queue status",
    upcoming_slots:"Upcoming slots",
    total_capacity:"Total capacity",
    all_requests:"All procurement requests",
    your_requests:"Your procurement requests",
    farmer:"Farmer",
    crop:"Crop",
    quantity:"Quantity",
    center:"Center",
    status:"Status",
    manage:"Manage",
    track:"Track",
    upcoming_schedules:"Upcoming procurement schedules",
    date:"Date",
    window:"Window",
    capacity:"Capacity",
    queue:"Queue",
    est_wait:"Est. Wait",
    notifications:"Notifications",
    no_notifications:"No notifications yet.",
    no_schedules:"No upcoming schedules have been published."
  },

  mr:{
    officer_dashboard:"खरेदी अधिकारी डॅशबोर्ड",
    farmer_dashboard:"शेतकरी खरेदी डॅशबोर्ड",
    total_requests:"एकूण विनंत्या",
    active:"सक्रिय",
    completed:"पूर्ण",
    unread_alerts:"न वाचलेल्या सूचना",
    ops_snapshot:"आगामी खरेदी कामकाज",
    live_summary:"सध्याच्या खरेदी नोंदींवर आधारित थेट सारांश",
    scheduled_farmers:"नियोजित शेतकरी",
    booked_quantity:"नोंदवलेले प्रमाण",
    remaining_capacity:"उर्वरित क्षमता",
    estimated_wait:"अंदाजे प्रतीक्षा वेळ",
    queue_status:"रांगेची स्थिती",
    upcoming_slots:"आगामी वेळा",
    total_capacity:"एकूण क्षमता",
    all_requests:"सर्व खरेदी विनंत्या",
    your_requests:"तुमच्या खरेदी विनंत्या",
    farmer:"शेतकरी",
    crop:"पीक",
    quantity:"प्रमाण",
    center:"केंद्र",
    status:"स्थिती",
    manage:"व्यवस्थापन",
    track:"पहा",
    upcoming_schedules:"आगामी खरेदी वेळापत्रक",
    date:"तारीख",
    window:"वेळ",
    capacity:"क्षमता",
    queue:"रांग",
    est_wait:"अंदाजे प्रतीक्षा",
    notifications:"सूचना",
    no_notifications:"सध्या कोणतीही सूचना नाही.",
    no_schedules:"सध्या कोणतेही आगामी खरेदी वेळापत्रक उपलब्ध नाही."
  },

  hi:{
    officer_dashboard:"खरीद अधिकारी डैशबोर्ड",
    farmer_dashboard:"किसान खरीद डैशबोर्ड",
    total_requests:"कुल अनुरोध",
    active:"सक्रिय",
    completed:"पूर्ण",
    unread_alerts:"अपठित सूचनाएँ",
    ops_snapshot:"आगामी खरीद संचालन",
    live_summary:"वर्तमान खरीद रिकॉर्ड पर आधारित लाइव सारांश",
    scheduled_farmers:"निर्धारित किसान",
    booked_quantity:"बुक की गई मात्रा",
    remaining_capacity:"शेष क्षमता",
    estimated_wait:"अनुमानित प्रतीक्षा",
    queue_status:"कतार की स्थिति",
    upcoming_slots:"आगामी स्लॉट",
    total_capacity:"कुल क्षमता",
    all_requests:"सभी खरीद अनुरोध",
    your_requests:"आपके खरीद अनुरोध",
    farmer:"किसान",
    crop:"फसल",
    quantity:"मात्रा",
    center:"केंद्र",
    status:"स्थिति",
    manage:"प्रबंधन",
    track:"देखें",
    upcoming_schedules:"आगामी खरीद समय-सारणी",
    date:"तारीख",
    window:"समय",
    capacity:"क्षमता",
    queue:"कतार",
    est_wait:"अनुमानित प्रतीक्षा",
    notifications:"सूचनाएँ",
    no_notifications:"अभी कोई सूचना नहीं है.",
    no_schedules:"अभी कोई आगामी खरीद समय-सारणी उपलब्ध नहीं है."
  }
};

function dt(key){
  return dashboardText[currentLang]?.[key] || dashboardText.en[key] || key;
}

function setTheme(t){document.body.classList.toggle('dark',t==='dark');localStorage.setItem('theme',t);renderNav()}
setTheme(localStorage.getItem('theme')||'light');
function renderNav(){
 nav.innerHTML=`<div class="nav"><div class="container navin">
 <div class="brand" onclick="go('/')" style="cursor:pointer">Agri<span>Flow</span></div>
 <div class="actions">
 <button class="btn" onclick="setTheme(document.body.classList.contains('dark')?'light':'dark')">
 ${document.body.classList.contains('dark')?'☀ '+pt('light'):'☾ '+pt('dark')}
 </button>
 <select class="btn" onchange="setLanguage(this.value)" title="Language">
   <option value="en" ${currentLang==='en'?'selected':''}>English</option>
   <option value="mr" ${currentLang==='mr'?'selected':''}>मराठी</option>
   <option value="hi" ${currentLang==='hi'?'selected':''}>हिंदी</option>
 </select>
 ${currentUser?`<button class="btn" onclick="go('/dashboard')">${pt('dashboard')}</button>
 <button class="btn" onclick="logout()">${pt('logout')}</button>`:
 `<button class="btn" onclick="go('/login')">${pt('login')}</button>
 <button class="btn primary" onclick="go('/register')">${pt('register_farmer')}</button>`}
 </div></div></div>`
}
function go(path){history.pushState({},'',path);route()}
window.onpopstate=route;
async function bootstrap(){try{currentUser=await api('/api/auth/me')}catch{currentUser=null}renderNav();route()}
function home(){
 root.innerHTML=`<div class="container">
 <section class="hero">
 <div>
 <div class="kicker">${pt('kicker')}</div>
 <h1>${pt('hero')}</h1>
 <p>${pt('intro')}</p>
 <div class="actions">
 <button class="btn primary" onclick="go('/register')">${pt('register_farmer')}</button>
 <button class="btn" onclick="go('/login')">${pt('login')}</button>
 </div></div>

 <div class="heroCard">
 <h3>${pt('how')}</h3>
 <div class="steps">
 <div class="step"><div class="num">1</div><div><b>${pt('register')}</b><div class="muted">${pt('register_desc')}</div></div></div>
 <div class="step"><div class="num">2</div><div><b>${pt('submit')}</b><div class="muted">${pt('submit_desc')}</div></div></div>
 <div class="step"><div class="num">3</div><div><b>${pt('scheduled')}</b><div class="muted">${pt('scheduled_desc')}</div></div></div>
 <div class="step"><div class="num">4</div><div><b>${pt('track')}</b><div class="muted">${pt('track_desc')}</div></div></div>
 </div></div>
 </section>

 <section class="section">
 <h2>${pt('clarity')}</h2>
 <p class="muted">${pt('clarity_desc')}</p>
 <div class="grid3">
 <div class="card"><h3>${pt('visibility')}</h3><p class="muted">${pt('visibility_desc')}</p></div>
 <div class="card"><h3>${pt('status_tracking')}</h3><p class="muted">${pt('status_desc')}</p></div>
 <div class="card"><h3>${pt('alerts')}</h3><p class="muted">${pt('alerts_desc')}</p></div>
 </div>
 </section>

 <footer class="footer">AgriFlow • Farmer Procurement Management Platform</footer>
 </div>`
}
function login(){
 root.innerHTML=`<div class="container authwrap"><div class="card"><h2>Login</h2><p class="muted">Access your procurement dashboard.</p><form class="form" onsubmit="doLogin(event)"><div class="field"><label>Email</label><input id="email" type="email" required></div><div class="field"><label>Password</label><input id="password" type="password" minlength="8" required></div><button class="btn primary">Login</button></form></div></div>`
}
async function doLogin(e){e.preventDefault();try{let d=await api('/api/auth/login',{method:'POST',body:JSON.stringify({email:qs('#email').value,password:qs('#password').value})});currentUser=d.user;renderNav();go('/dashboard')}catch(err){toast(err.message)}}
function register(){
 root.innerHTML=`<div class="container authwrap"><div class="card"><h2>Farmer Registration</h2><form class="form" onsubmit="doRegister(event)">
 <div class="field"><label>Full name</label><input id="full_name" required minlength="2"></div><div class="field"><label>Mobile</label><input id="mobile" required minlength="10"></div><div class="field"><label>Email</label><input id="email" type="email" required></div><div class="field"><label>Password</label><input id="password" type="password" minlength="8" required></div><div class="field"><label>State</label><input id="state" value="Maharashtra" required></div><div class="field"><label>District</label><input id="district" required></div><div class="field"><label>Village / Address</label><input id="village" required></div><div class="field"><label>Farmer ID (optional)</label><input id="farmer_id"></div><button class="btn primary">Create account</button></form></div></div>`
}
async function doRegister(e){e.preventDefault();let x=id=>qs('#'+id).value;try{let d=await api('/api/auth/register',{method:'POST',body:JSON.stringify({full_name:x('full_name'),mobile:x('mobile'),email:x('email'),password:x('password'),state:x('state'),district:x('district'),village:x('village'),farmer_id:x('farmer_id')||null})});currentUser=d.user;renderNav();go('/dashboard')}catch(err){toast(err.message)}}
async function logout(){await api('/api/auth/logout',{method:'POST'});currentUser=null;renderNav();go('/')}
function renderFarmerJourney(requests,schedules){
 if(!requests || !requests.length){
   return `<div class="card" style="margin-top:16px">
     <h3>Your Procurement Journey</h3>
     <div class="muted">Create your first procurement request to begin.</div>
   </div>`;
 }

 const r=requests[0];

 const labels=[
   ['SUBMITTED','Request submitted'],
   ['UNDER_REVIEW','Under review'],
   ['SCHEDULED','Scheduled'],
   ['READY_FOR_PROCUREMENT','Ready for procurement'],
   ['PROCURED','Procured'],
   ['COMPLETED','Completed']
 ];

 const order=labels.map(x=>x[0]);
 const currentIndex=order.indexOf(r.status);

 let journey=labels.map((x,i)=>{
   const done=r.status==='COMPLETED' || (currentIndex>=0 && i<=currentIndex);
   return `<span class="badge" style="margin:4px;${done?'border-color:var(--brand);font-weight:800':''}">
     ${done?'✓':'○'} ${esc(x[1])}
   </span>`;
 }).join('');

 let nextTitle='';
 let nextText='';

 if(r.status==='COMPLETED'){
   nextTitle='✅ Procurement completed';
   nextText='Your procurement process is complete. No further action is required.';
 }
 else if(r.status==='SUBMITTED'){
   nextTitle='⏳ What happens next?';
   nextText='Your request has been submitted. A procurement officer will review it.';
 }
 else if(r.status==='UNDER_REVIEW'){
   nextTitle='🔎 What happens next?';
   nextText='Your request is being reviewed by the procurement officer.';
 }
 else if(r.status==='SCHEDULED' || r.status==='READY_FOR_PROCUREMENT'){
   const s=(schedules||[]).find(x=>x.id===r.schedule?.id);
    const wait=null;
   const queue=s?.queue?.congestion ?? null;

   nextTitle='🚜 Your next step';
   nextText=`Bring your ${esc(displayCropName(r.crop))} to ${esc(r.center.name)}
     ${r.schedule?` on <b>${fmt(r.schedule.scheduled_at)}</b> during <b>${esc(r.schedule.time_window)}</b>`:''}.
     ${queue?` Queue: <b>${esc(queue)}</b>.`:''}
      See your Digital Token below for your live queue position and estimated wait.`;
 }
 else if(r.status==='PROCURED'){
   nextTitle='✅ Produce received';
   nextText='Your produce has been procured. Wait for final completion confirmation.';
 }
 else if(r.status==='REJECTED'){
   nextTitle='❌ Request rejected';
   nextText='Please review the officer note or contact the procurement center.';
 }
 else if(r.status==='CANCELLED'){
   nextTitle='Request cancelled';
   nextText='This procurement request has been cancelled.';
 }

 return `<div class="card" style="margin-top:16px">
   <h3 style="margin-bottom:8px">Your Procurement Journey</h3>
   <div class="muted" style="margin-bottom:12px">
     Request #${r.id} • ${esc(displayCropName(r.crop))} • ${r.quantity_kg.toLocaleString()} kg
   </div>

   <div style="margin-bottom:14px">${journey}</div>

   <div class="notice" style="border-color:var(--brand)">
     <b>${nextTitle}</b>
     <div style="margin-top:7px">${nextText}</div>
   </div>
 </div>`;
}


function renderOfficerSnapshot(requests,schedules){
  const upcoming=(schedules||[]).filter(s=>s.status!=='CLOSED');

  const scheduledFarmers=(requests||[]).filter(r=>
    r.schedule && !['COMPLETED','REJECTED','CANCELLED'].includes(r.status)
  );

  const bookedKg=scheduledFarmers.reduce(
    (sum,r)=>sum+(Number(r.quantity_kg)||0),0
  );

  const totalCapacity=upcoming.reduce(
    (sum,s)=>sum+(Number(s.capacity_kg)||0),0
  );

  const remainingCapacity=upcoming.reduce(
    (sum,s)=>sum+(Number(s.queue?.remaining_capacity_kg ?? s.capacity_kg)||0),0
  );

  const waits=upcoming
    .map(s=>Number(s.queue?.predicted_wait_minutes)||0)
    .filter(v=>v>=0);

  const estimatedWait=waits.length
    ? Math.round(waits.reduce((a,b)=>a+b,0)/waits.length)
    : 0;

  const levels={LOW:1,MODERATE:2,HIGH:3};
  let queueLevel='LOW';

  upcoming.forEach(s=>{
    const q=(s.queue?.congestion||'LOW').toUpperCase();
    if((levels[q]||1)>(levels[queueLevel]||1)) queueLevel=q;
  });

  return `
  <div class="card" style="margin-top:16px">
    <div class="topline">
      <div>
        <h3 style="margin:0">${dt('ops_snapshot')}</h3>
        <div class="muted">${dt('live_summary')}</div>
      </div>
    </div>

    <div class="stats" style="margin-top:14px">
      <div class="card stat">
        <span class="muted">${dt('scheduled_farmers')}</span>
        <b>${scheduledFarmers.length}</b>
      </div>

      <div class="card stat">
        <span class="muted">${dt('booked_quantity')}</span>
        <b>${bookedKg.toLocaleString()} kg</b>
      </div>

      <div class="card stat">
        <span class="muted">${dt('remaining_capacity')}</span>
        <b>${remainingCapacity.toLocaleString()} kg</b>
      </div>

      <div class="card stat">
        <span class="muted">${dt('estimated_wait')}</span>
        <b>${estimatedWait} min</b>
      </div>
    </div>

    <div class="notice" style="margin-top:12px">
      ${dt('queue_status')}: <b>${esc(queueLevel)}</b>
      • ${dt('upcoming_slots')}: <b>${upcoming.length}</b>
      • ${dt('total_capacity')}: <b>${totalCapacity.toLocaleString()} kg</b>
    </div>
  </div>`;
}


function renderProcurementAnalytics(requests,schedules){
  const all = requests || [];
  const slots = schedules || [];

  const completed = all.filter(r=>r.status==='COMPLETED');
  const active = all.filter(r=>!['COMPLETED','REJECTED','CANCELLED'].includes(r.status));

  const completedKg = completed.reduce((sum,r)=>sum+(Number(r.quantity_kg)||0),0);
  const activeKg = active.reduce((sum,r)=>sum+(Number(r.quantity_kg)||0),0);

  const totalCapacity = slots.reduce(
    (sum,s)=>sum+(Number(s.capacity_kg)||0),0
  );

  const bookedKg = active
    .filter(r=>r.schedule)
    .reduce((sum,r)=>sum+(Number(r.quantity_kg)||0),0);

  const utilization = totalCapacity > 0
    ? Math.min(100,Math.round((bookedKg/totalCapacity)*100))
    : 0;

  const cropMap = {};
  all.forEach(r=>{
    let crop=(r.crop||'Unknown').trim();
    if(crop.toLowerCase()==='soyabean') crop='Soybean';
    else crop=crop.charAt(0).toUpperCase()+crop.slice(1).toLowerCase();
    if(!cropMap[crop]) cropMap[crop]={requests:0,kg:0};
    cropMap[crop].requests++;
    cropMap[crop].kg += Number(r.quantity_kg)||0;
  });

  const crops = Object.entries(cropMap)
    .sort((a,b)=>b[1].kg-a[1].kg);

  const maxCropKg = crops.length ? crops[0][1].kg : 1;
  const topCrop = crops.length ? crops[0][0] : '-';

  return `
    <div class="card" style="margin-top:16px">
      <div class="topline">
        <div>
          <h3 style="margin:0">📊 Procurement Analytics</h3>
          <div class="muted">Live operational insights from procurement activity</div>
        </div>
        <span class="badge">${utilization}% capacity used</span>
      </div>

      <div class="stats" style="margin-top:14px">
        <div class="card stat">
          <span class="muted">Active Quantity</span>
          <b>${activeKg.toLocaleString()} kg</b>
        </div>

        <div class="card stat">
          <span class="muted">Completed Quantity</span>
          <b>${completedKg.toLocaleString()} kg</b>
        </div>

        <div class="card stat">
          <span class="muted">Capacity Utilization</span>
          <b>${utilization}%</b>
        </div>

        <div class="card stat">
          <span class="muted">Highest Demand Crop</span>
          <b>${esc(topCrop)}</b>
        </div>
      </div>

      <div style="margin-top:16px">
        <div class="muted" style="margin-bottom:8px">Crop-wise Procurement Demand</div>

        ${crops.length ? crops.map(([crop,data])=>{
          const width=Math.max(4,Math.round((data.kg/maxCropKg)*100));
          return `
            <div style="margin-bottom:12px">
              <div class="topline" style="margin-bottom:5px">
                <span><b>${esc(crop)}</b> • ${data.requests} request${data.requests===1?'':'s'}</span>
                <span>${data.kg.toLocaleString()} kg</span>
              </div>
              <div style="height:8px;background:var(--border);border-radius:999px;overflow:hidden">
                <div style="height:100%;width:${width}%;background:var(--brand);border-radius:999px"></div>
              </div>
            </div>
          `;
        }).join('') : `
          <div class="notice">No procurement data available yet.</div>
        `}
      </div>

      <div class="notice" style="margin-top:14px">
        <b>Decision Insight:</b>
        ${topCrop!=='-'
          ? `${esc(topCrop)} currently has the highest procurement demand. Overall scheduled capacity utilization is ${utilization}%.`
          : `More procurement data is needed to generate demand insights.`
        }
      </div>
    </div>
  `;
}

function renderCapacityAlert(schedules){
  const slots = (schedules || []).filter(s=>s.status!=='CLOSED');

  const risky = slots
    .map(s=>({
      ...s,
      utilization: Number(s.queue?.utilization_percent)||0,
      remaining: Number(s.queue?.remaining_capacity_kg ?? s.capacity_kg)||0
    }))
    .filter(s=>s.utilization>=80)
    .sort((a,b)=>b.utilization-a.utilization);

  if(!risky.length){
    return `
      <div class="card" style="margin-top:16px">
        <div class="topline">
          <div>
            <h3 style="margin:0">⚡ Smart Capacity Alert</h3>
            <div class="muted">No procurement slot is currently overloaded</div>
          </div>
          <span class="badge">Normal</span>
        </div>
        <div class="notice" style="margin-top:12px">
          All active procurement schedules are currently below the overload threshold.
        </div>
      </div>
    `;
  }

  const worst = risky[0];

  return `
    <div class="card" style="margin-top:16px">
      <div class="topline">
        <div>
          <h3 style="margin:0">⚡ Smart Capacity Alert</h3>
          <div class="muted">Schedules approaching full capacity</div>
        </div>
        <span class="badge">${risky.length} high-load slot${risky.length===1?'':'s'}</span>
      </div>

      <div class="notice" style="margin-top:12px">
        <b>Attention:</b>
        ${esc(worst.crop)} at ${esc(worst.center?.name || 'procurement center')}
        is at <b>${Math.round(worst.utilization)}% utilization</b>
        with approximately <b>${worst.remaining.toLocaleString()} kg</b> capacity remaining.
      </div>

      <div style="margin-top:12px">
        ${risky.map(s=>`
          <div class="card" style="margin-bottom:10px">
            <div class="topline">
              <div>
                <b>${esc(displayCropName(s.crop))}</b>
                <div class="muted">
                  ${esc(s.center?.name || '-')} • ${fmt(s.scheduled_at)}
                </div>
              </div>
              <span class="badge">${Math.round(s.utilization)}% used</span>
            </div>
          </div>
        `).join('')}
      </div>

      <div class="notice">
        <b>Recommendation:</b>
        Prefer lower-load available slots for new farmer assignments to reduce waiting time and center congestion.
      </div>
    </div>
  `;
}

function renderOfficerLiveQueue(rows){
  const queue = rows || [];

  return `
    <div class="card" style="margin-top:16px">
      <div class="topline">
        <div>
          <h3 style="margin:0">🚜 Live Farmer Queue</h3>
          <div class="muted">Farmers who have checked in at the procurement center</div>
        </div>
        <span class="badge">${queue.length} checked in</span>
      </div>

      ${queue.length ? `
        <div class="tablewrap" style="margin-top:14px">
          <table class="table">
            <tr>
              <th>Position</th>
              <th>Token</th>
              <th>Farmer</th>
              <th>Crop</th>
              <th>Quantity</th>
              <th>Check-in time</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
            ${queue.map(q=>`
              <tr>
                <td><b>#${q.queue_position}</b></td>
                <td><span class="badge">${esc(q.token || '-')}</span></td>
                <td>${esc(q.farmer_name)}</td>
                <td>${esc(q.crop)}</td>
                <td>${Number(q.quantity_kg).toLocaleString()} kg</td>
                <td>${fmt(q.checked_in_at)}</td>
                <td><span class="badge">${esc(q.status.replaceAll('_',' '))}</span></td>
                <td>
                  ${q.status==='PROCURED'
                    ? `<button class="btn primary" onclick="completeProcurement(${q.request_id})">Complete Procurement</button>`
                    : q.status==='READY_FOR_PROCUREMENT'
                      ? `<button class="btn primary" onclick="startProcurement(${q.request_id})">Start Procurement</button>`
                      : q.queue_position===1
                        ? `<button class="btn primary" onclick="callNextFarmer(${q.request_id})">Call Next</button>`
                        : `<span class="muted">Waiting</span>`
                  }
                </td>
              </tr>
            `).join('')}
          </table>
        </div>
      ` : `
        <div class="notice" style="margin-top:14px">
          No farmers have checked in yet.
        </div>
      `}
    </div>
  `;
}

async function callNextFarmer(requestId){
  try{
    await api('/api/admin/requests/' + requestId + '/status', {
      method: 'PATCH',
      body: JSON.stringify({
        status: 'READY_FOR_PROCUREMENT',
        note: 'Farmer called from live procurement queue',
        schedule_id: null
      })
    });

    toast('Next farmer called successfully');
    dashboard();
  }catch(err){
    toast(err.message);
  }
}

async function startProcurement(requestId){
  try{
    await api('/api/admin/requests/' + requestId + '/status', {
      method: 'PATCH',
      body: JSON.stringify({
        status: 'PROCURED',
        note: 'Procurement started from live queue',
        schedule_id: null
      })
    });

    toast('Procurement started');
    dashboard();
  }catch(err){
    toast(err.message);
  }
}

async function completeProcurement(requestId){
  try{
    await api('/api/admin/requests/' + requestId + '/status', {
      method: 'PATCH',
      body: JSON.stringify({
        status: 'COMPLETED',
        note: 'Procurement completed from live queue',
        schedule_id: null
      })
    });

    toast('Procurement completed');
    dashboard();
  }catch(err){
    toast(err.message);
  }
}

async function renderFarmerQueueCards(requests){
  const active=(requests||[]).filter(r =>
    ['SCHEDULED','READY_FOR_PROCUREMENT','PROCURED'].includes(r.status) && r.schedule
  );

  if(!active.length) return '';

  const cards=[];

  for(const r of active){
    try{
      const q=await api('/api/requests/'+r.id+'/queue');
      if(!q.available) continue;

      cards.push(`
        <div class="card" style="margin-top:16px;border:1px solid var(--brand)">
          <div class="topline">
            <div>
              <h3 style="margin:0">🎫 Your Digital Token</h3>
              <div class="muted">Request #${r.id} • ${esc(displayCropName(r.crop))} • ${Number(r.quantity_kg).toLocaleString()} kg</div>
            </div>
            <span class="badge">${esc(q.token)}</span>
          </div>

          <div class="stats" style="margin-top:14px">
            <div class="card stat">
              <span class="muted">Queue position</span>
              <b>#${q.queue_position}</b>
            </div>
            <div class="card stat">
              <span class="muted">Farmers ahead</span>
              <b>${q.farmers_ahead}</b>
            </div>
            <div class="card stat">
              <span class="muted">Estimated wait</span>
              <b>${q.estimated_wait_minutes} min</b>
            </div>
            <div class="card stat">
              <span class="muted">Estimated service</span>
              <b>${fmt(q.estimated_service_time)}</b>
            </div>
          </div>

          <div class="notice" style="margin-top:12px">
            <b>${esc(q.center)}</b><br>
            <span class="muted">${fmt(q.scheduled_at)} • ${esc(q.time_window)}</span>
          </div>

          <button class="btn" style="margin-top:12px" onclick="checkInFarmer(${r.id}, this)">
            📍 Check In at Procurement Center
          </button>
        </div>
      `);
    }catch(e){
      console.error('Queue information error',e);
    }
  }

  return cards.join('');
}

async function checkInFarmer(requestId, button){
  const originalText = button.innerHTML;

  try{
    button.disabled = true;
    button.innerHTML = 'Checking in...';

    const result = await api('/api/requests/' + requestId + '/check-in', {
      method: 'POST'
    });

    button.innerHTML = '✅ Checked In';
    button.disabled = true;

    if(result.already_checked_in){
      toast('You are already checked in');
    }else{
      toast('Check-in successful');
    }

  }catch(err){
    button.disabled = false;
    button.innerHTML = originalText;
    toast(err.message);
  }
}

async function dashboard(){
 if(!currentUser){go('/login');return}
 try{
  const liveQueuePromise=currentUser.role==='ADMIN'
    ? api('/api/admin/live-queue')
    : Promise.resolve([]);

  const [d,notifs,centers,schedules,requests,liveQueue]=await Promise.all([
    api('/api/dashboard'),
    api('/api/notifications'),
    api('/api/centers'),
    api('/api/schedules'),
    api('/api/requests'),
    liveQueuePromise
  ]);
  let complete=d.status_counts.COMPLETED||0, active=d.total_requests-complete-(d.status_counts.REJECTED||0)-(d.status_counts.CANCELLED||0);
  root.innerHTML=`<div class="container app"><div class="topline"><div><h2 style="margin:0">Welcome, ${esc(currentUser.full_name)}</h2><div class="muted">${currentUser.role==='ADMIN'?dt('officer_dashboard'):dt('farmer_dashboard')}</div></div><div class="actions">${currentUser.role==='FARMER'?'<button class="btn primary" onclick="openRequest()">+ New Request</button>':'<button class="btn primary" onclick="openSchedule()">+ New Schedule</button>'}</div></div>
  <div class="stats"><div class="card stat"><span class="muted">${dt('total_requests')}</span><b>${d.total_requests}</b></div><div class="card stat"><span class="muted">${dt('active')}</span><b>${Math.max(active,0)}</b></div><div class="card stat"><span class="muted">${dt('completed')}</span><b>${complete}</b></div><div class="card stat"><span class="muted">${dt('unread_alerts')}</span><b>${notifs.filter(n=>!n.read).length}</b></div></div>
  ${currentUser.role==='ADMIN'?renderOfficerSnapshot(requests,schedules):''}

  ${currentUser.role==='ADMIN'?`
    <div style="margin-top:24px;margin-bottom:8px">
      <h2 style="margin:0">Decision Intelligence</h2>
      <div class="muted">Demand, capacity and congestion insights for procurement planning</div>
    </div>
  `:''}

  ${currentUser.role==='ADMIN'?renderProcurementAnalytics(requests,schedules):''}
  ${currentUser.role==='ADMIN'?renderCapacityAlert(schedules):''}

  ${currentUser.role==='ADMIN'?`
    <div style="margin-top:24px;margin-bottom:8px">
      <h2 style="margin:0">Live Procurement Operations</h2>
      <div class="muted">Real-time farmer check-in and queue processing</div>
    </div>
  `:''}

  ${currentUser.role==='ADMIN'?renderOfficerLiveQueue(liveQueue):''}
${currentUser.role==='FARMER'?renderFarmerJourney(requests,schedules):''}
${currentUser.role==='FARMER'?await renderFarmerQueueCards(requests):''}
  <div class="layout"><div>
   <div class="card"><div class="topline"><h3 style="margin:0">${currentUser.role==='ADMIN'?'All procurement requests':'Your procurement requests'}</h3></div>${requests.length?renderRequests(requests):'<div class="muted">No procurement requests yet.</div>'}</div>
   <div class="card" style="margin-top:16px"><h3>${dt('upcoming_schedules')}</h3>${schedules.length?`<div class="tablewrap"><table class="table"><tr><th>${dt('crop')}</th><th>${dt('center')}</th><th>${dt('date')}</th><th>${dt('window')}</th><th>${dt('capacity')}</th><th>${dt('queue')}</th><th>${dt('est_wait')}</th></tr>${schedules.map(s=>`<tr><td>${esc(displayCropName(s.crop))}</td><td>${esc(s.center.name)}</td><td>${fmt(s.scheduled_at)}</td><td>${esc(s.time_window)}</td><td>${s.capacity_kg.toLocaleString()} kg</td><td>${s.queue?esc(s.queue.congestion):'-'}</td><td>${s.queue?s.queue.predicted_wait_minutes+' min':'-'}</td></tr>`).join('')}</table></div>`:'<div class="muted">'+dt('no_schedules')+'</div>'}</div>
  </div><div><div class="card"><h3>${dt('notifications')}</h3>${notifs.length?notifs.slice(0,8).map(n=>`<div class="notice"><b>${esc(n.title)}</b><div class="muted">${esc(n.message)}</div><small class="muted">${fmt(n.created_at)}</small></div>`).join(''):'<div class="muted">'+dt('no_notifications')+'</div>'}</div></div></div></div>`;
  window.__centers=centers;window.__schedules=schedules;
 }catch(err){toast(err.message);if(err.message.toLowerCase().includes('auth')){currentUser=null;renderNav();go('/login')}}
}
function renderRequests(rows){return `<div class="tablewrap"><table class="table"><tr><th>ID</th>${currentUser.role==='ADMIN'?'<th>'+dt('farmer')+'</th>':''}<th>${dt('crop')}</th><th>${dt('quantity')}</th><th>${dt('center')}</th><th>${dt('status')}</th><th></th></tr>${rows.map(r=>`<tr><td>#${r.id}</td>${currentUser.role==='ADMIN'?`<td>${esc(r.farmer.full_name)}</td>`:''}<td>${esc(displayCropName(r.crop))}</td><td>${r.quantity_kg.toLocaleString()} kg</td><td>${esc(r.center.name)}</td><td><span class="badge">${esc(r.status.replaceAll('_',' '))}</span></td><td><div class="actions"><button class="btn" onclick="track(${r.id})">${currentUser.role==='ADMIN'?'Manage':'Track'}</button>${currentUser.role==='FARMER' && r.status==='COMPLETED'?`<button class="btn primary" onclick="openReceipt(${r.id})">Receipt</button>`:''}</div></td></tr>`).join('')}</table></div>`}
function openRequest(){modal.className='modal';modal.innerHTML=`<div class="modalbox"><div class="topline"><h3>New procurement request</h3><button class="btn" onclick="closeModal()">✕</button></div><form class="form" onsubmit="submitRequest(event)"><div class="field"><label>Crop / Commodity</label><input id="crop" placeholder="e.g. Soybean" required></div><div class="field"><label>Quantity (kg)</label><input id="qty" type="number" min="1" step=".01" required></div><div class="field"><label>Procurement center</label><select id="center" required>${window.__centers.map(c=>`<option value="${c.id}">${esc(c.name)} — ${esc(c.district)}</option>`).join('')}</select></div><div class="field"><label>Schedule (optional)</label><select id="schedule"><option value="">Request scheduling by officer</option>${window.__schedules.map(s=>`<option value="${s.id}">${esc(displayCropName(s.crop))} — ${fmt(s.scheduled_at)} — ${esc(s.center.name)}</option>`).join('')}</select></div><div class="field"><label>Details</label><textarea id="details" rows="4" placeholder="Grade, expected harvest readiness, notes..."></textarea></div><button class="btn primary">Submit request</button></form></div>`}
async function submitRequest(e){e.preventDefault();try{await api('/api/requests',{method:'POST',body:JSON.stringify({crop:qs('#crop').value,quantity_kg:+qs('#qty').value,center_id:+qs('#center').value,schedule_id:qs('#schedule').value?+qs('#schedule').value:null,details:qs('#details').value||null})});closeModal();toast('Request submitted');dashboard()}catch(err){toast(err.message)}}
async function openReceipt(id){
  try{
    const r = await api('/api/requests/' + id);

    modal.className='modal';
    modal.innerHTML=`
      <div class="modalbox">
        <div class="topline">
          <div>
            <h3 style="margin:0">🧾 Procurement Receipt</h3>
            <div class="muted">AgriFlow Digital Acknowledgement</div>
          </div>
          <button class="btn" onclick="closeModal()">✕</button>
        </div>

        <div id="receiptPrintArea" style="margin-top:16px">
          <div class="card">
            <div class="topline">
              <div>
                <h2 style="margin:0">AgriFlow</h2>
                <div class="muted">Procurement Completion Receipt</div>
              </div>
              <span class="badge">COMPLETED</span>
            </div>

            <hr style="margin:16px 0;border:none;border-top:1px solid var(--border)">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
              <div>
                <div class="muted">Receipt / Request ID</div>
                <b>#${r.id}</b>
              </div>

              <div>
                <div class="muted">Farmer</div>
                <b>${esc(r.farmer.full_name)}</b>
              </div>

              <div>
                <div class="muted">Crop</div>
                <b>${esc(displayCropName(r.crop))}</b>
              </div>

              <div>
                <div class="muted">Quantity</div>
                <b>${Number(r.quantity_kg).toLocaleString()} kg</b>
              </div>

              <div>
                <div class="muted">Procurement Center</div>
                <b>${esc(r.center.name)}</b>
              </div>

              <div>
                <div class="muted">District</div>
                <b>${esc(r.center.district || '-')}</b>
              </div>

              <div>
                <div class="muted">Scheduled Date</div>
                <b>${r.schedule ? fmt(r.schedule.scheduled_at) : '-'}</b>
              </div>

              <div>
                <div class="muted">Completed On</div>
                <b>${fmt(r.updated_at)}</b>
              </div>
            </div>

            <div class="notice" style="margin-top:16px">
              <b>Procurement successfully completed.</b><br>
              This receipt confirms that the farmer's procurement request has been processed through AgriFlow.
            </div>
          </div>
        </div>

        <div class="actions" style="margin-top:16px">
          <button class="btn primary" onclick="printReceipt()">Print Receipt</button>
          <button class="btn" onclick="closeModal()">Close</button>
        </div>
      </div>
    `;
  }catch(err){
    toast(err.message);
  }
}

function printReceipt(){
  const area = document.getElementById('receiptPrintArea');

  if(!area){
    toast('Receipt not available');
    return;
  }

  const printWindow = window.open('', '_blank');

  printWindow.document.write(`
    <html>
      <head>
        <title>AgriFlow Procurement Receipt</title>
        <style>
          body{
            font-family:Arial,sans-serif;
            padding:32px;
            color:#111;
          }
          .card{
            border:1px solid #ddd;
            border-radius:12px;
            padding:24px;
          }
          .topline{
            display:flex;
            justify-content:space-between;
            align-items:flex-start;
            gap:16px;
          }
          .muted{
            color:#666;
            font-size:14px;
          }
          .badge{
            border:1px solid #999;
            border-radius:999px;
            padding:5px 10px;
            font-size:12px;
          }
          .notice{
            margin-top:16px;
            padding:12px;
            background:#f5f5f5;
            border-radius:8px;
          }
        </style>
      </head>
      <body>
        ${area.innerHTML}
      </body>
    </html>
  `);

  printWindow.document.close();
  printWindow.focus();
  printWindow.print();
}

async function track(id){try{let r=await api('/api/requests/'+id);modal.className='modal';modal.innerHTML=`<div class="modalbox"><div class="topline"><div><h3 style="margin:0">Request #${r.id}</h3><div class="muted">${esc(displayCropName(r.crop))} • ${r.quantity_kg.toLocaleString()} kg • ${esc(r.center.name)}</div></div><button class="btn" onclick="closeModal()">✕</button></div><p><span class="badge">${esc(r.status.replaceAll('_',' '))}</span></p>${currentUser.role==='ADMIN'?adminStatusForm(r):''}<h3>Status timeline</h3><div class="timeline">${r.history.map(h=>`<div class="event"><b>${esc(h.status.replaceAll('_',' '))}</b><div class="muted">${esc(h.note||'Status updated')}</div><small class="muted">${fmt(h.changed_at)}</small></div>`).join('')}</div></div>`}catch(err){toast(err.message)}}
function scheduleRecommendation(r){
  const options=(window.__schedules||[]).filter(s=>
    s.status==='OPEN' &&
    s.center.id===r.center.id &&
    s.crop.toLowerCase().replace('soyabean','soybean')===r.crop.toLowerCase().replace('soyabean','soybean') &&
    ((s.queue?.remaining_capacity_kg??s.capacity_kg)>=r.quantity_kg || r.schedule?.id===s.id)
  );

  if(!options.length){
    return `<div class="notice">
      <b>⭐ AgriFlow Recommendation</b>
      <div class="muted">No suitable open schedule is currently available for this crop and center.</div>
    </div>`;
  }

  options.sort((a,b)=>
    (a.queue?.predicted_wait_minutes??9999)-(b.queue?.predicted_wait_minutes??9999) ||
    (a.queue?.utilization_percent??9999)-(b.queue?.utilization_percent??9999)
  );

  const best=options[0];
  const current=r.schedule ? options.find(s=>s.id===r.schedule.id) : null;

  if(r.schedule && current && best.id===current.id){
    return `<div class="notice" style="border-color:var(--brand)">
      <b>✅ Current Slot Is Already Optimal</b>
      <div style="margin-top:7px"><b>${fmt(current.scheduled_at)} · ${esc(current.time_window)}</b></div>
      <div class="muted">${esc(current.center.name)}</div>
      <div style="margin-top:7px">
        Queue: <b>${esc(current.queue?.congestion||'LOW')}</b> ·
        Estimated wait: <b>${current.queue?.predicted_wait_minutes??0} min</b>
      </div>
      <div class="muted" style="margin-top:6px">
        AgriFlow found no better compatible slot based on waiting time and capacity.
      </div>
    </div>`;
  }

  if(r.schedule && best.id!==r.schedule.id){
    const currentWait=current?.queue?.predicted_wait_minutes;
    const bestWait=best.queue?.predicted_wait_minutes??0;

    return `<div class="notice" style="border-color:var(--brand)">
      <b>🔄 AgriFlow Smart Reschedule</b>

      ${current ? `
      <div class="muted" style="margin-top:7px">Current slot</div>
      <div><b>${fmt(current.scheduled_at)} · ${esc(current.time_window)}</b></div>
      <div>
        Queue: <b>${esc(current.queue?.congestion||'LOW')}</b> ·
        Estimated wait: <b>${currentWait??0} min</b>
      </div>` : ''}

      <div class="muted" style="margin-top:10px">Better available slot</div>
      <div><b>${fmt(best.scheduled_at)} · ${esc(best.time_window)}</b></div>
      <div class="muted">${esc(best.center.name)}</div>
      <div>
        Queue: <b>${esc(best.queue?.congestion||'LOW')}</b> ·
        Estimated wait: <b>${bestWait} min</b>
      </div>

      <div class="muted" style="margin-top:6px">
        Reason: Lower expected waiting time or lower slot utilization with enough remaining capacity.
      </div>

      <button type="button" class="btn primary" style="margin-top:10px"
        onclick="qs('#assignSchedule').value='${best.id}';toast('Better slot selected')">
        Use better slot
      </button>
    </div>`;
  }

  return `<div class="notice" style="border-color:var(--brand)">
    <b>⭐ AgriFlow Recommended Slot</b>
    <div style="margin-top:7px"><b>${fmt(best.scheduled_at)} · ${esc(best.time_window)}</b></div>
    <div class="muted">${esc(best.center.name)}</div>
    <div style="margin-top:7px">
      Queue: <b>${esc(best.queue?.congestion||'LOW')}</b> ·
      Estimated wait: <b>${best.queue?.predicted_wait_minutes??0} min</b>
    </div>
    <div class="muted" style="margin-top:6px">
      Reason: Lowest expected waiting time among suitable open slots with enough remaining capacity.
    </div>
    <button type="button" class="btn primary" style="margin-top:10px"
      onclick="qs('#assignSchedule').value='${best.id}';toast('Recommended slot selected')">
      Use recommended slot
    </button>
  </div>`;
}

function adminStatusForm(r){let statuses=['SUBMITTED','UNDER_REVIEW','SCHEDULED','READY_FOR_PROCUREMENT','PROCURED','COMPLETED','REJECTED','CANCELLED'];return `${scheduleRecommendation(r)}<form class="form card" onsubmit="saveStatus(event,${r.id})" style="box-shadow:none;margin:14px 0"><div class="field"><label>Update status</label><select id="newStatus">${statuses.map(s=>`<option ${s===r.status?'selected':''}>${s}</option>`).join('')}</select></div><div class="field"><label>Assign schedule</label><select id="assignSchedule"><option value="">Keep current / no schedule</option>${window.__schedules.map(s=>`<option value="${s.id}" ${r.schedule?.id===s.id?'selected':''}>${esc(displayCropName(s.crop))} — ${fmt(s.scheduled_at)} — ${esc(s.center.name)}</option>`).join('')}</select></div><div class="field"><label>Officer note</label><input id="statusNote" placeholder="Instruction or reason"></div><button class="btn primary">Save update</button></form>`}
async function saveStatus(e,id){e.preventDefault();try{await api('/api/admin/requests/'+id+'/status',{method:'PATCH',body:JSON.stringify({status:qs('#newStatus').value,note:qs('#statusNote').value||null,schedule_id:qs('#assignSchedule').value?+qs('#assignSchedule').value:null})});closeModal();toast('Status updated');dashboard()}catch(err){toast(err.message)}}
function openSchedule(){modal.className='modal';modal.innerHTML=`<div class="modalbox"><div class="topline"><h3>Create procurement schedule</h3><button class="btn" onclick="closeModal()">✕</button></div><form class="form" onsubmit="submitSchedule(event)"><div class="field"><label>Center</label><select id="scenter">${window.__centers.map(c=>`<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select></div><div class="field"><label>Crop</label><input id="scrop" required></div><div class="field"><label>Date & time</label><input id="sdate" type="datetime-local" required></div><div class="field"><label>Time window</label><input id="swindow" placeholder="10:00 AM – 1:00 PM" required></div><div class="field"><label>Capacity (kg)</label><input id="scapacity" type="number" min="1" required></div><button class="btn primary">Publish schedule</button></form></div>`}
async function submitSchedule(e){e.preventDefault();try{await api('/api/admin/schedules',{method:'POST',body:JSON.stringify({center_id:+qs('#scenter').value,crop:qs('#scrop').value,scheduled_at:new Date(qs('#sdate').value).toISOString(),time_window:qs('#swindow').value,capacity_kg:+qs('#scapacity').value,status:'OPEN'})});closeModal();toast('Schedule published');dashboard()}catch(err){toast(err.message)}}
function closeModal(){modal.className='hidden';modal.innerHTML=''}
function route(){renderNav();let p=location.pathname;if(p==='/login')login();else if(p==='/register')register();else if(p==='/dashboard')dashboard();else home()}
bootstrap();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("agriflow_procurement:app", host="127.0.0.1", port=8000, reload=True)
