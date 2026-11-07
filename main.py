import json
import os
import secrets
import shutil
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Generator

import cloudinary
import cloudinary.uploader
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, create_engine, func, text
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
APP_ENV = os.getenv("APP_ENV", "development").lower()
IS_PRODUCTION = APP_ENV == "production"

SECRET_KEY = os.getenv("SECRET_KEY")
if IS_PRODUCTION and not SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be configured in production.")
SECRET_KEY = SECRET_KEY or secrets.token_urlsafe(48)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(STATIC_DIR / "uploads")))
STATIC_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'commercial_portfolio.db'}")
# Render and some other providers supply postgres:// URLs. SQLAlchemy's
# psycopg 3 dialect uses postgresql+psycopg://.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine_options = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")
CLOUDINARY_CONFIGURED = all(
    [CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET]
)
if CLOUDINARY_CONFIGURED:
    cloudinary.config(
        cloud_name=CLOUDINARY_CLOUD_NAME,
        api_key=CLOUDINARY_API_KEY,
        api_secret=CLOUDINARY_API_SECRET,
        secure=True,
    )

# ---------------------------------------------------------------------------
# Database models
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    otp_code = Column(String, nullable=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    profile = relationship(
        "UserProfile", back_populates="user", uselist=False,
        cascade="all, delete-orphan"
    )
    items = relationship(
        "PortfolioItem", back_populates="owner",
        cascade="all, delete-orphan"
    )


class UserProfile(Base):
    __tablename__ = "profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    full_name = Column(String, nullable=True)
    bio = Column(Text, nullable=True)
    avatar_url = Column(String, nullable=True)
    user = relationship("User", back_populates="profile")


class PortfolioItem(Base):
    __tablename__ = "portfolio_items"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String, index=True, nullable=False)
    description = Column(Text, nullable=True)
    file_url = Column(String, nullable=False)
    is_public = Column(Boolean, default=True)
    private_token = Column(String, unique=True, index=True)
    view_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    owner = relationship("User", back_populates="items")


# Creates missing tables on first deployment. Use migrations for future schema
# changes rather than relying on create_all to alter existing tables.
Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# Authentication and database helpers
# ---------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_error = HTTPException(
        status_code=401,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise credentials_error
    except JWTError:
        raise credentials_error

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise credentials_error
    return user


# ---------------------------------------------------------------------------
# Email delivery (Resend). In local development, OTP is printed to the
# terminal; production never exposes OTPs in application logs.
# ---------------------------------------------------------------------------
def send_otp_email(email: str, otp: str) -> None:
    api_key = os.getenv("RESEND_API_KEY")
    email_from = os.getenv("EMAIL_FROM")

    if not api_key or not email_from:
        if IS_PRODUCTION:
            raise HTTPException(
                status_code=503,
                detail="Email verification is not configured. Contact the site owner.",
            )
        print(f"[LOCAL DEVELOPMENT] OTP for {email}: {otp}")
        return

    payload = {
        "from": email_from,
        "to": [email],
        "subject": "Verify your portfolio account",
        "html": (
            "<p>Use this verification code to activate your portfolio account:</p>"
            f"<p style='font-size:28px;font-weight:bold;letter-spacing:6px'>{otp}</p>"
            "<p>If you did not request this, you can ignore this email.</p>"
        ),
    }
    request = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status >= 300:
                raise RuntimeError("Email provider rejected the request.")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not send the verification email. Please try again.",
        ) from exc


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(title="Portfolio API", version="2.0.0")

# The frontend is served by this same application, so same-origin requests
# need no CORS exception. Add trusted origins only when using a separate site.
allowed_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
if allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")


@app.get("/", include_in_schema=False)
def homepage():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/healthz", tags=["system"])
def health_check(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "ok", "database": "connected"}


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
@app.post("/signup")
def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    bio: str = Form(""),
    db: Session = Depends(get_db),
):
    username = username.strip()
    email = email.strip().lower()
    if not username or not email or len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Enter a username, valid email, and password of at least 8 characters.",
        )

    existing_user = db.query(User).filter(
        (User.username == username) | (User.email == email)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already taken")

    otp_code = f"{secrets.randbelow(1_000_000):06d}"
    # Send first so a failed email does not leave an unverified account that
    # prevents the user from signing up again.
    send_otp_email(email, otp_code)

    new_user = User(
        username=username,
        email=email,
        hashed_password=pwd_context.hash(password),
        otp_code=otp_code,
        is_verified=False,
    )
    db.add(new_user)
    db.flush()
    db.add(UserProfile(user_id=new_user.id, bio=bio, full_name=username))
    db.commit()

    return {"message": "Account created. Check your email for the verification code."}


@app.post("/verify_otp")
def verify_otp(
    username: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username.strip()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.otp_code or not secrets.compare_digest(user.otp_code, otp.strip()):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    user.is_verified = True
    user.otp_code = None
    db.commit()
    return {"message": "Account verified."}


@app.post("/token")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form_data.username.strip()).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    if not user.is_verified:
        raise HTTPException(status_code=400, detail="Account not verified")

    return {
        "access_token": create_access_token(data={"sub": user.username}),
        "token_type": "bearer",
    }


@app.post("/upload")
async def upload_content(
    title: str = Form(...),
    is_public: bool = Form(...),
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    original_name = Path(file.filename or "upload").name
    extension = Path(original_name).suffix[:20]
    file.file.seek(0, os.SEEK_END)
    file_size = file.file.tell()
    file.file.seek(0)
    if file_size == 0:
        raise HTTPException(status_code=400, detail="The selected file is empty.")
    if file_size > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Files must be 25 MB or smaller.")

    if CLOUDINARY_CONFIGURED:
        try:
            uploaded = cloudinary.uploader.upload(
                file.file,
                folder="portfolio-app",
                resource_type="auto",
            )
            file_url = uploaded["secure_url"]
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail="Cloud file storage could not save this upload.",
            ) from exc
    else:
        if IS_PRODUCTION:
            raise HTTPException(
                status_code=503,
                detail="Cloud file storage is not configured. Contact the site owner.",
            )
        filename = f"{secrets.token_hex(16)}{extension}"
        destination = UPLOAD_DIR / filename
        with destination.open("wb") as output:
            shutil.copyfileobj(file.file, output)
        file_url = f"/uploads/{filename}"

    item = PortfolioItem(
        title=title.strip(),
        file_url=file_url,
        is_public=is_public,
        private_token=secrets.token_urlsafe(24),
        owner_id=user.id,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return {"message": "Uploaded", "private_token": item.private_token, "file_url": item.file_url}


@app.get("/portfolio/{username}")
def get_portfolio(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username.strip()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    items = (
        db.query(PortfolioItem)
        .filter(
            PortfolioItem.owner_id == user.id,
            PortfolioItem.is_public.is_(True),
        )
        .order_by(PortfolioItem.created_at.desc())
        .all()
    )
    return {
        "user": user.username,
        "bio": user.profile.bio if user.profile else "",
        "items": [
            {
                "id": item.id,
                "title": item.title,
                "description": item.description,
                "file_url": item.file_url,
                "view_count": item.view_count,
                "created_at": item.created_at,
            }
            for item in items
        ],
    }
