import os
import secrets
import random
import shutil
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, ForeignKey, DateTime, func
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- CONFIGURATION ---
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
UPLOAD_DIR = "static/uploads"
SQLALCHEMY_DATABASE_URL = "sqlite:///./commercial_portfolio.db"

os.makedirs(UPLOAD_DIR, exist_ok=True)

# --- DATABASE ENGINE ---
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- DATABASE MODELS (COMMERCIAL SCHEMA) ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    otp_code = Column(String, nullable=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    profile = relationship("UserProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    items = relationship("PortfolioItem", back_populates="owner", cascade="all, delete-orphan")

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

# Create Tables
Base.metadata.create_all(bind=engine)

# --- SECURITY & UTILS ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def send_otp_email(email: str, otp: str):
    print(f"\n[EMAIL SERVICE] Sending OTP: {otp} to {email}\n")

# --- API APP ---
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- ENDPOINTS ---
@app.post("/signup")
def signup(username: str = Form(...), email: str = Form(...), password: str = Form(...), bio: str = Form(...), db: Session = Depends(get_db)):
    if db.query(User).filter((User.username == username) | (User.email == email)).first():
        raise HTTPException(status_code=400, detail="Username or Email already taken")
    
    otp_code = str(random.randint(100000, 999999))
    new_user = User(
        username=username, email=email, hashed_password=pwd_context.hash(password),
        otp_code=otp_code, is_verified=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    new_profile = UserProfile(user_id=new_user.id, bio=bio, full_name=username)
    db.add(new_profile)
    db.commit()
    
    send_otp_email(email, otp_code)
    return {"message": "Account created. Check server console for OTP."}

@app.post("/verify_otp")
def verify_otp(username: str = Form(...), otp: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if user.otp_code == otp:
        user.is_verified = True
        user.otp_code = None
        db.commit()
        return {"message": "Verified!"}
    raise HTTPException(status_code=400, detail="Invalid OTP")

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect credentials")
    if not user.is_verified:
        raise HTTPException(status_code=400, detail="Account not verified")
    return {"access_token": create_access_token(data={"sub": user.username}), "token_type": "bearer"}

@app.post("/upload")
async def upload_content(title: str = Form(...), is_public: bool = Form(...), file: UploadFile = File(...), token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(User).filter(User.username == payload.get("sub")).first()
    except: raise HTTPException(status_code=401)
    
    if not user: raise HTTPException(status_code=401)
    
    file_location = f"{UPLOAD_DIR}/{secrets.token_hex(8)}_{file.filename}"
    with open(file_location, "wb") as buffer: shutil.copyfileobj(file.file, buffer)
    
    new_item = PortfolioItem(
        title=title, file_url=file_location, is_public=is_public,
        private_token=secrets.token_urlsafe(16), owner_id=user.id
    )
    db.add(new_item)
    db.commit()
    return {"message": "Uploaded", "private_token": new_item.private_token}

@app.get("/portfolio/{username}")
def get_portfolio(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user: raise HTTPException(status_code=404)
    items = db.query(PortfolioItem).filter(PortfolioItem.owner_id == user.id, PortfolioItem.is_public == True).all()
    return {"user": user.username, "bio": user.profile.bio if user.profile else "", "items": items}