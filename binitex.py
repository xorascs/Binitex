from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, exceptions
from datetime import datetime, timedelta
from pydantic import BaseModel
import logging

# FastAPI instance
app = FastAPI(debug=True)

# Set up logging configuration
logging.basicConfig(level=logging.INFO)

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

security = HTTPBearer(description="Type JWT Token to use private-data request")

# JWT settings
SECRET_KEY = "oscar"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

Base.metadata.create_all(bind=engine)

# Pydantic models
class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class PublicData(BaseModel):
    email: str

class PrivateData(BaseModel):
    id: int
    email: str
    password: str

class MyExceptions:
    USER_EXISTS = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="User already exists",
        headers={"WWW-Authenticate": "Bearer"},
    )
    INVALID_CREDENTIALS = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    NO_PRIVATE_DATA = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="No private data or your JWT has expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    NO_PUBLIC_DATA = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="No public data",
        headers={"WWW-Authenticate": "Bearer"},
    )

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Helper functions
def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def get_public_data(db: Session):
    users = db.query(User).all()
    if len(users) == 0:
        logging.info("No public data found")
        return None
    users_list = []
    for user in users:
        users_list.append(PublicData(email=user.email))
    return users_list

def get_private_data(db: Session, token: str):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = decoded_token.get("sub")
        user = db.query(User).where(User.email == email).first()
        if not user:
            logging.info(f"No private data found for email {email}")
            return None
        return PrivateData(id=user.id, email=user.email, password=user.hashed_password)
    except (exceptions.ExpiredSignatureError, exceptions.JWTError):
        logging.info("Invalid JWT token")
        return None

def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        logging.info(f"Authentication failed for email {email}")
        return None
    return user

# Routes
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = get_user_by_email(db, user.email)
    if existing_user:
        raise MyExceptions.USER_EXISTS
    create_user(db, user)
    logging.info(f"User {user.email} registered successfully")
    return {"message": "Registration successful!"}

@app.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    authenticated_user = authenticate_user(db, user.email, user.password)
    if not authenticated_user:
        raise MyExceptions.INVALID_CREDENTIALS
    access_token = create_access_token({"sub": authenticated_user.email}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    logging.info(f"User {authenticated_user.email} logged in successfully")
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/public-data")
def public_data(db: Session = Depends(get_db)):
    data = get_public_data(db)
    if not data:
        raise MyExceptions.NO_PUBLIC_DATA
    logging.info(f"Public data retrieved successfully")
    return {"message": "This is public data", "data": data}

@app.get("/private-data")
def private_data(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    user = get_private_data(db, token)
    if not user:
        raise MyExceptions.NO_PRIVATE_DATA
    logging.info(f"Private data retrieved successfully for user {user.email}")
    return {"message": "This is private data", "data": user}

# Run the application using:
# uvicorn binitex:app --reload