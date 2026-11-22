
import os
import re
import boto3
import jwt

from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from pwdlib import PasswordHash

load_dotenv()

# ---------------- CONFIGURATION ----------------

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
USERS_TABLE_NAME = os.getenv("USERS_TABLE_NAME", "USERS")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(
    os.getenv("JWT_EXPIRE_MINUTES", "60")
)

if not JWT_SECRET_KEY or len(JWT_SECRET_KEY) < 32:
    raise RuntimeError(
        "JWT_SECRET_KEY must be at least 32 characters."
    )

# ---------------- AWS DYNAMODB ----------------

dynamodb = boto3.resource(
    "dynamodb",
    region_name=AWS_REGION
)

users_table = dynamodb.Table(USERS_TABLE_NAME)

# ---------------- SECURITY ----------------

password_hasher = PasswordHash.recommended()

# ---------------- FASTAPI ----------------

app = FastAPI(
    title="OnlyBroker API",
    description="OnlyBroker Authentication Service",
    version="1.0.0"
)

origins = os.getenv("CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# ---------------- REQUEST MODELS ----------------

class CheckUserIDRequest(BaseModel):
    user_id: str = Field(min_length=3, max_length=30)


class SignupRequest(BaseModel):
    user_id: str = Field(min_length=3, max_length=30)
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=2, max_length=100)
    email: str = Field(max_length=254)
    mobile_number: str = Field(min_length=10, max_length=16)


class LoginRequest(BaseModel):
    user_id: str
    password: str


# ---------------- VALIDATION ----------------

def normalize_user_id(user_id):
    return user_id.strip().lower()


def validate_user_id(user_id):
    if not re.fullmatch(
        r"[a-z0-9_]{3,30}", user_id
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Please use 3-30 characters: "
                "letters, numbers or underscores."
            )
        )


def validate_email(email):
    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email.strip()
    ):
        raise HTTPException(
            status_code=400,
            detail="Please enter a valid email address."
        )


def validate_mobile(mobile):
    if not re.fullmatch(
        r"\+?[0-9]{10,15}", mobile.strip()
    ):
        raise HTTPException(
            status_code=400,
            detail="Please enter a valid mobile number."
        )


# ---------------- JWT TOKEN ----------------

def create_access_token(user_id):
    now = datetime.now(timezone.utc)

    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(
            minutes=JWT_EXPIRE_MINUTES
        )
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )


# ---------------- HEALTH CHECK ----------------

@app.get("/")
def home():
    return {
        "success": True,
        "application": "OnlyBroker API",
        "message": "API is running."
    }


# ---------------- CHECK USER ID ----------------

@app.post("/auth/check-user-id")
def check_user_id(data: CheckUserIDRequest):

    user_id = normalize_user_id(data.user_id)

    validate_user_id(user_id)

    try:
        response = users_table.get_item(
            Key={"USERS_ID": user_id},
            ConsistentRead=True
        )

        if "Item" in response:
            return {
                "available": False,
                "message": (
                    "This User ID is already taken. "
                    "Please choose another User ID."
                )
            }

        return {
            "available": True,
            "message": "User ID is available."
        }

    except ClientError:
        raise HTTPException(
            status_code=503,
            detail="Unable to check User ID. Please try again."
        )


# ---------------- SIGNUP ----------------

@app.post("/auth/signup")
def signup(data: SignupRequest):

    user_id = normalize_user_id(data.user_id)
    email = data.email.strip().lower()
    full_name = data.full_name.strip()
    mobile = data.mobile_number.strip()

    validate_user_id(user_id)
    validate_email(email)
    validate_mobile(mobile)

    if not full_name:
        raise HTTPException(
            status_code=400,
            detail="Full name is required."
        )

    password_hash = password_hasher.hash(data.password)

    item = {
        "USERS_ID": user_id,
        "PASSWORD_HASH": password_hash,
        "FULL_NAME": full_name,
        "EMAIL": email,
        "MOBILE_NUMBER": mobile,
        "ACCOUNT_STATUS": "ACTIVE",
        "EMAIL_VERIFIED": False,
        "MOBILE_VERIFIED": False,
        "CREATED_AT": datetime.now(
            timezone.utc
        ).isoformat()
    }

    try:
        users_table.put_item(
            Item=item,
            ConditionExpression=(
                "attribute_not_exists(USERS_ID)"
            )
        )

        token = create_access_token(user_id)

        return {
            "success": True,
            "message": "Your OnlyBroker account has been created.",
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "user_id": user_id,
                "full_name": full_name,
                "email": email,
                "mobile_number": mobile
            }
        }

    except ClientError as error:

        error_code = error.response["Error"]["Code"]

        if error_code == "ConditionalCheckFailedException":
            raise HTTPException(
                status_code=409,
                detail=(
                    "This User ID is already taken. "
                    "Please choose another User ID."
                )
            )

        raise HTTPException(
            status_code=503,
            detail="Signup failed. Please try again."
        )


# ---------------- LOGIN ----------------

@app.post("/auth/login")
def login(data: LoginRequest):

    user_id = normalize_user_id(data.user_id)

    try:
        response = users_table.get_item(
            Key={"USERS_ID": user_id},
            ConsistentRead=True
        )

        user = response.get("Item")

        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid User ID or Password."
            )

        if user.get("ACCOUNT_STATUS") != "ACTIVE":
            raise HTTPException(
                status_code=403,
                detail="This account is not active."
            )

        password_hash = user.get("PASSWORD_HASH")

        if not password_hash or not password_hasher.verify(
            data.password,
            password_hash
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid User ID or Password."
            )

        token = create_access_token(user_id)

        return {
            "success": True,
            "message": "Login successful.",
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "user_id": user_id,
                "full_name": user.get("FULL_NAME", ""),
                "email": user.get("EMAIL", ""),
                "mobile_number": user.get("MOBILE_NUMBER", "")
            }
        }

    except HTTPException:
        raise

    except ClientError:
        raise HTTPException(
            status_code=503,
            detail="Login service is temporarily unavailable."
        )
        
