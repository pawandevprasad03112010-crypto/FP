import os
import random
import time
import uuid
from decimal import Decimal
from typing import Any, Optional

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="OnlyBroker API", version="1.8.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# AWS DynamoDB Configuration
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")

LISTINGS_TABLE_NAME = os.getenv("LISTINGS_TABLE", "LARGE_PROPERTY_LISTING")
LISTINGS_PK = "property_id"

USERS_TABLE_NAME = os.getenv("USERS_TABLE", "USERS")
USERS_PK = "USERS_ID"

_dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
_listings_table = _dynamodb.Table(LISTINGS_TABLE_NAME)
_users_table = _dynamodb.Table(USERS_TABLE_NAME)

# Temporary OTP store + fallback cache
_otp_store: dict[str, dict[str, Any]] = {}
_fallback_users_by_phone: dict[str, dict[str, Any]] = {}
_fallback_users_by_id: dict[str, dict[str, Any]] = {}
OTP_TTL_SECONDS = 300

_FALLBACK_LISTINGS: list[dict[str, Any]] = [
    {
        "property_id": "OB-PROP-101",
        "title": "3 BHK Luxury Sky Residence",
        "city": "Mumbai",
        "locality": "Bandra West",
        "price": "₹4.25 Cr",
        "category": "Buy",
        "broker_name": "Direct Broker Network",
    },
    {
        "property_id": "OB-PROP-102",
        "title": "2 BHK Modern Park View Flat",
        "city": "Kolkata",
        "locality": "Salt Lake Sector V",
        "price": "₹38,000 / mo",
        "category": "Rent",
        "broker_name": "OnlyBroker Verified",
    },
]


def _clean_dynamo_value(val: Any) -> Any:
    if isinstance(val, Decimal):
        return int(val) if val % 1 == 0 else float(val)
    if isinstance(val, list):
        return [_clean_dynamo_value(v) for v in val]
    if isinstance(val, dict):
        return {k: _clean_dynamo_value(v) for k, v in val.items()}
    return val


def _normalize_phone(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    return digits[-10:] if len(digits) >= 10 else digits


def _build_user_json(
    users_id: str,
    username: str,
    phone: str,
    created_at: int,
    last_login_at: int,
) -> dict[str, Any]:
    # Ordered keys: USERS_ID first, then username, then phone
    return {
        "USERS_ID": str(users_id),
        "username": username.strip(),
        "phone": phone,
        "platform": "OnlyBroker",
        "created_at": created_at,
        "last_login_at": last_login_at,
    }


def _users_id_exists(users_id: str) -> bool:
    if users_id in _fallback_users_by_id:
        return True
    try:
        resp = _users_table.get_item(Key={USERS_PK: str(users_id)})
        return "Item" in resp and resp["Item"] is not None
    except (ClientError, BotoCoreError, Exception):
        return False


def _get_max_serial_id() -> int:
    max_num = 0
    for uid in _fallback_users_by_id.keys():
        if uid.isdigit():
            max_num = max(max_num, int(uid))

    try:
        scan_kwargs: dict[str, Any] = {"ProjectionExpression": USERS_PK}
        while True:
            resp = _users_table.scan(**scan_kwargs)
            for item in resp.get("Items", []):
                raw_id = str(item.get(USERS_PK, "")).strip()
                if raw_id.isdigit():
                    max_num = max(max_num, int(raw_id))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
    except (ClientError, BotoCoreError, Exception):
        pass

    return max_num


def _next_serial_users_id() -> str:
    num = _get_max_serial_id() + 1
    while _users_id_exists(str(num)):
        num += 1
    return str(num)


def _find_user_by_phone(phone: str) -> Optional[dict[str, Any]]:
    try:
        scan_kwargs: dict[str, Any] = {"FilterExpression": Attr("phone").eq(phone)}
        while True:
            resp = _users_table.scan(**scan_kwargs)
            items = [_clean_dynamo_value(i) for i in resp.get("Items", [])]
            if items:
                return items[0]
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
    except (ClientError, BotoCoreError, Exception):
        pass

    return _fallback_users_by_phone.get(phone)


def _find_user_by_id(users_id: str) -> Optional[dict[str, Any]]:
    clean_id = str(users_id).strip()
    try:
        resp = _users_table.get_item(Key={USERS_PK: clean_id})
        item = resp.get("Item")
        if item:
            return _clean_dynamo_value(item)
    except (ClientError, BotoCoreError, Exception):
        pass

    return _fallback_users_by_id.get(clean_id)


def _process_auth_user(
    username: str,
    phone: str,
    mode: str = "auto",
) -> tuple[dict[str, Any], bool]:
    clean_name = username.strip()
    now_ts = int(time.time())
    existing = _find_user_by_phone(phone)

    if existing:
        existing_uid = str(existing.get(USERS_PK) or "").strip()
        if not existing_uid:
            existing_uid = _next_serial_users_id()
        created_at = int(existing.get("created_at", now_ts))
        final_name = clean_name or str(existing.get("username") or existing.get("name") or "")
        user_json = _build_user_json(
            users_id=existing_uid,
            username=final_name,
            phone=phone,
            created_at=created_at,
            last_login_at=now_ts,
        )
        _fallback_users_by_phone[phone] = user_json
        _fallback_users_by_id[existing_uid] = user_json
        try:
            _users_table.put_item(Item=user_json)
        except (ClientError, BotoCoreError, Exception):
            pass
        return user_json, False

    if mode == "login":
        raise HTTPException(status_code=404, detail="पहले साइन अप करो")

    for _ in range(25):
        serial_id = _next_serial_users_id()
        if _users_id_exists(serial_id):
            continue

        new_user_json = _build_user_json(
            users_id=serial_id,
            username=clean_name,
            phone=phone,
            created_at=now_ts,
            last_login_at=now_ts,
        )

        try:
            _users_table.put_item(
                Item=new_user_json,
                ConditionExpression=f"attribute_not_exists({USERS_PK})",
            )
            _fallback_users_by_phone[phone] = new_user_json
            _fallback_users_by_id[serial_id] = new_user_json
            return new_user_json, True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                continue
            _fallback_users_by_phone[phone] = new_user_json
            _fallback_users_by_id[serial_id] = new_user_json
            return new_user_json, True
        except (BotoCoreError, Exception):
            _fallback_users_by_phone[phone] = new_user_json
            _fallback_users_by_id[serial_id] = new_user_json
            return new_user_json, True

    raise HTTPException(status_code=409, detail="Could not assign serial USERS_ID")


class SendOtpRequest(BaseModel):
    name: str = Field(default="", max_length=100)
    phone: str = Field(..., min_length=10, max_length=15)
    mode: str = Field(default="auto")


class VerifyOtpRequest(BaseModel):
    name: str = Field(default="", max_length=100)
    phone: str = Field(..., min_length=10, max_length=15)
    otp: str = Field(..., min_length=4, max_length=6)
    mode: str = Field(default="auto")


class CreateListingRequest(BaseModel):
    property_id: Optional[str] = None
    title: str = Field(..., min_length=2, max_length=160)
    city: str = Field(..., min_length=2, max_length=80)
    locality: str = Field(default="", max_length=120)
    price: str = Field(..., min_length=1, max_length=60)
    category: str = Field(default="Buy", max_length=40)
    broker_name: str = Field(default="OnlyBroker Partner", max_length=100)
    broker_phone: Optional[str] = None


@app.get("/")
def health_check():
    return {
        "status": "ok",
        "service": "OnlyBroker API",
        "region": AWS_REGION,
        "users_table": USERS_TABLE_NAME,
        "users_pk": USERS_PK,
        "listings_table": LISTINGS_TABLE_NAME,
        "listings_pk": LISTINGS_PK,
    }


@app.post("/send-otp")
def send_otp(payload: SendOtpRequest):
    clean_phone = _normalize_phone(payload.phone)
    if len(clean_phone) < 10:
        raise HTTPException(status_code=400, detail="पहले साइन अप करो: मान्य नंबर दर्ज करें")

    existing = _find_user_by_phone(clean_phone)
    if payload.mode == "login" and not existing:
        raise HTTPException(status_code=404, detail="पहले साइन अप करो")

    if payload.mode != "login" and not payload.name.strip() and not existing:
        raise HTTPException(status_code=400, detail="पहले साइन अप करो: अपना नाम दर्ज करें")

    otp_code = f"{random.randint(1000, 9999)}"
    _otp_store[clean_phone] = {
        "name": payload.name.strip() or (str(existing.get("username", "")) if existing else ""),
        "otp": otp_code,
        "mode": payload.mode,
        "expires_at": time.time() + OTP_TTL_SECONDS,
    }

    return {
        "success": True,
        "message": "OTP generated",
        "phone": clean_phone,
        "existing_user": existing is not None,
        "USERS_ID": existing.get(USERS_PK) if existing else None,
        "debug_otp": otp_code,
    }


@app.post("/verify-otp")
def verify_otp(payload: VerifyOtpRequest):
    clean_phone = _normalize_phone(payload.phone)
    record = _otp_store.get(clean_phone)

    if not record:
        raise HTTPException(status_code=400, detail="पहले साइन अप करो या पहले OTP भेजें")
    if time.time() > record["expires_at"]:
        _otp_store.pop(clean_phone, None)
        raise HTTPException(status_code=400, detail="OTP समाप्त हो गया है, दोबारा कोशिश करें")
    if payload.otp.strip() != record["otp"]:
        raise HTTPException(status_code=400, detail="गलत OTP दर्ज किया गया है")

    effective_mode = payload.mode or record.get("mode", "auto")
    effective_name = payload.name.strip() or str(record.get("name", ""))

    user_json, is_new = _process_auth_user(
        username=effective_name,
        phone=clean_phone,
        mode=effective_mode,
    )
    _otp_store.pop(clean_phone, None)

    return {
        "success": True,
        "message": "Signup complete" if is_new else "Login complete",
        "is_new_user": is_new,
        "USERS_ID": user_json["USERS_ID"],
        "username": user_json["username"],
        "phone": user_json["phone"],
        "user": user_json,
    }


@app.get("/users/{users_id}")
def get_user_by_id(users_id: str):
    item = _find_user_by_id(users_id)
    if not item:
        raise HTTPException(status_code=404, detail="पहले साइन अप करो")
    return {"success": True, "user": item}


@app.get("/properties")
def get_listings(
    city: Optional[str] = Query(default=None),
    limit: int = Query(default=40, ge=1, le=100),
):
    source = LISTINGS_TABLE_NAME
    try:
        resp = _listings_table.scan(Limit=limit)
        raw_items = resp.get("Items", [])
        items = [_clean_dynamo_value(item) for item in raw_items]
        if not items:
            items = _FALLBACK_LISTINGS
            source = "fallback"
    except (ClientError, BotoCoreError, Exception):
        items = _FALLBACK_LISTINGS
        source = "fallback"

    if city and city.strip():
        q = city.strip().lower()
        items = [
            item
            for item in items
            if q in str(item.get("city", "")).lower()
            or q in str(item.get("locality", "")).lower()
            or q in str(item.get("title", "")).lower()
        ]

    return {
        "success": True,
        "source": source,
        "count": len(items),
        "properties": items,
    }


@app.get("/properties/{property_id}")
def get_single_listing(property_id: str):
    try:
        resp = _listings_table.get_item(Key={LISTINGS_PK: property_id})
        item = resp.get("Item")
        if item:
            return {"success": True, "property": _clean_dynamo_value(item)}
    except (ClientError, BotoCoreError, Exception):
        pass

    for sample in _FALLBACK_LISTINGS:
        if sample[LISTINGS_PK] == property_id:
            return {"success": True, "property": sample}

    raise HTTPException(status_code=404, detail="Property not found")


@app.post("/properties")
def add_listing(payload: CreateListingRequest):
    prop_id = (payload.property_id or f"OB-{uuid.uuid4().hex[:8].upper()}").strip()
    item: dict[str, Any] = {
        LISTINGS_PK: prop_id,
        "title": payload.title.strip(),
        "city": payload.city.strip(),
        "locality": payload.locality.strip(),
        "price": payload.price.strip(),
        "category": payload.category.strip(),
        "broker_name": payload.broker_name.strip(),
        "created_at": int(time.time()),
    }
    if payload.broker_phone:
        item["broker_phone"] = _normalize_phone(payload.broker_phone)

    try:
        _listings_table.put_item(Item=item)
    except (ClientError, BotoCoreError, Exception) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save in {LISTINGS_TABLE_NAME}: {exc}",
        )

    return {
        "success": True,
        "table": LISTINGS_TABLE_NAME,
        "property": item,
        }
    
