from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import random

app = FastAPI(title="OTP Login Backend")

# Flutter Web / Mobile से कॉल करने के लिए CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# मेमोरी में OTP स्टोर करने के लिए (प्रोडक्शन में Redis या Database इस्तेमाल करें)
otp_store: dict[str, str] = {}


class SendOtpRequest(BaseModel):
    name: str = Field(..., min_length=1)
    phone: str = Field(..., min_length=10, max_length=15)


class VerifyOtpRequest(BaseModel):
    name: str = Field(..., min_length=1)
    phone: str = Field(..., min_length=10, max_length=15)
    otp: str = Field(..., min_length=4, max_length=6)


@app.get("/")
def root():
    return {"status": "ok", "message": "Login OTP Backend is running"}


@app.post("/send-otp")
def send_otp(data: SendOtpRequest):
    phone_clean = data.phone.strip()
    otp = f"{random.randint(1000, 9999)}"
    otp_store[phone_clean] = otp

    # Render Logs में OTP दिखेगा (टेस्टिंग के लिए)
    print(f"[OTP] Name: {data.name.strip()} | Phone: {phone_clean} | OTP: {otp}")

    # डेमो के लिए debug_otp भेज रहे हैं; लाइव SMS गेटवे लगाने पर इसे हटा दें
    return {
        "success": True,
        "message": f"OTP sent to {phone_clean}",
        "debug_otp": otp,
    }


@app.post("/verify-otp")
def verify_otp(data: VerifyOtpRequest):
    phone_clean = data.phone.strip()
    otp_clean = data.otp.strip()
    saved_otp = otp_store.get(phone_clean)

    if not saved_otp or saved_otp != otp_clean:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # सफल लॉगिन के बाद OTP हटा दें
    del otp_store[phone_clean]

    return {
        "success": True,
        "message": "Login successful",
        "user": {
            "name": data.name.strip(),
            "phone": phone_clean,
        },
    }
