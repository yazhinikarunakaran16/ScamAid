import os, re, json
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="ScamAid")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

client = OpenAI(
    api_key=os.getenv("LLM_API_KEY") or "dummy",
    base_url=os.getenv("LLM_BASE_URL") or "https://api.meta.ai/v1",
)
MODEL = os.getenv("LLM_MODEL")

class Message(BaseModel):
    text: str

SUSPICIOUS_WORDS = ["urgent", "otp", "kyc", "blocked", "winner", "prize",
                    "lottery", "click here", "verify now", "refund", "suspended"]

SUSPICIOUS_WORDS = [
    "urgent", "immediately", "otp", "kyc", "pan card", "aadhaar", "blocked",
    "suspended", "expire", "winner", "prize", "lottery", "congratulations",
    "click here", "verify now", "update now", "refund", "cashback",
    "upi pin", "cvv", "password", "electricity bill", "disconnected",
    "parcel", "customs", "courier", "work from home", "part time job",
    "earn daily", "investment", "double your money", "loan approved",
    "account will be", "legal action", "arrest", "police", "sim card",
    "பரிசு", "லாட்டரி", "உடனே", "வங்கி", "கணக்கு", "முடக்கம்",
]

def rule_check(text: str):
    flags = []
    low = text.lower()
    for w in SUSPICIOUS_WORDS:
        if w in low:
            flags.append(f"Suspicious word: {w}")
    if re.search(r"https?://|www\.|bit\.ly|tinyurl|\.xyz|\.top|\.click", low):
        flags.append("Contains a link")
    if re.search(r"\b\d{4,8}\b", low) and "otp" in low:
        flags.append("Mentions an OTP code")
    return flags

PROMPT = """You are a scam SMS detector. Analyze the message and reply ONLY with JSON:
{"verdict": "safe" | "suspicious" | "scam",
 "risk_score": 0-100,
 "reason": "short explanation",
 "advice": "what the user should do"}"""

@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(request, "index.html")

@app.post("/analyze")
def analyze(msg: Message):
    flags = rule_check(msg.text)
    try:
        res = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": PROMPT},
                {"role": "user", "content": msg.text},
            ],
            temperature=0,
        )
        raw = res.choices[0].message.content
        data = json.loads(re.search(r"\{.*\}", raw, re.S).group())
    except Exception as e:
        data = {"verdict": "suspicious", "risk_score": 50,
                "reason": "AI analysis failed", "advice": "Be careful."}
    data["flags"] = flags
    return data