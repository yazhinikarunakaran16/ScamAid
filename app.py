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

def rule_check(text: str):
    flags = []
    low = text.lower()
    for w in SUSPICIOUS_WORDS:
        if w in low:
            flags.append(f"Suspicious word: {w}")
    if re.search(r"https?://|bit\.ly|tinyurl", low):
        flags.append("Contains a link")
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