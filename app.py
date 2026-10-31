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

API_KEY = os.getenv("LLM_API_KEY") or ""
BASE_URL = os.getenv("LLM_BASE_URL") or "https://api.meta.ai/v1"
MODEL = os.getenv("LLM_MODEL") or "muse-spark-1.1"
AI_ENABLED = bool(API_KEY) and API_KEY != "dummy"
client = OpenAI(api_key=API_KEY or "dummy", base_url=BASE_URL)


class Message(BaseModel):
    text: str


RULES = [
    {"title": "Pressure to act fast", "weight": 25,
     "explain": "Scammers create panic so you act before you think.",
     "words": ["urgent", "immediately", "within 24 hours", "last chance",
               "final notice", "expire", "expires", "உடனே"]},
    {"title": "Asks for private or bank details", "weight": 30,
     "explain": "Real banks never ask for OTP, PIN, CVV or passwords by SMS or call.",
     "words": ["otp", "kyc", "pan card", "aadhaar", "upi pin", "cvv", "password",
               "card number", "verify now", "update now"]},
    {"title": "Threat of block or legal action", "weight": 25,
     "explain": "Threats about blocked accounts or arrest are used to scare people.",
     "words": ["blocked", "suspended", "account will be", "legal action", "arrest",
               "police", "sim card", "disconnected", "முடக்கம்"]},
    {"title": "Too-good-to-be-true reward", "weight": 25,
     "explain": "Unexpected prizes, refunds or easy money are common bait.",
     "words": ["winner", "prize", "lottery", "congratulations", "cashback", "refund",
               "loan approved", "double your money", "பரிசு", "லாட்டரி"]},
    {"title": "Suspicious job or investment offer", "weight": 20,
     "explain": "Easy daily earnings and work-from-home offers are a common scam.",
     "words": ["work from home", "part time job", "earn daily", "investment"]},
    {"title": "Fake delivery or customs notice", "weight": 20,
     "explain": "Scammers pretend a parcel is stuck and ask for a small payment.",
     "words": ["parcel", "customs", "courier"]},
]

SHORTENERS = r"bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|t\.co|is\.gd"
ODD_TLDS = r"\.(xyz|top|click|buzz|icu|vip|work|loan|monster)(?![a-z])"


def find_words(low, words):
    found = []
    for w in words:
        if w.isascii():
            if re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", low):
                found.append(w)
        elif w in low:
            found.append(w)
    return found


def analyze_rules(text):
    low = text.lower()
    findings = []
    matched = []
    score = 0

    for r in RULES:
        found = find_words(low, r["words"])
        if found:
            score += r["weight"]
            matched += found
            findings.append({"title": r["title"], "explain": r["explain"], "found": found})

    links = re.findall(r"(?:https?://|www\.)\S+", low)
    if links or re.search(SHORTENERS, low):
        weight = 25
        explain = "Do not open links in unexpected messages. Real banks and delivery companies use their official app or website."
        if re.search(SHORTENERS, low) or re.search(ODD_TLDS, low):
            weight += 15
            explain = "This link uses a shortener or an unusual web address. Scammers use these to hide where the link really goes."
        score += weight
        findings.append({"title": "Suspicious link", "explain": explain,
                         "found": [l.rstrip(".,)") for l in links]})

    score = min(100, score)
    verdict = "scam" if score >= 60 else "suspicious" if score >= 25 else "safe"

    if findings:
        reason = "Flagged for: " + ", ".join(f["title"].lower() for f in findings) + "."
    else:
        reason = "No common scam warning signs were found. This does not guarantee the message is safe."

    if verdict == "scam":
        advice = ("Do not click the link or reply. Never share OTP, PIN or card details. "
                  "Open your bank's official app or website, or call the number printed on your card. "
                  "You can report it at cybercrime.gov.in or call 1930.")
    elif verdict == "suspicious":
        advice = ("Do not click any link yet. Check with the company using its official app, "
                  "website or the number on your card.")
    else:
        advice = "No common warning signs found, but never share your OTP or PIN with anyone."

    return {"verdict": verdict, "risk_score": score, "reason": reason, "advice": advice,
            "findings": findings, "matched": matched, "mode": "rules"}


PROMPT = """You are a scam SMS detector for users in India. Analyze the message and reply ONLY with JSON:
{"verdict": "safe" | "suspicious" | "scam",
 "risk_score": 0-100,
 "reason": "one or two plain sentences",
 "advice": "a specific safe next step"}"""


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.post("/analyze")
def analyze(msg: Message):
    text = msg.text.strip()[:2000]
    result = analyze_rules(text)

    if AI_ENABLED:
        try:
            res = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": PROMPT},
                    {"role": "user", "content": text},
                ],
                temperature=0,
            )
            raw = res.choices[0].message.content
            ai = json.loads(re.search(r"\{.*\}", raw, re.S).group())
            if ai.get("verdict") in ("safe", "suspicious", "scam"):
                result["verdict"] = ai["verdict"]
                result["risk_score"] = int(ai.get("risk_score", result["risk_score"]))
                result["reason"] = ai.get("reason") or result["reason"]
                result["advice"] = ai.get("advice") or result["advice"]
                result["mode"] = "ai"
        except Exception as e:
            print("AI call failed, using rules:", e)

    return result