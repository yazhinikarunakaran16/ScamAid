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
client = OpenAI(api_key=API_KEY or "dummy", base_url=BASE_URL, timeout=40, max_retries=0)


class Message(BaseModel):
    text: str


RULES = [
    {"title": "Pressure to act fast", "weight": 25,
     "title_ta": "உடனே செயல்பட அழுத்தம்",
     "explain": "Scammers create panic so you act before you think.",
     "explain_ta": "நீங்கள் யோசிப்பதற்குள் செயல்பட வைக்க மோசடியாளர்கள் பயத்தை உருவாக்குகிறார்கள்.",
     "words": ["urgent", "immediately", "within 24 hours", "last chance",
               "final notice", "expire", "expires", "உடனே"]},
    {"title": "Asks for private or bank details", "weight": 30,
     "title_ta": "தனிப்பட்ட அல்லது வங்கி விவரங்களைக் கேட்கிறது",
     "explain": "Real banks never ask for OTP, PIN, CVV or passwords by SMS or call.",
     "explain_ta": "உண்மையான வங்கிகள் OTP, PIN, CVV அல்லது கடவுச்சொல்லை SMS அல்லது அழைப்பில் ஒருபோதும் கேட்காது.",
     "words": ["otp", "kyc", "pan card", "aadhaar", "upi pin", "cvv", "password",
               "card number", "verify now", "update now"]},
    {"title": "Threat of block or legal action", "weight": 25,
     "title_ta": "கணக்கு முடக்கம் அல்லது சட்ட நடவடிக்கை மிரட்டல்",
     "explain": "Threats about blocked accounts or arrest are used to scare people.",
     "explain_ta": "கணக்கு முடக்கம் அல்லது கைது பற்றிய மிரட்டல்கள் மக்களை பயமுறுத்த பயன்படுத்தப்படுகின்றன.",
     "words": ["blocked", "suspended", "account will be", "legal action", "arrest",
               "police", "sim card", "disconnected", "முடக்கம்"]},
    {"title": "Too-good-to-be-true reward", "weight": 25,
     "title_ta": "நம்ப முடியாத பரிசு அல்லது வெகுமதி",
     "explain": "Unexpected prizes, refunds or easy money are common bait.",
     "explain_ta": "எதிர்பாராத பரிசு, பணத்திருப்பம் அல்லது எளிதான பணம் ஆகியவை பொதுவான தூண்டில்கள்.",
     "words": ["winner", "prize", "lottery", "congratulations", "cashback", "refund",
               "loan approved", "double your money", "பரிசு", "லாட்டரி"]},
    {"title": "Suspicious job or investment offer", "weight": 30,
     "title_ta": "சந்தேகத்திற்குரிய வேலை அல்லது முதலீட்டு வாய்ப்பு",
     "explain": "Easy daily earnings and work-from-home offers are a common scam.",
     "explain_ta": "தினமும் எளிதாக சம்பாதிக்கலாம், வீட்டிலிருந்தே வேலை போன்ற வாய்ப்புகள் பொதுவான மோசடி.",
     "words": ["work from home", "part time job", "part time work", "earn daily",
               "whatsapp group", "per day", "investment"]},
    {"title": "Fake delivery or customs notice", "weight": 20,
     "title_ta": "போலி டெலிவரி அல்லது சுங்க அறிவிப்பு",
     "explain": "Scammers pretend a parcel is stuck and ask for a small payment.",
     "explain_ta": "பார்சல் சிக்கிக்கொண்டது என்று கூறி சிறிய தொகை செலுத்தச் சொல்வது மோசடியாளர்களின் வழக்கம்.",
     "words": ["parcel", "customs", "courier"]},
]

SHORTENERS = r"bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|t\.co|is\.gd"
ODD_TLDS = r"\.(xyz|top|click|buzz|icu|vip|work|loan|monster)(?![a-z])"

ADVICE_EN = {
    "scam": ("Do not click the link or reply. Never share OTP, PIN or card details. "
             "Open your bank's official app or website, or call the number printed on your card. "
             "You can report it at cybercrime.gov.in or call 1930."),
    "suspicious": ("Do not click any link yet. Check with the company using its official app, "
                   "website or the number on your card."),
    "safe": "No common warning signs found, but never share your OTP or PIN with anyone.",
}

ADVICE_TA = {
    "scam": ("இணைப்பைத் தொடாதீர்கள், பதிலும் அனுப்பாதீர்கள். OTP, PIN அல்லது கார்டு விவரங்களை யாரிடமும் பகிராதீர்கள். "
             "உங்கள் வங்கியின் அதிகாரப்பூர்வ செயலி அல்லது இணையதளத்தைத் திறக்கவும், அல்லது கார்டில் அச்சிடப்பட்ட எண்ணை அழைக்கவும். "
             "cybercrime.gov.in இல் புகாரளிக்கலாம் அல்லது 1930 ஐ அழைக்கலாம்."),
    "suspicious": ("இப்போதைக்கு எந்த இணைப்பையும் தொடாதீர்கள். நிறுவனத்தின் அதிகாரப்பூர்வ செயலி, "
                   "இணையதளம் அல்லது கார்டில் உள்ள எண் மூலம் உறுதிசெய்யுங்கள்."),
    "safe": "பொதுவான எச்சரிக்கை அறிகுறிகள் எதுவும் இல்லை. ஆனாலும் உங்கள் OTP அல்லது PIN ஐ யாரிடமும் பகிராதீர்கள்.",
}


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
            findings.append({"title": r["title"], "title_ta": r["title_ta"],
                             "explain": r["explain"], "explain_ta": r["explain_ta"],
                             "found": found})

    links = re.findall(r"(?:https?://|www\.)\S+", low)
    if links or re.search(SHORTENERS, low):
        weight = 25
        explain = "Do not open links in unexpected messages. Real banks and delivery companies use their official app or website."
        explain_ta = "எதிர்பாராத செய்திகளில் உள்ள இணைப்புகளைத் திறக்காதீர்கள். உண்மையான வங்கிகளும் டெலிவரி நிறுவனங்களும் தங்கள் அதிகாரப்பூர்வ செயலி அல்லது இணையதளத்தையே பயன்படுத்தும்."
        if re.search(SHORTENERS, low) or re.search(ODD_TLDS, low):
            weight += 15
            explain = "This link uses a shortener or an unusual web address. Scammers use these to hide where the link really goes."
            explain_ta = "இந்த இணைப்பு சுருக்கப்பட்ட அல்லது வழக்கத்துக்கு மாறான முகவரியைப் பயன்படுத்துகிறது. இணைப்பு உண்மையில் எங்கு செல்கிறது என்பதை மறைக்க மோசடியாளர்கள் இதைப் பயன்படுத்துகிறார்கள்."
        score += weight
        findings.append({"title": "Suspicious link", "title_ta": "சந்தேகத்திற்குரிய இணைப்பு",
                         "explain": explain, "explain_ta": explain_ta,
                         "found": [l.rstrip(".,)") for l in links]})

    if re.search(r"(do not|don't|never) share", low) and not links:
        score = max(0, score - 20)

    score = min(100, score)
    verdict = "scam" if score >= 60 else "suspicious" if score >= 25 else "safe"

    if findings:
        reason = "Flagged for: " + ", ".join(f["title"].lower() for f in findings) + "."
        reason_ta = "எச்சரிக்கை அறிகுறிகள்: " + ", ".join(f["title_ta"] for f in findings) + "."
    else:
        reason = "No common scam warning signs were found. This does not guarantee the message is safe."
        reason_ta = "பொதுவான மோசடி எச்சரிக்கை அறிகுறிகள் எதுவும் கண்டறியப்படவில்லை. இது செய்தி பாதுகாப்பானது என்பதற்கான உத்தரவாதம் அல்ல."

    return {"verdict": verdict, "risk_score": score,
            "reason": reason, "reason_ta": reason_ta,
            "advice": ADVICE_EN[verdict], "advice_ta": ADVICE_TA[verdict],
            "findings": findings, "matched": matched, "mode": "rules"}


PROMPT = """You are a scam SMS detector for users in India. Analyze the message and reply ONLY with JSON:
{"verdict": "safe" | "suspicious" | "scam",
 "risk_score": 0-100,
 "reason": "one or two plain English sentences",
 "advice": "a specific safe next step in English",
 "reason_ta": "the same reason in simple Tamil",
 "advice_ta": "the same advice in simple Tamil"}"""


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
                v = ai["verdict"]
                result["verdict"] = v
                result["risk_score"] = int(ai.get("risk_score", result["risk_score"]))
                result["reason"] = ai.get("reason") or result["reason"]
                result["advice"] = ai.get("advice") or ADVICE_EN[v]
                result["reason_ta"] = ai.get("reason_ta") or result["reason_ta"]
                result["advice_ta"] = ai.get("advice_ta") or ADVICE_TA[v]
                result["mode"] = "ai"
        except Exception as e:
            print("AI call failed, using rules:", e)

    return result