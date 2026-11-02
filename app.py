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

# API key stays on the server only. It is never sent to the browser.
API_KEY = os.getenv("LLM_API_KEY") or ""
BASE_URL = os.getenv("LLM_BASE_URL") or "https://api.meta.ai/v1"
MODEL = os.getenv("LLM_MODEL") or "muse-spark-1.1"
AI_ENABLED = bool(API_KEY) and API_KEY != "dummy"
client = OpenAI(api_key=API_KEY or "dummy", base_url=BASE_URL, timeout=40, max_retries=0)


class Message(BaseModel):
    text: str


NOTES = {
    "kyc": ("KYC request: Banks do not ask you to update KYC through a link in an SMS. Scammers say 'KYC update' to steal your login or card details.",
            "KYC கோரிக்கை: வங்கிகள் SMS இணைப்பு மூலம் KYC புதுப்பிக்கச் சொல்வதில்லை. மோசடியாளர்கள் 'KYC' என்று கூறி உங்கள் லாகின் அல்லது கார்டு விவரங்களைத் திருடுகிறார்கள்."),
    "otp": ("OTP request: An OTP is a key to your money. Never share it. Anyone who asks for it is trying to approve a payment from your account.",
            "OTP கோரிக்கை: OTP என்பது உங்கள் பணத்தின் சாவி. யாரிடமும் பகிராதீர்கள். அதைக் கேட்பவர் உங்கள் கணக்கிலிருந்து பணம் எடுக்க முயல்கிறார்."),
    "upi pin": ("UPI PIN request: You enter a UPI PIN only to send money, never to receive it or to 'verify'.",
                "UPI PIN கோரிக்கை: UPI PIN பணம் அனுப்ப மட்டுமே. பெறுவதற்கோ 'சரிபார்ப்பதற்கோ' தேவையில்லை."),
    "cvv": ("CVV request: Your card's CVV lets others pay online with your card. Never share it.",
            "CVV கோரிக்கை: CVV இருந்தால் மற்றவர்கள் உங்கள் கார்டில் ஆன்லைனில் பணம் செலுத்த முடியும். பகிராதீர்கள்."),
    "password": ("Password request: Real companies never ask for your password by message.",
                 "கடவுச்சொல் கோரிக்கை: உண்மையான நிறுவனங்கள் செய்தியில் கடவுச்சொல் கேட்காது."),
    "aadhaar": ("Aadhaar request: Aadhaar details can be misused for fake loans and SIM cards.",
                "ஆதார் கோரிக்கை: ஆதார் விவரங்கள் போலிக் கடன், சிம் கார்டுகளுக்குத் தவறாகப் பயன்படுத்தப்படலாம்."),
    "pan card": ("PAN request: PAN details can be misused for fake loans and fraud.",
                 "PAN கோரிக்கை: PAN விவரங்கள் போலிக் கடன், மோசடிக்குத் தவறாகப் பயன்படுத்தப்படலாம்."),
    "card number": ("Card number request: Banks never ask for your full card number by message.",
                    "கார்டு எண் கோரிக்கை: வங்கிகள் செய்தியில் முழு கார்டு எண்ணைக் கேட்காது."),
    "verify now": ("'Verify now' pressure: Scammers push you to verify through a link so you enter your details on a fake page.",
                   "'இப்போதே சரிபார்' அழுத்தம்: போலி பக்கத்தில் விவரங்களை உள்ளிட வைக்க இணைப்பு மூலம் சரிபார்க்கச் சொல்கிறார்கள்."),
    "update now": ("'Update now' pressure: Scammers push you to update details through a link so you enter them on a fake page.",
                   "'இப்போதே புதுப்பி' அழுத்தம்: போலி பக்கத்தில் விவரங்களை உள்ளிட வைக்க இணைப்பு மூலம் புதுப்பிக்கச் சொல்கிறார்கள்."),
}

RULES = [
    {"key": "urgency", "title": "Pressure to act fast", "weight": 25,
     "title_ta": "உடனே செயல்பட அழுத்தம்",
     "explain": "Scammers create pressure so you act before you think.",
     "explain_ta": "நீங்கள் யோசிப்பதற்குள் செயல்பட வைக்க மோசடியாளர்கள் அழுத்தம் உருவாக்குகிறார்கள்.",
     "words": ["urgent", "immediately", "within 24 hours", "last chance",
               "final notice", "expire", "expires", "உடனே"]},
    {"key": "private", "title": "Asks for private or bank details", "weight": 30,
     "title_ta": "தனிப்பட்ட அல்லது வங்கி விவரங்களைக் கேட்கிறது",
     "explain": "Asks for KYC, OTP or bank details. Real banks never ask for these by SMS or call.",
     "explain_ta": "KYC, OTP அல்லது வங்கி விவரங்களைக் கேட்கிறது. உண்மையான வங்கிகள் இவற்றை SMS அல்லது அழைப்பில் கேட்காது.",
     "words": ["otp", "kyc", "pan card", "aadhaar", "upi pin", "cvv", "password",
               "card number", "verify now", "update now"]},
    {"key": "threat", "title": "Threat of block or legal action", "weight": 25,
     "title_ta": "கணக்கு முடக்கம் அல்லது சட்ட நடவடிக்கை மிரட்டல்",
     "explain": "Threats like 'your account will be blocked today' are used to create panic.",
     "explain_ta": "'இன்றே உங்கள் கணக்கு முடக்கப்படும்' போன்ற மிரட்டல்கள் பயத்தை உருவாக்கப் பயன்படுகின்றன.",
     "words": ["blocked", "suspended", "account will be", "legal action", "arrest",
               "police", "sim card", "disconnected", "முடக்கம்"]},
    {"key": "reward", "title": "Too-good-to-be-true reward", "weight": 25,
     "title_ta": "நம்ப முடியாத பரிசு அல்லது வெகுமதி",
     "explain": "Unexpected prizes, refunds or easy money are common bait.",
     "explain_ta": "எதிர்பாராத பரிசு, பணத்திருப்பம் அல்லது எளிதான பணம் ஆகியவை பொதுவான தூண்டில்கள்.",
     "words": ["winner", "prize", "lottery", "congratulations", "cashback", "refund",
               "loan approved", "double your money", "பரிசு", "லாட்டரி"]},
    {"key": "job", "title": "Suspicious job or investment offer", "weight": 30,
     "title_ta": "சந்தேகத்திற்குரிய வேலை அல்லது முதலீட்டு வாய்ப்பு",
     "explain": "Easy daily earnings and work-from-home offers are a common scam.",
     "explain_ta": "தினமும் எளிதாக சம்பாதிக்கலாம், வீட்டிலிருந்தே வேலை போன்ற வாய்ப்புகள் பொதுவான மோசடி.",
     "words": ["work from home", "part time job", "part time work", "earn daily",
               "whatsapp group", "per day", "investment"]},
    {"key": "parcel", "title": "Fake delivery or customs notice", "weight": 20,
     "title_ta": "போலி டெலிவரி அல்லது சுங்க அறிவிப்பு",
     "explain": "Scammers pretend a parcel is stuck and ask for a small payment.",
     "explain_ta": "பார்சல் சிக்கிக்கொண்டது என்று கூறி சிறிய தொகை செலுத்தச் சொல்வது மோசடியாளர்களின் வழக்கம்.",
     "words": ["parcel", "customs", "courier"]},
]

BRANDS = {
    "sbi": ("SBI", "YONO SBI app"),
    "hdfc": ("HDFC Bank", "HDFC Bank app"),
    "icici": ("ICICI Bank", "iMobile app"),
    "axis": ("Axis Bank", "Axis Mobile app"),
    "paytm": ("Paytm", "Paytm app"),
    "phonepe": ("PhonePe", "PhonePe app"),
}

SHORTENERS = r"bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|t\.co|is\.gd"
ODD_TLDS = r"\.(xyz|top|click|buzz|icu|vip|work|loan|monster)(?![a-z])"

REPORT_EN = " Report it at cybercrime.gov.in or call 1930."
REPORT_TA = " cybercrime.gov.in இல் புகாரளிக்கவும் அல்லது 1930 ஐ அழைக்கவும்."


def find_words(low, words):
    found = []
    for w in words:
        if w.isascii():
            if re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", low):
                found.append(w)
        elif w in low:
            found.append(w)
    return found


def build_advice(verdict, low, keys):
    if verdict == "safe":
        return ("No major warning signs found. If you did not expect this message, still do not click links or share your OTP or PIN.",
                "முக்கிய எச்சரிக்கை அறிகுறிகள் இல்லை. இந்தச் செய்தியை எதிர்பார்க்கவில்லை என்றால், இணைப்புகளைத் தொடாதீர்கள், OTP அல்லது PIN ஐப் பகிராதீர்கள்.")

    brand = None
    for k, val in BRANDS.items():
        if find_words(low, [k]):
            brand = val
            break

    if brand and keys & {"private", "threat", "urgency", "link"}:
        name, app_name = brand
        return (f"Do not click the link or reply. Open the official {app_name} yourself, or call the number on the back of your card. Never share OTP or PIN." + REPORT_EN,
                f"இணைப்பைத் தொடாதீர்கள், பதிலளிக்காதீர்கள். {app_name} அதிகாரப்பூர்வ செயலியை நீங்களே திறக்கவும், அல்லது கார்டின் பின்புறம் உள்ள எண்ணை அழைக்கவும். OTP, PIN ஐ யாரிடமும் பகிராதீர்கள்." + REPORT_TA)
    if "parcel" in keys:
        return ("Do not pay or click the link. Track your parcel only in the courier's official app or website." + REPORT_EN,
                "பணம் செலுத்தாதீர்கள், இணைப்பைத் தொடாதீர்கள். பார்சலை கூரியர் நிறுவனத்தின் அதிகாரப்பூர்வ செயலி அல்லது இணையதளத்தில் மட்டும் கண்காணியுங்கள்." + REPORT_TA)
    if "job" in keys:
        return ("Do not send money or join the group. Real employers never ask you to pay to get a job." + REPORT_EN,
                "பணம் அனுப்பாதீர்கள், குழுவில் சேராதீர்கள். உண்மையான நிறுவனங்கள் வேலைக்காகப் பணம் கேட்காது." + REPORT_TA)
    if "reward" in keys:
        return ("Do not pay any fee or share details to claim a prize or refund. Real prizes never ask for money first." + REPORT_EN,
                "பரிசு அல்லது பணத்திருப்பத்தைப் பெற கட்டணம் செலுத்தாதீர்கள், விவரங்களைப் பகிராதீர்கள்." + REPORT_TA)
    if verdict == "scam":
        return ("Do not click any link or reply. Never share OTP, PIN or card details. Contact the company only through its official app, website or the number on your card." + REPORT_EN,
                "இணைப்பைத் தொடாதீர்கள், பதிலளிக்காதீர்கள். OTP, PIN அல்லது கார்டு விவரங்களைப் பகிராதீர்கள். நிறுவனத்தின் அதிகாரப்பூர்வ செயலி, இணையதளம் அல்லது கார்டில் உள்ள எண் மூலம் மட்டும் தொடர்பு கொள்ளுங்கள்." + REPORT_TA)
    return ("Do not click any link yet. Check with the company using its official app, website or the number on your card.",
            "இப்போதைக்கு எந்த இணைப்பையும் தொடாதீர்கள். நிறுவனத்தின் அதிகாரப்பூர்வ செயலி, இணையதளம் அல்லது கார்டில் உள்ள எண் மூலம் உறுதிசெய்யுங்கள்.")


def analyze_rules(text):
    low = text.lower()
    findings = []
    breakdown = []
    matched = []
    score = 0

    for r in RULES:
        found = find_words(low, r["words"])
        if found:
            score += r["weight"]
            matched += found
            explain, explain_ta = r["explain"], r["explain_ta"]
            used = [NOTES[w] for w in found if w in NOTES][:2]
            if used:
                explain = " ".join(n[0] for n in used)
                explain_ta = " ".join(n[1] for n in used)
            findings.append({"key": r["key"], "title": r["title"], "title_ta": r["title_ta"],
                             "explain": explain, "explain_ta": explain_ta, "found": found})
            breakdown.append({"label": r["title"], "label_ta": r["title_ta"], "points": r["weight"]})

    links = re.findall(r"(?:https?://|www\.)\S+", low)
    short = re.findall(SHORTENERS, low)
    if links or short:
        weight = 25
        explain = "Do not use this link. Verify only through the official bank app or website."
        explain_ta = "இந்த இணைப்பைப் பயன்படுத்தாதீர்கள். அதிகாரப்பூர்வ வங்கி செயலி அல்லது இணையதளம் மூலம் மட்டுமே சரிபார்க்கவும்."
        if short or re.search(ODD_TLDS, low):
            weight += 15
            explain += " It uses a shortener or an unusual address that hides where it really goes."
            explain_ta += " இது இணைப்பு எங்கு செல்கிறது என்பதை மறைக்கும் சுருக்கப்பட்ட அல்லது வழக்கத்துக்கு மாறான முகவரி."
        score += weight
        found = [l.rstrip(".,)") for l in links] or short
        matched += found
        findings.append({"key": "link", "title": "Suspicious link", "title_ta": "சந்தேகத்திற்குரிய இணைப்பு",
                         "explain": explain, "explain_ta": explain_ta, "found": found})
        breakdown.append({"label": "Suspicious link", "label_ta": "சந்தேகத்திற்குரிய இணைப்பு", "points": weight})

    if re.search(r"(do not|don't|never) share", low) and not links:
        delta = min(20, score)
        if delta > 0:
            score -= delta
            breakdown.append({"label": "Message tells you not to share codes",
                              "label_ta": "குறியீடுகளைப் பகிர வேண்டாம் என்று செய்தி கூறுகிறது",
                              "points": -delta})

    score = min(100, score)
    verdict = "scam" if score >= 60 else "suspicious" if score >= 25 else "safe"
    keys = {f["key"] for f in findings}

    if verdict == "safe" and findings:
        reason = "Only minor warning signs were found, so this looks low risk."
        reason_ta = "சிறிய எச்சரிக்கை அறிகுறிகள் மட்டுமே உள்ளன, எனவே ஆபத்து குறைவு."
    elif findings:
        reason = "Rule-based checks found these warning signs: " + " + ".join(f["title"].lower() for f in findings) + "."
        reason_ta = "விதி அடிப்படையிலான சோதனை இந்த எச்சரிக்கை அறிகுறிகளைக் கண்டறிந்தது: " + " + ".join(f["title_ta"] for f in findings) + "."
    else:
        reason = "Rule-based checks found no common scam warning signs. This does not guarantee the message is safe."
        reason_ta = "விதி அடிப்படையிலான சோதனையில் பொதுவான மோசடி அறிகுறிகள் எதுவும் இல்லை. இது செய்தி பாதுகாப்பானது என்பதற்கான உத்தரவாதம் அல்ல."

    advice, advice_ta = build_advice(verdict, low, keys)

    return {"verdict": verdict, "risk_score": score,
            "reason": reason, "reason_ta": reason_ta,
            "advice": advice, "advice_ta": advice_ta,
            "findings": findings, "breakdown": breakdown,
            "matched": matched, "mode": "rules"}


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

    # Optional AI layer. If it fails, the rule-based result above is returned.
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
                keys = {f["key"] for f in result["findings"]}
                fb_en, fb_ta = build_advice(v, text.lower(), keys)
                result["verdict"] = v
                result["risk_score"] = int(ai.get("risk_score", result["risk_score"]))
                result["reason"] = ai.get("reason") or result["reason"]
                result["advice"] = ai.get("advice") or fb_en
                result["reason_ta"] = ai.get("reason_ta") or result["reason_ta"]
                result["advice_ta"] = ai.get("advice_ta") or fb_ta
                result["mode"] = "ai"
        except Exception as e:
            print("AI call failed, using rules:", e)

    return result