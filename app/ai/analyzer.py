from anthropic import Anthropic

from app.config import settings

# إنشاء عميل Anthropic بالمفتاح من الإعدادات
client = Anthropic(api_key=settings.ANTHROPIC_API_KEY)

MODEL = "claude-haiku-4-5"


def analyze_finding(
    title: str,
    severity: str,
    description: str,
    location: str,
) -> str:
    """إرسال ثغرة إلى Claude للحصول على تحليل أمني مفصّل."""

    prompt = f"""أنت خبير أمن سيبراني. حلّل الثغرة الأمنية التالية بالعربية.

الثغرة: {title}
مستوى الخطورة: {severity}
الموقع: {location}
الوصف: {description}

قدّم تحليلاً منظّماً يحتوي على:
1. **شرح الثغرة**: ما هي وكيف تعمل؟
2. **الخطر**: ماذا يمكن أن يفعل المهاجم؟
3. **الحل**: خطوات الإصلاح العملية.
4. **مثال كود** (إن أمكن): كود صحيح لإصلاح المشكلة.

اجعل الإجابة عملية ومباشرة."""

    message = client.messages.create(
        model=MODEL,
        max_tokens=2000,
        messages=[
            {"role": "user", "content": prompt}
        ],
    )

    parts = []
    for block in message.content:
        if block.type == "text":
            parts.append(block.text)

    return "".join(parts)


def ask_assistant(question: str) -> str:
    """مساعد أمني ذكي — يجيب عن أي سؤال في الأمن السيبراني."""

    prompt = f"""أنت مساعد خبير في الأمن السيبراني تعمل داخل منصة SecureVision AI.
أجب عن السؤال التالي بالعربية بشكل عملي ومفيد، مع أمثلة كود إن لزم.

السؤال: {question}"""

    message = client.messages.create(
        model=MODEL,
        max_tokens=2000,
        messages=[
            {"role": "user", "content": prompt}
        ],
    )

    parts = []
    for block in message.content:
        if block.type == "text":
            parts.append(block.text)

    return "".join(parts)