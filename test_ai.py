import traceback

from app.ai.analyzer import analyze_finding

try:
    result = analyze_finding(
        title="اختبار ثغرة",
        severity="high",
        description="هذه ثغرة تجريبية للاختبار باللغة العربية",
        location="http://localhost:3000/test",
    )
    print("=== نجح التحليل ===")
    print(result)
except Exception:
    print("=== فشل التحليل — التتبّع الكامل ===")
    traceback.print_exc()