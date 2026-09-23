import re
import os
from io import BytesIO
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_RIGHT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

import arabic_reshaper
from bidi.algorithm import get_display


# ===== تسجيل الخط العربي (Arial من نظام ويندوز) =====
# ===== تسجيل الخط العربي (متعدّد الأنظمة: لينكس/ويندوز) =====
FONT_NAME = "ArabicFont"
FONT_BOLD = "ArabicFont-Bold"

# مرشّحات الخط (عادي، عريض) — نختار أول ما هو موجود
_FONT_CANDIDATES = [
    # خط Amiri العربي (منزّل داخل الحاوية) — الأفضل
    ("/usr/share/fonts/arabic/Amiri-Regular.ttf",
     "/usr/share/fonts/arabic/Amiri-Bold.ttf"),
    # ويندوز (التطوير المحلي) — Arial يدعم العربية
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
    # احتياطي أخير (لاتيني فقط)
    ("/usr/share/fonts/truetype/freefont/FreeSans.ttf",
     "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf"),
]

_regular = None
_bold = None
for _reg, _bd in _FONT_CANDIDATES:
    if os.path.exists(_reg):
        _regular = _reg
        _bold = _bd if os.path.exists(_bd) else _reg
        break

if _regular:
    pdfmetrics.registerFont(TTFont(FONT_NAME, _regular))
    pdfmetrics.registerFont(TTFont(FONT_BOLD, _bold))
    pdfmetrics.registerFontFamily(FONT_NAME, normal=FONT_NAME, bold=FONT_BOLD)
else:
    # حل أخير حتى لا ينهار التطبيق (بلا دعم عربي كامل)
    FONT_NAME = "Helvetica"
    FONT_BOLD = "Helvetica-Bold"


def ar(text) -> str:
    """معالجة النص العربي: تشكيل الحروف + اتجاه صحيح."""
    if text is None:
        text = ""
    reshaped = arabic_reshaper.reshape(str(text))
    return get_display(reshaped)


SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#16a34a"),
    "info": colors.HexColor("#0284c7"),
}

SEVERITY_LABELS = {
    "critical": "حرجة",
    "high": "عالية",
    "medium": "متوسطة",
    "low": "منخفضة",
    "info": "معلومة",
}


def _engine_of(title: str) -> str:
    t = title or ""
    if t.startswith("[Nmap]"):
        return "Nmap"
    if t.startswith("[Nuclei]"):
        return "Nuclei"
    if t.startswith("[SQLMap]"):
        return "SQLMap"
    return "SecureVision"


def _clean_title(title: str) -> str:
    return re.sub(r"^\[(Nmap|Nuclei|SQLMap)\]\s*", "", title or "")


def generate_report(project_name: str, findings: list) -> bytes:
    """توليد تقرير أمني PDF احترافي بالعربية لمشروع."""

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm
    )

    title_style = ParagraphStyle("TitleAr", fontName=FONT_BOLD, fontSize=22,
                                 alignment=TA_CENTER, textColor=colors.HexColor("#0f172a"))
    subtitle_style = ParagraphStyle("SubAr", fontName=FONT_NAME, fontSize=13,
                                    alignment=TA_CENTER, textColor=colors.HexColor("#64748b"))
    heading_style = ParagraphStyle("HeadAr", fontName=FONT_BOLD, fontSize=15,
                                   alignment=TA_RIGHT, textColor=colors.HexColor("#1d4ed8"),
                                   spaceBefore=10, spaceAfter=6)
    normal = ParagraphStyle("NormAr", fontName=FONT_NAME, fontSize=11,
                            alignment=TA_RIGHT, leading=18)
    finding_title = ParagraphStyle("FindTitle", fontName=FONT_BOLD, fontSize=12,
                                   alignment=TA_RIGHT, textColor=colors.HexColor("#0f172a"),
                                   spaceBefore=8)

    elements = []

    # ===== العنوان =====
    elements.append(Paragraph("SecureVision AI", title_style))
    elements.append(Paragraph(ar("تقرير التقييم الأمني"), subtitle_style))
    elements.append(Spacer(1, 0.6 * cm))

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    elements.append(Paragraph(ar(f"المشروع: {project_name}"), normal))
    elements.append(Paragraph(ar(f"تاريخ الإصدار: {now}"), normal))
    elements.append(Paragraph(ar(f"إجمالي النتائج: {len(findings)}"), normal))
    elements.append(Spacer(1, 0.6 * cm))

    # عدّ الخطورة
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1

    # ===== الملخص التنفيذي + درجة الأمان =====
    score = 100 - (counts["critical"] * 20 + counts["high"] * 10
                   + counts["medium"] * 4 + counts["low"] * 1)
    score = max(0, min(100, score))

    if score >= 90:
        rating, rcolor = "ممتاز", colors.HexColor("#16a34a")
    elif score >= 75:
        rating, rcolor = "جيد", colors.HexColor("#0284c7")
    elif score >= 50:
        rating, rcolor = "متوسط", colors.HexColor("#ca8a04")
    elif score >= 25:
        rating, rcolor = "ضعيف", colors.HexColor("#ea580c")
    else:
        rating, rcolor = "خطير", colors.HexColor("#dc2626")

    elements.append(Paragraph(ar("الملخص التنفيذي"), heading_style))
    score_table = Table(
        [[ar(f"درجة الأمان: {score} / 100"), ar(f"التقييم: {rating}")]],
        colWidths=[8 * cm, 8 * cm],
    )
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), rcolor),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), FONT_BOLD),
        ("FONTSIZE", (0, 0), (-1, -1), 14),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    elements.append(score_table)
    elements.append(Spacer(1, 0.4 * cm))

    exec_text = (f"تم فحص المشروع واكتشاف {len(findings)} نتيجة، "
                 f"منها {counts['critical']} حرجة و{counts['high']} عالية. ")
    if counts["critical"] or counts["high"]:
        exec_text += "يُوصى بمعالجة الثغرات الحرجة والعالية بشكل عاجل."
    else:
        exec_text += "لا توجد ثغرات حرجة أو عالية — الوضع الأمني جيد."
    elements.append(Paragraph(ar(exec_text), normal))
    elements.append(Spacer(1, 0.6 * cm))

    # ===== ملخص الخطورة =====
    elements.append(Paragraph(ar("توزيع الخطورة"), heading_style))
    summary_table = Table([
        [ar("حرجة"), ar("عالية"), ar("متوسطة"), ar("منخفضة"), ar("معلومة")],
        [str(counts["critical"]), str(counts["high"]), str(counts["medium"]),
         str(counts["low"]), str(counts["info"])],
    ], colWidths=[3.2 * cm] * 5)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), FONT_NAME),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 1), (-1, 1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.7 * cm))

    # ===== النتائج حسب أداة الفحص =====
    engines = {}
    for f in findings:
        e = _engine_of(f.get("title", ""))
        engines[e] = engines.get(e, 0) + 1

    if engines:
        elements.append(Paragraph(ar("النتائج حسب أداة الفحص"), heading_style))
        eng_rows = [[ar("الأداة"), ar("عدد النتائج")]]
        for name, cnt in sorted(engines.items(), key=lambda x: -x[1]):
            eng_rows.append([name, str(cnt)])
        eng_table = Table(eng_rows, colWidths=[8 * cm, 8 * cm])
        eng_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), FONT_NAME),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTSIZE", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(eng_table)
        elements.append(Spacer(1, 0.8 * cm))

    # ===== تفاصيل الثغرات =====
    elements.append(Paragraph(ar("تفاصيل الثغرات"), heading_style))
    elements.append(Spacer(1, 0.2 * cm))

    if not findings:
        elements.append(Paragraph(ar("لا توجد ثغرات مسجّلة."), normal))
    else:
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info")
            color = SEVERITY_COLORS.get(sev, colors.grey)
            sev_label = SEVERITY_LABELS.get(sev, sev)
            engine = _engine_of(f.get("title", ""))

            sev_style = ParagraphStyle(f"Sev{i}", fontName=FONT_BOLD, fontSize=11,
                                       alignment=TA_RIGHT, textColor=color)

            elements.append(Paragraph(ar(f"{i}. {_clean_title(f.get('title', ''))}"), finding_title))
            elements.append(Paragraph(ar(f"مستوى الخطورة: {sev_label}   |   الأداة: {engine}"), sev_style))
            elements.append(Paragraph(ar(f"الموقع: {f.get('location', '-')}"), normal))
            elements.append(Paragraph(ar(f"الوصف: {f.get('description', '-')}"), normal))
            elements.append(Paragraph(ar(f"التوصية: {f.get('recommendation', '-')}"), normal))

            if f.get("ai_analysis"):
                elements.append(Paragraph(ar(f"تحليل الذكاء الاصطناعي: {f.get('ai_analysis')}"), normal))

            elements.append(Spacer(1, 0.5 * cm))

    doc.build(elements)

    pdf = buffer.getvalue()
    buffer.close()
    return pdf