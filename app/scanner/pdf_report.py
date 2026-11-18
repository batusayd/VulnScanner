"""PDF report (executive summary + findings with fixes) built with reportlab. Supports EN/TR.

Turkish characters need a Unicode TrueType font; common system fonts are tried and the
built-in Helvetica (with ASCII transliteration) is the fallback.
"""
from __future__ import annotations

import html
import io
import os
import time

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .report import COLORS, L, _sorted_findings, pick, summary_text

FONT_CANDIDATES = [
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/Library/Fonts/Arial.ttf", "/Library/Fonts/Arial Bold.ttf"),
]
_TR_ASCII = str.maketrans("şŞğĞıİöÖüÜçÇ", "sSgGiIoOuUcC")


def _fonts() -> tuple[str, str, bool]:
    """Register a Unicode font; returns (regular, bold, unicode_ok)."""
    for reg, bold in FONT_CANDIDATES:
        if os.path.exists(reg):
            try:
                pdfmetrics.registerFont(TTFont("VS-Regular", reg))
                pdfmetrics.registerFont(TTFont("VS-Bold", bold if os.path.exists(bold) else reg))
                return "VS-Regular", "VS-Bold", True
            except Exception:  # noqa: BLE001
                continue
    return "Helvetica", "Helvetica-Bold", False


def _p(text: str, style: ParagraphStyle, uni: bool, code: bool = False) -> Paragraph:
    text = str(text or "")
    if not uni:
        text = text.translate(_TR_ASCII)
    safe = html.escape(text).replace("\n", "<br/>")
    if code:
        safe = safe.replace("  ", "&nbsp;&nbsp;")
    return Paragraph(safe, style)


def render_pdf(d: dict, lang: str = "en") -> bytes:
    lang = lang if lang in L else "en"
    t = L[lang]
    reg, bold, uni = _fonts()
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontName=reg, fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=colors.HexColor("#475569"))
    code = ParagraphStyle("c", parent=body, fontSize=8, leading=10, backColor=colors.HexColor("#f1f5f9"),
                          borderPadding=3, leftIndent=4)
    h1 = ParagraphStyle("h1", parent=body, fontName=bold, fontSize=18, leading=22, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=body, fontName=bold, fontSize=13, leading=16, spaceBefore=10, spaceAfter=4)
    h3 = ParagraphStyle("h3", parent=body, fontName=bold, fontSize=10, leading=13, spaceBefore=6)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm, title=t["title"])
    s = d["summary"]
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(d["started_at"]))
    story = [_p(t["title"], h1, uni),
             _p(f"{t['target']}: {d['target']}", body, uni),
             _p(f"{t['date']}: {when}    {t['status']}: {d['status']}", body, uni),
             Spacer(1, 6)]

    gt = Table([[f"{t['grade']}: {d.get('grade', '?')}", f"{t['score']}: {d.get('score', '?')}/100",
                 *[f"{k}: {s[k]}" for k in ("High", "Medium", "Low", "Info")]]],
               colWidths=[28 * mm, 30 * mm] + [24 * mm] * 4)
    style = [("FONTNAME", (0, 0), (-1, -1), bold), ("FONTSIZE", (0, 0), (-1, -1), 10),
             ("BOX", (0, 0), (-1, -1), .5, colors.grey), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
             ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]
    for i, k in enumerate(("High", "Medium", "Low", "Info")):
        style += [("BACKGROUND", (2 + i, 0), (2 + i, 0), colors.HexColor(COLORS[k])),
                  ("TEXTCOLOR", (2 + i, 0), (2 + i, 0), colors.white)]
    gt.setStyle(TableStyle(style))
    story += [gt, _p(t["summary"], h2, uni), _p(summary_text(d, lang), body, uni)]

    story.append(_p(t["priorities"], h2, uni))
    top = [f for f in _sorted_findings(d) if f["severity"] in ("High", "Medium")
           and f.get("triage", {}).get("status") != "false_positive"]
    if top:
        for i, f in enumerate(top[:15], 1):
            first = (pick(f, "fix_details", lang) or f.get("recommendation", "")).split("\n")[0]
            story.append(_p(f"{i}. [{f['severity']}] {f['title']} - {first[:140]}", body, uni))
    else:
        story.append(_p("-", body, uni))

    if d.get("owasp"):
        story.append(_p(t["owasp"], h2, uni))
        rows = [[k, str(v)] for k, v in d["owasp"].items()]
        ot = Table(rows, colWidths=[120 * mm, 20 * mm])
        ot.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), reg), ("FONTSIZE", (0, 0), (-1, -1), 9),
                                ("GRID", (0, 0), (-1, -1), .25, colors.lightgrey)]))
        story.append(ot)

    diff = d.get("diff")
    if diff:
        story.append(_p(t["changes"], h2, uni))
        for k in ("new", "fixed", "persisting"):
            story.append(_p(f"{t[k]} ({len(diff[k])}): " + ", ".join(x["title"] for x in diff[k][:25]), body, uni))

    story.append(_p(t["findings"], h2, uni))
    if not d["findings"]:
        story.append(_p(t["none"], body, uni))
    for f in _sorted_findings(d):
        tri = f.get("triage", {})
        tag = f" ({t['fp']})" if tri.get("status") == "false_positive" else \
            f" ({t['accepted']})" if tri.get("status") == "accepted" else ""
        meta = " / ".join(x for x in (f["category"], f.get("cwe"), f.get("owasp")) if x)
        story.append(_p(f"[{f['severity']}] {f['title']}{tag}", h3, uni))
        story.append(_p(meta, small, uni))
        story.append(_p(f["description"], body, uni))
        impact, fix = pick(f, "impact", lang), pick(f, "fix_details", lang)
        if impact:
            story.append(_p(f"{t['risk']}: {impact}", body, uni))
        if fix:
            story.append(_p(f"{t['fix']}:", body, uni))
            story.append(_p(fix, code, uni, code=True))
        if f.get("evidence"):
            story.append(_p(f"{t['evidence']}: {f['evidence'][:400]}", small, uni))
        if tri.get("note"):
            story.append(_p(f"{t['note']}: {tri['note']}", small, uni))

    story.append(_p(t["scan_risks"], h2, uni))
    for r in d.get("scan_risks", []):
        story.append(_p(f"[{r['level']}] {pick(r, 'title', lang)}", h3, uni))
        story.append(_p(pick(r, "description", lang), body, uni))
        story.append(_p(f"{t['mitigation']}: {pick(r, 'mitigation', lang)}", body, uni))
    story += [Spacer(1, 10), _p(t["footer"], small, uni)]

    doc.build(story)
    return buf.getvalue()
