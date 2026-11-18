"""HTML report rendering from a decorated scan dict (see scoring.decorate). Supports EN/TR."""
from __future__ import annotations

import html
import time

SEVERITIES = ("High", "Medium", "Low", "Info")
COLORS = {"High": "#dc2626", "Medium": "#ea580c", "Low": "#ca8a04", "Info": "#2563eb"}

L = {
    "en": {"title": "Web Vulnerability Scan Report", "target": "Target", "date": "Date", "status": "Status",
           "tech": "Technology", "grade": "Grade", "score": "Score", "findings": "Findings",
           "none": "No findings.", "risk": "Risk", "fix": "How to fix", "evidence": "Evidence",
           "refs": "References", "scan_risks": "Risks of running this scan", "mitigation": "Mitigation",
           "owasp": "OWASP Top 10 (2021) overview", "priorities": "Fix priorities",
           "changes": "Changes since previous scan", "new": "New", "fixed": "Fixed",
           "persisting": "Unchanged", "fp": "marked as false positive", "accepted": "risk accepted",
           "note": "Note", "footer": "Automated results may include false positives; verify manually. "
                                     "This report is confidential - share only with the system owner.",
           "summary": "Executive summary",
           "summary_text": "The scan produced {n} actionable finding(s): {h} high, {m} medium, {l} low."},
    "tr": {"title": "Web Zafiyet Tarama Raporu", "target": "Hedef", "date": "Tarih", "status": "Durum",
           "tech": "Teknoloji", "grade": "Not", "score": "Puan", "findings": "Bulgular",
           "none": "Bulgu yok.", "risk": "Risk", "fix": "Nasıl düzeltilir", "evidence": "Kanıt",
           "refs": "Kaynaklar", "scan_risks": "Bu taramanın riskleri", "mitigation": "Önlem",
           "owasp": "OWASP Top 10 (2021) özeti", "priorities": "Düzeltme öncelikleri",
           "changes": "Önceki taramadan bu yana değişiklikler", "new": "Yeni", "fixed": "Düzeltilen",
           "persisting": "Değişmeyen", "fp": "yanlış pozitif olarak işaretlendi", "accepted": "risk kabul edildi",
           "note": "Not", "footer": "Otomatik sonuçlar yanlış pozitif içerebilir; elle doğrulayın. "
                                    "Bu rapor gizlidir - yalnızca sistem sahibiyle paylaşın.",
           "summary": "Yönetici özeti",
           "summary_text": "Tarama {n} aksiyon gerektiren bulgu üretti: {h} yüksek, {m} orta, {l} düşük."},
}


def pick(obj: dict, key: str, lang: str) -> str:
    """Return obj[key_tr] when lang is Turkish and available, else the English value."""
    if lang == "tr" and obj.get(key + "_tr"):
        return obj[key + "_tr"]
    return obj.get(key, "")


def _sorted_findings(d: dict) -> list[dict]:
    order = {k: i for i, k in enumerate(SEVERITIES)}
    return sorted(d["findings"], key=lambda x: order.get(x["severity"], 9))


def summary_text(d: dict, lang: str) -> str:
    s = d["summary"]
    return L[lang]["summary_text"].format(n=s["High"] + s["Medium"] + s["Low"],
                                           h=s["High"], m=s["Medium"], l=s["Low"])


def render_html(d: dict, lang: str = "en") -> str:
    lang = lang if lang in L else "en"
    t, e = L[lang], html.escape
    s = d["summary"]
    rows = []
    for f in _sorted_findings(d):
        tri = f.get("triage", {})
        refs = " ".join(f"<a href='{e(r)}'>{e(r)}</a><br>" for r in f.get("references", []))
        impact, fix = pick(f, "impact", lang), pick(f, "fix_details", lang)
        flag = ""
        if tri.get("status") == "false_positive":
            flag = f" <em>({t['fp']})</em>"
        elif tri.get("status") == "accepted":
            flag = f" <em>({t['accepted']})</em>"
        rows.append(
            f"<div class='f' style='border-left:6px solid {COLORS[f['severity']]}'>"
            f"<b>[{e(f['severity'])}] {e(f['title'])}</b>{flag} <small>({e(f['category'])}"
            f"{' / ' + e(f['cwe']) if f.get('cwe') else ''}"
            f"{' / ' + e(f['owasp']) if f.get('owasp') else ''})</small>"
            f"<p>{e(f['description'])}</p>"
            + (f"<p><b>{t['risk']}:</b> {e(impact)}</p>" if impact else "")
            + (f"<p><b>{t['fix']}:</b></p><pre>{e(fix)}</pre>" if fix else "")
            + (f"<p><b>{t['evidence']}:</b></p><pre>{e(f['evidence'])}</pre>" if f.get("evidence") else "")
            + (f"<p><b>{t['note']}:</b> {e(tri['note'])}</p>" if tri.get("note") else "")
            + (f"<p><small>{t['refs']}:<br>{refs}</small></p>" if refs else "") + "</div>")
    risks = "".join(
        f"<div class='f' style='border-left:6px solid {COLORS.get(r['level'], '#64748b')}'>"
        f"<b>[{e(r['level'])}] {e(pick(r, 'title', lang))}</b><p>{e(pick(r, 'description', lang))}</p>"
        f"<p><b>{t['mitigation']}:</b> {e(pick(r, 'mitigation', lang))}</p></div>"
        for r in d.get("scan_risks", []))
    badges = " ".join(f"<span style='background:{COLORS[k]};color:#fff;padding:2px 10px;"
                      f"border-radius:9px'>{k}: {s[k]}</span>" for k in SEVERITIES)
    owasp = "".join(f"<tr><td>{e(k)}</td><td>{v}</td></tr>" for k, v in d.get("owasp", {}).items())
    diff = d.get("diff")
    diff_html = ""
    if diff:
        diff_html = f"<h2>{t['changes']}</h2>" + "".join(
            f"<p><b>{t[k]} ({len(diff[key])}):</b> " + ", ".join(e(x['title']) for x in diff[key][:30]) + "</p>"
            for k, key in (("new", "new"), ("fixed", "fixed"), ("persisting", "persisting")))
    prios = "".join(f"<li><b>[{e(f['severity'])}]</b> {e(f['title'])}</li>" for f in _sorted_findings(d)
                    if f["severity"] in ("High", "Medium")
                    and f.get("triage", {}).get("status") != "false_positive")
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d["started_at"]))
    return f"""<!doctype html><html lang="{lang}"><meta charset="utf-8"><title>{t['title']} - {e(d['target'])}</title>
<style>body{{font-family:system-ui;max-width:900px;margin:2rem auto;padding:0 1rem}}
.f{{background:#f8fafc;padding:.6rem 1rem;margin:.6rem 0}}pre{{background:#0f172a;color:#e2e8f0;
padding:.5rem;overflow:auto;white-space:pre-wrap}}table{{border-collapse:collapse}}td{{border:1px solid #cbd5e1;padding:3px 10px}}
.grade{{font-size:3rem;font-weight:bold}}</style>
<h1>{t['title']}</h1>
<p><b>{t['target']}:</b> {e(d['target'])}<br><b>{t['date']}:</b> {when}<br><b>{t['status']}:</b> {e(d['status'])}<br>
<b>{t['tech']}:</b> {e(', '.join(d.get('tech', [])) or 'n/a')}</p>
<p><span class="grade">{t['grade']}: {e(str(d.get('grade', '?')))}</span> ({t['score']}: {d.get('score', '?')}/100)</p>
<h2>{t['summary']}</h2><p>{summary_text(d, lang)}</p><p>{badges}</p>
<h2>{t['priorities']}</h2><ol>{prios or '<li>-</li>'}</ol>
<h2>{t['owasp']}</h2><table>{owasp or '<tr><td>-</td></tr>'}</table>{diff_html}
<h2>{t['findings']}</h2>{''.join(rows) or '<p>' + t['none'] + '</p>'}
<h2>{t['scan_risks']}</h2>{risks}
<hr><small>{t['footer']}</small></html>
"""


def render_batch_html(scans: list[dict], lang: str = "en") -> str:
    """One-page overview of several scans (batch report)."""
    e = html.escape
    rows = "".join(
        f"<tr><td>{e(d['target'])}</td><td>{e(str(d.get('grade', '?')))}</td><td>{d.get('score', '?')}</td>"
        + "".join(f"<td>{d['summary'].get(k, 0)}</td>" for k in SEVERITIES) + "</tr>" for d in scans)
    heads = "".join(f"<th>{k}</th>" for k in SEVERITIES)
    title = "Batch scan report" if lang != "tr" else "Toplu tarama raporu"
    return (f"<!doctype html><meta charset='utf-8'><title>{title}</title>"
            "<style>body{font-family:system-ui;margin:2rem}td,th{border:1px solid #cbd5e1;padding:4px 10px}"
            "table{border-collapse:collapse}</style>"
            f"<h1>{title}</h1><table><tr><th>Target</th><th>Grade</th><th>Score</th>{heads}</tr>{rows}</table>")
