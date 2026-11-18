"""Command-line mode, e.g. for CI/CD pipelines scanning your own sites after each deploy.

Examples:
  python -m app.cli https://staging.example.com --consent --format sarif --out results.sarif --fail-on high
  python -m app.cli example.com --consent --profile gentle --format pdf --lang tr --out rapor.pdf
  python -m app.cli --decrypt report.json.enc --password secret --out report.json
Exit codes: 0 = ok, 1 = findings at or above --fail-on, 2 = scan failed / invalid input.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import signing, storage
from .scanner.engine import run_scan
from .scanner.models import ScanResult
from .scanner.pdf_report import render_pdf
from .scanner.presets import ALL_MODULES, MODULES_CATALOG, PRESETS, resolve_preset
from .scanner.report import render_html
from .scanner.sarif_enc import decrypt_bytes, encrypt_bytes, render_sarif
from .scanner.scope import ScopeError, check_authorisation, normalize_target
from .scanner.scoring import compute_diff, decorate

LEVELS = {"high": ("High",), "medium": ("High", "Medium"), "low": ("High", "Medium", "Low"), "none": ()}


async def _run(args: argparse.Namespace) -> int:
    code = 0
    for raw in args.targets:
        try:
            url = normalize_target(raw)
            await check_authorisation(url, args.consent, args.scope, args.window_start, args.window_end)
        except ScopeError as exc:
            print(f"[!] {raw}: {exc}", file=sys.stderr)
            return 2
        cfg = resolve_preset(args.preset if args.preset != "custom" else None,
                             args.profile or "normal", args.cve,
                             req_modules=args.modules or None)
        if args.profile:
            cfg["profile"] = args.profile
            cfg["auto"] = False
        res = ScanResult(target=url, profile=cfg["profile"],
                         options={"preset": cfg["preset"], "auto": cfg["auto"],
                                  "modules": cfg["modules"], "custom_modules": cfg["custom_modules"],
                                  "scope_domains": args.scope, "cve_lookup": cfg["cve_lookup"]})
        task = asyncio.create_task(run_scan(res))
        seen = 0
        while not task.done():
            await asyncio.sleep(0.5)
            for line in res.logs[seen:]:
                print(line)
            seen = len(res.logs)
        await task
        for line in res.logs[seen:]:
            print(line)
        d = res.to_dict()
        if args.save:
            prev = storage.previous_scan(url, res.started_at)
            if prev:
                res.diff = compute_diff(d["findings"], prev["findings"])
                d = res.to_dict()
            storage.save_scan(d)
        d = decorate(d, storage.get_triage(url) if args.save else {})
        if res.status == "failed":
            print(f"[!] scan failed: {res.error}", file=sys.stderr)
            return 2
        out = Path(args.out) if args.out else None
        if len(args.targets) > 1 and out:
            out = out.with_name(f"{out.stem}-{res.id}{out.suffix}")
        if out:
            if args.format == "pdf":
                blob = render_pdf(d, args.lang)
            elif args.format == "html":
                blob = render_html(d, args.lang).encode("utf-8")
            elif args.format == "sarif":
                blob = json.dumps(render_sarif(d), indent=2, ensure_ascii=False).encode("utf-8")
            else:
                blob = json.dumps(signing.sign_document(d), indent=2, ensure_ascii=False).encode("utf-8")
            sig = signing.sign(blob)
            if args.password:
                blob = encrypt_bytes(blob, args.password)
            out.write_bytes(blob)
            print(f"[+] report written to {out}  ({sig})")
        s = d["summary"]
        print(f"[=] {url}: grade {d['grade']} ({d['score']}/100) "
              f"High {s['High']} Medium {s['Medium']} Low {s['Low']} Info {s['Info']}")
        if any(s[k] for k in LEVELS[args.fail_on]):
            code = 1
    return code


def main() -> None:
    ap = argparse.ArgumentParser(description="VulnScanner CLI (authorised testing only)")
    ap.add_argument("targets", nargs="*", help="URL(s) or domain(s)")
    ap.add_argument("--consent", action="store_true", help="confirm you are authorised to scan the targets")
    ap.add_argument("--preset", choices=[*PRESETS.keys(), "custom"], default="auto",
                    help="ready-to-use auto-configured scan mode (default: auto)")
    ap.add_argument("--modules", nargs="*", choices=list(ALL_MODULES), default=[],
                    help="select specific scan modules to run (e.g. --modules headers tls dns)")
    ap.add_argument("--list-modules", action="store_true", help="list all available scan modules and exit")
    ap.add_argument("--list-presets", action="store_true", help="list all ready-to-use scan presets and exit")
    ap.add_argument("--profile", choices=["gentle", "normal", "fast"], default=None,
                    help="explicit speed profile override")
    ap.add_argument("--scope", nargs="*", default=[], help="authorised domains (targets must be inside)")
    ap.add_argument("--window-start"), ap.add_argument("--window-end")
    ap.add_argument("--cve", action="store_true", help="optional NVD/EPSS/KEV/OSV lookup")
    ap.add_argument("--format", choices=["json", "html", "pdf", "sarif"], default="json")
    ap.add_argument("--lang", choices=["en", "tr"], default="en")
    ap.add_argument("--out", help="output file")
    ap.add_argument("--password", help="encrypt (or decrypt with --decrypt) report with password")
    ap.add_argument("--decrypt", help="decrypt an encrypted report file to --out")
    ap.add_argument("--fail-on", choices=list(LEVELS), default="none")
    ap.add_argument("--save", action="store_true", help="store in the history database")
    args = ap.parse_args()
    if args.list_modules:
        for m in MODULES_CATALOG:
            print(f"{m['id']:12s} [{m['group']:7s}] {m['name']} - {m['desc']}")
        sys.exit(0)
    if args.list_presets:
        for pid, p in PRESETS.items():
            print(f"{pid:18s} [{p['profile']:6s}] ({len(p['modules']):2d} modules) - {p['description']}")
        sys.exit(0)
    if args.decrypt:
        if not args.password or not args.out:
            print("[!] --decrypt requires --password and --out", file=sys.stderr)
            sys.exit(2)
        Path(args.out).write_bytes(decrypt_bytes(Path(args.decrypt).read_bytes(), args.password))
        print(f"[+] decrypted to {args.out}")
        sys.exit(0)
    if not args.targets or not args.consent:
        ap.error("targets and --consent are required for scanning")
    if args.save:
        storage.init()
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
