#!/usr/bin/env python3

import argparse
import csv
import json
import os
import re
import sys

import requests
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

API_BASE = "https://console.xbow.com/api/v1"
API_VERSION = "2026-04-01"

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "informational": colors.HexColor("#6b7280"),
    "info": colors.HexColor("#6b7280"),
    "untriaged": colors.HexColor("#6b7280"),
}


def make_headers(api_key):
    return {
        "Authorization": f"Bearer {api_key}",
        "X-XBOW-API-Version": API_VERSION,
        "Content-Type": "application/json",
    }


def list_findings(api_key, asset_id):
    findings = []
    after = None
    while True:
        params = {"limit": 100}
        if after:
            params["after"] = after
        url = f"{API_BASE}/assets/{asset_id}/findings"
        resp = requests.get(url, headers=make_headers(api_key), params=params)
        if not resp.ok:
            sys.exit(
                f"Error fetching findings for asset {asset_id}: {resp.status_code} {resp.text}"
            )
        data = resp.json()
        findings.extend(data["items"])
        after = data.get("nextCursor")
        if not after:
            break
    return findings


def get_asset(api_key, asset_id):
    url = f"{API_BASE}/assets/{asset_id}"
    resp = requests.get(url, headers=make_headers(api_key))
    if not resp.ok:
        sys.exit(f"Error fetching asset {asset_id}: {resp.status_code} {resp.text}")
    return resp.json()


def get_finding(api_key, finding_id):
    url = f"{API_BASE}/findings/{finding_id}"
    resp = requests.get(url, headers=make_headers(api_key))
    if not resp.ok:
        sys.exit(f"Error fetching finding {finding_id}: {resp.status_code} {resp.text}")
    return resp.json()


def enrich_findings(api_key, findings):
    enriched = []
    for i, f in enumerate(findings, 1):
        print(f"  Fetching finding {i}/{len(findings)}...", end="\r", file=sys.stderr)
        enriched.append(get_finding(api_key, f["id"]))
    print(" " * 40, end="\r", file=sys.stderr)
    return enriched


def sort_findings(findings):
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(
        key=lambda f: (
            severity_order.get(f.get("severity", "info"), 5),
            f.get("name", ""),
        )
    )
    return findings


def print_table(findings, asset_id):
    if not findings:
        print(f"No findings for asset {asset_id}")
        return
    print(f"Asset: {asset_id}")
    print(f"Findings: {len(findings)}\n")
    col_w = {"severity": 10, "state": 10, "id": 38}
    print(
        f"{'Severity':<{col_w['severity']}}  {'State':<{col_w['state']}}  {'ID':<{col_w['id']}}  Name"
    )
    print("-" * 90)
    for f in findings:
        severity = f.get("severity", "unknown")
        state = f.get("state", "unknown")
        fid = f.get("id", "")
        name = f.get("name", "")
        print(
            f"{severity:<{col_w['severity']}}  {state:<{col_w['state']}}  {fid:<{col_w['id']}}  {name}"
        )


def write_json(findings, asset_id):
    path = f"{asset_id}.json"
    with open(path, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"Wrote {path}")


def flatten_finding(f):
    cvss31 = (f.get("cvss") or {}).get("3.1") or {}
    return {
        "id": f.get("id", ""),
        "name": f.get("name", ""),
        "severity": f.get("severity", ""),
        "state": f.get("state", ""),
        "cwe": f.get("cwe", ""),
        "cvss_score": cvss31.get("score", ""),
        "cvss_vector": cvss31.get("vector", ""),
        "summary": f.get("summary", ""),
        "impact": f.get("impact", ""),
        "mitigations": f.get("mitigations", ""),
        "evidence": f.get("evidence", ""),
        "recipe": f.get("recipe", ""),
        "createdAt": f.get("createdAt", ""),
        "updatedAt": f.get("updatedAt", ""),
    }


def write_csv(findings, asset_id):
    path = f"{asset_id}.csv"
    fields = [
        "id",
        "name",
        "severity",
        "state",
        "cwe",
        "cvss_score",
        "cvss_vector",
        "summary",
        "impact",
        "mitigations",
        "evidence",
        "recipe",
        "createdAt",
        "updatedAt",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(flatten_finding(f) for f in findings)
    print(f"Wrote {path}")


def _parse_finding_name(name):
    """Extract (attack_type, endpoint, via) from names like 'Attack Type in /path via param'."""
    m = re.match(r"^(.+?)\s+in\s+(/\S+)(?:\s+via\s+(.+))?$", name or "")
    if m:
        return m.group(1).strip(), m.group(2).strip(), (m.group(3) or "").strip()
    return name or "", "", ""


def _xml_escape(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _inline_md(text):
    """Convert inline markdown to reportlab XML tags. XML-escapes non-tag content first."""
    text = _xml_escape(text)
    # Bold: **text**
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    # Italic: *text* (single asterisk, not adjacent to another)
    text = re.sub(r"(?<!\*)\*(?!\*)([^*\n]+?)(?<!\*)\*(?!\*)", r"<i>\1</i>", text)
    # Italic: _text_ (not part of an identifier/underscore sequence)
    text = re.sub(r"(?<!\w)_([^_\n]+?)_(?!\w)", r"<i>\1</i>", text)
    # Inline code: `code` — rendered in Courier
    text = re.sub(r"`([^`\n]+?)`", r'<font name="Courier">\1</font>', text)
    return text


def _md_to_flowables(text, body_style, mono_style, bullet_style):
    """Parse a markdown text block into a list of reportlab Paragraph flowables."""
    if not text:
        return []

    flowables = []
    lines = text.split("\n")
    i = 0

    while i < len(lines):
        line = lines[i]

        # Fenced code block
        if line.strip().startswith("```"):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1  # consume closing fence
            for code_line in code_lines:
                flowables.append(Paragraph(_xml_escape(code_line) or " ", mono_style))
            continue

        # Blank line
        if line.strip() == "":
            i += 1
            continue

        # List items — consume the whole run
        if re.match(r"^\s*(?:[-*+]|\d+\.)\s", line):
            while i < len(lines):
                l = lines[i]
                mb = re.match(r"^\s*[-*+]\s+(.+)$", l)
                mo = re.match(r"^\s*(\d+)\.\s+(.+)$", l)
                if mb:
                    flowables.append(
                        Paragraph(_inline_md(mb.group(1)), bullet_style, bulletText="•")
                    )
                    i += 1
                elif mo:
                    flowables.append(
                        Paragraph(
                            _inline_md(mo.group(2)),
                            bullet_style,
                            bulletText=f"{mo.group(1)}.",
                        )
                    )
                    i += 1
                else:
                    break
            continue

        # Regular paragraph — join consecutive non-blank, non-block lines
        para_lines = []
        while i < len(lines):
            l = lines[i]
            if l.strip() == "":
                break
            if l.strip().startswith("```"):
                break
            if re.match(r"^\s*(?:[-*+]|\d+\.)\s", l):
                break
            para_lines.append(l.rstrip())
            i += 1
        if para_lines:
            flowables.append(Paragraph(_inline_md(" ".join(para_lines)), body_style))

    return flowables


def write_pdf(findings, asset_id, asset_name, keep_json=False):
    json_path = f"{asset_id}.json"
    with open(json_path, "w") as fh:
        json.dump(findings, fh, indent=2)

    try:
        with open(json_path) as fh:
            data = json.load(fh)

        pdf_path = f"{asset_id}.pdf"
        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=LETTER,
            leftMargin=inch,
            rightMargin=inch,
            topMargin=inch,
            bottomMargin=inch,
        )

        base = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "FindingTitle",
            parent=base["Normal"],
            fontSize=15,
            leading=18,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#111827"),
            spaceAfter=10,
        )
        label_style = ParagraphStyle(
            "MetaLabel",
            parent=base["Normal"],
            fontSize=8,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#6b7280"),
            spaceAfter=1,
        )
        value_style = ParagraphStyle(
            "MetaValue",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica",
            textColor=colors.HexColor("#111827"),
        )
        section_style = ParagraphStyle(
            "SectionHead",
            parent=base["Normal"],
            fontSize=11,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#111827"),
            spaceBefore=14,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#374151"),
        )
        mono_style = ParagraphStyle(
            "Mono",
            parent=base["Normal"],
            fontSize=9,
            leading=13,
            fontName="Courier",
            textColor=colors.HexColor("#374151"),
            backColor=colors.HexColor("#f3f4f6"),
            leftIndent=6,
            rightIndent=6,
            spaceBefore=4,
            spaceAfter=4,
        )
        badge_style = ParagraphStyle(
            "Badge",
            parent=base["Normal"],
            fontSize=10,
            fontName="Helvetica-Bold",
            textColor=colors.white,
            alignment=TA_CENTER,
        )
        bullet_style = ParagraphStyle(
            "Bullet",
            parent=body_style,
            leftIndent=18,
            bulletIndent=6,
            spaceAfter=2,
        )

        doc_title_style = ParagraphStyle(
            "DocTitle",
            parent=base["Normal"],
            fontSize=22,
            leading=26,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#111827"),
            spaceAfter=6,
        )
        doc_sub_style = ParagraphStyle(
            "DocSub",
            parent=base["Normal"],
            fontSize=11,
            fontName="Helvetica",
            textColor=colors.HexColor("#6b7280"),
            spaceAfter=0,
        )

        story = []
        usable_width = LETTER[0] - 2 * inch

        story.append(Paragraph(_xml_escape(asset_name), doc_title_style))
        story.append(Paragraph(f"Findings Report", doc_sub_style))
        story.append(
            HRFlowable(
                width="100%",
                thickness=1,
                color=colors.HexColor("#e5e7eb"),
                spaceBefore=10,
                spaceAfter=4,
            )
        )
        story.append(PageBreak())

        for i, f in enumerate(data):
            if i > 0:
                story.append(PageBreak())

            name = f.get("name", "")
            severity = (f.get("severity") or "unknown").lower()
            attack_type, endpoint, via = _parse_finding_name(name)
            cvss31 = (f.get("cvss") or {}).get("3.1") or {}
            cvss_score = cvss31.get("score", "")
            cvss_vector = cvss31.get("vector", "")
            cwe = f.get("cwe", "")
            sev_color = SEVERITY_COLORS.get(severity, colors.HexColor("#6b7280"))

            # ── Summary header table ──────────────────────────────────────────
            def meta_cell(label, value):
                return [
                    Paragraph(label, label_style),
                    Paragraph(str(value) if value else "—", value_style),
                ]

            badge_cell = Paragraph(severity.upper(), badge_style)
            badge_tbl = Table(
                [[badge_cell]], colWidths=[0.9 * inch], rowHeights=[0.28 * inch]
            )
            badge_tbl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), sev_color),
                        ("ROUNDEDCORNERS", [4]),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 2),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ]
                )
            )

            col = usable_width / 2
            meta_rows = [
                [
                    Paragraph("ATTACK TYPE", label_style),
                    Paragraph(attack_type or "—", value_style),
                    Paragraph("ENDPOINT", label_style),
                    Paragraph(endpoint or "—", value_style),
                ],
                [
                    Paragraph("CVSS SCORE", label_style),
                    Paragraph(str(cvss_score) if cvss_score else "—", value_style),
                    Paragraph("CWE", label_style),
                    Paragraph(cwe or "—", value_style),
                ],
                [
                    Paragraph("CVSS VECTOR", label_style),
                    Paragraph(cvss_vector or "—", value_style),
                    Paragraph("VIA", label_style),
                    Paragraph(via or "—", value_style),
                ],
            ]
            meta_tbl = Table(
                meta_rows, colWidths=[col * 0.28, col * 0.72, col * 0.28, col * 0.72]
            )
            meta_tbl.setStyle(
                TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 0),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )

            story.append(Paragraph(_xml_escape(name), title_style))
            story.append(badge_tbl)
            story.append(Spacer(1, 8))
            story.append(meta_tbl)
            story.append(
                HRFlowable(
                    width="100%",
                    thickness=1,
                    color=colors.HexColor("#e5e7eb"),
                    spaceAfter=4,
                )
            )

            # ── Finding sections ─────────────────────────────────────────────
            for section_title, field, raw_mono in [
                ("Summary", "summary", False),
                ("Impact", "impact", False),
                ("Evidence", "evidence", True),
                ("Reproduction Steps", "recipe", False),
                ("Mitigations", "mitigations", False),
            ]:
                text = f.get(field, "")
                if not text:
                    continue
                story.append(Paragraph(section_title, section_style))
                if raw_mono:
                    # Evidence is raw payload — just escape and render verbatim in mono
                    for line in text.split("\n"):
                        story.append(Paragraph(_xml_escape(line) or " ", mono_style))
                else:
                    story.extend(
                        _md_to_flowables(text, body_style, mono_style, bullet_style)
                    )

        doc.build(story)
        print(f"Wrote {pdf_path}")
    finally:
        if not keep_json:
            os.remove(json_path)


def write_markdown(findings, asset_id, asset_name, keep_json=False):
    json_path = f"{asset_id}.json"
    with open(json_path, "w") as fh:
        json.dump(findings, fh, indent=2)

    try:
        with open(json_path) as fh:
            data = json.load(fh)

        md_path = f"{asset_id}.md"
        lines = [f"# Findings: {asset_name}\n"]

        for f in data:
            name = f.get("name", "")
            severity = (f.get("severity") or "unknown").lower()
            state = f.get("state", "unknown")
            attack_type, endpoint, via = _parse_finding_name(name)
            cvss31 = (f.get("cvss") or {}).get("3.1") or {}
            cvss_score = cvss31.get("score", "")
            cvss_vector = cvss31.get("vector", "")
            cwe = f.get("cwe", "")

            lines.append(f"---\n")
            lines.append(f"## {name}\n")

            # Summary metadata table
            lines.append("| | |")
            lines.append("|---|---|")
            lines.append(f"| **Severity** | {severity} |")
            lines.append(f"| **State** | {state} |")
            if attack_type:
                lines.append(f"| **Attack Type** | {attack_type} |")
            if endpoint:
                lines.append(f"| **Endpoint** | `{endpoint}` |")
            if via:
                lines.append(f"| **Via** | {via} |")
            if cvss_score:
                lines.append(f"| **CVSS Score** | {cvss_score} |")
            if cvss_vector:
                lines.append(f"| **CVSS Vector** | `{cvss_vector}` |")
            if cwe:
                lines.append(f"| **CWE** | {cwe} |")
            lines.append("")

            for section_title, field, fenced in [
                ("Summary", "summary", False),
                ("Impact", "impact", False),
                ("Evidence", "evidence", True),
                ("Reproduction Steps", "recipe", False),
                ("Mitigations", "mitigations", False),
            ]:
                text = f.get(field, "")
                if not text:
                    continue
                lines.append(f"### {section_title}\n")
                if fenced:
                    lines.append("```")
                    lines.append(text)
                    lines.append("```")
                else:
                    lines.append(text)
                lines.append("")

        with open(md_path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"Wrote {md_path}")
    finally:
        if not keep_json:
            os.remove(json_path)


def main():
    parser = argparse.ArgumentParser(description="List findings for an XBOW asset")
    parser.add_argument("asset_id", help="Asset ID to fetch findings for")
    parser.add_argument(
        "--print",
        action="store_true",
        dest="print_table",
        help="Print findings table to console",
    )
    parser.add_argument(
        "--json", action="store_true", help="Write findings to <asset_id>.json"
    )
    parser.add_argument(
        "--csv", action="store_true", help="Write findings to <asset_id>.csv"
    )
    parser.add_argument(
        "--pdf", action="store_true", help="Write findings to <asset_id>.pdf"
    )
    parser.add_argument(
        "--markdown", action="store_true", help="Write findings to <asset_id>.md"
    )
    args = parser.parse_args()

    if not any([args.print_table, args.json, args.csv, args.pdf, args.markdown]):
        parser.error(
            "Specify at least one output flag: --print, --json, --csv, --pdf, --markdown"
        )

    api_key = os.environ.get("XBOW_API_KEY")
    if not api_key:
        token_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "token.txt"
        )
        if os.path.exists(token_file):
            with open(token_file) as f:
                api_key = f.read().strip()
    if not api_key:
        sys.exit(
            "Error: XBOW_API_KEY environment variable not set and token.txt not found"
        )

    asset = get_asset(api_key, args.asset_id)
    asset_name = asset.get("name") or args.asset_id

    findings = sort_findings(list_findings(api_key, args.asset_id))

    if args.print_table:
        print_table(findings, args.asset_id)

    if args.json or args.csv or args.pdf or args.markdown:
        findings = enrich_findings(api_key, findings)
        if args.json:
            write_json(findings, args.asset_id)
        if args.csv:
            write_csv(findings, args.asset_id)
        if args.pdf:
            write_pdf(findings, args.asset_id, asset_name, keep_json=args.json)
        if args.markdown:
            write_markdown(findings, args.asset_id, asset_name, keep_json=args.json)


if __name__ == "__main__":
    main()
