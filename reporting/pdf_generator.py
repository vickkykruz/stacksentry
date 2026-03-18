"""
PDF Report Generation using ReportLab.

Generates a structured security audit report with professional design:
- Consistent color palette
- Running page headers/footers
- Color-coded grade, status cells, and risk levels
- Proper margins and typography
- Visual title page with banner
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph,
    Spacer, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
from sec_audit.results import ScanResult
from sec_audit.planner import build_hardening_plan
from sec_audit.narratives import generate_owasp_narrative
from sec_audit.baseline import HARDENED_FLASK_BASELINE
from typing import List
import datetime

# ── Brand palette ────────────────────────────────────────────────────────────
NAVY        = colors.HexColor("#0D1B2A")
STEEL       = colors.HexColor("#1B3A5C")
ACCENT      = colors.HexColor("#2196F3")
PASS_GREEN  = colors.HexColor("#2E7D32")
FAIL_RED    = colors.HexColor("#C62828")
WARN_AMBER  = colors.HexColor("#F57F17")
LIGHT_GREEN = colors.HexColor("#E8F5E9")
LIGHT_RED   = colors.HexColor("#FFEBEE")
LIGHT_AMBER = colors.HexColor("#FFFDE7")
ROW_ALT     = colors.HexColor("#F5F7FA")
RULE_GREY   = colors.HexColor("#CFD8DC")
TEXT_DARK   = colors.HexColor("#212121")
TEXT_MUTED  = colors.HexColor("#546E7A")

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


# ── Grade colour helper ───────────────────────────────────────────────────────
def _grade_color(grade: str):
    return {
        "A": PASS_GREEN,
        "B": colors.HexColor("#558B2F"),
        "C": WARN_AMBER,
        "D": colors.HexColor("#E65100"),
        "F": FAIL_RED,
    }.get(grade.upper(), STEEL)


def _status_bg(status: str):
    return {
        "PASS": LIGHT_GREEN,
        "FAIL": LIGHT_RED,
        "WARN": LIGHT_AMBER,
    }.get(status.upper(), colors.white)


def _status_fg(status: str):
    return {
        "PASS": PASS_GREEN,
        "FAIL": FAIL_RED,
        "WARN": WARN_AMBER,
    }.get(status.upper(), TEXT_DARK)


def _risk_bg(risk: str):
    risk_upper = risk.upper() if risk else ""
    if "HIGH" in risk_upper or "CRIT" in risk_upper:
        return LIGHT_RED
    if "MED" in risk_upper:
        return LIGHT_AMBER
    return LIGHT_GREEN


# ── Page header/footer via canvas callbacks ───────────────────────────────────
def _make_page_callbacks(title: str, target: str, total_pages_ref: list):
    """Return onFirstPage and onLaterPages callbacks."""

    def _header_footer(canv, doc):
        canv.saveState()
        page_num = doc.page

        # Header bar
        canv.setFillColor(NAVY)
        canv.rect(MARGIN, PAGE_H - 14*mm, PAGE_W - 2*MARGIN, 10*mm, fill=1, stroke=0)
        canv.setFillColor(colors.white)
        canv.setFont("Helvetica-Bold", 8)
        canv.drawString(MARGIN + 3*mm, PAGE_H - 9*mm, title)
        canv.setFont("Helvetica", 8)
        canv.drawRightString(PAGE_W - MARGIN - 3*mm, PAGE_H - 9*mm, f"Target: {target}")

        # Footer rule + text
        canv.setStrokeColor(RULE_GREY)
        canv.setLineWidth(0.5)
        canv.line(MARGIN, 12*mm, PAGE_W - MARGIN, 12*mm)
        canv.setFillColor(TEXT_MUTED)
        canv.setFont("Helvetica", 7)
        canv.drawString(MARGIN, 8*mm, f"Generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}  •  CONFIDENTIAL")
        canv.drawRightString(PAGE_W - MARGIN, 8*mm, f"Page {page_num}")

        canv.restoreState()

    def _first_page(canv, doc):
        _header_footer(canv, doc)

    def _later_pages(canv, doc):
        _header_footer(canv, doc)

    return _first_page, _later_pages


# ── Style helpers ─────────────────────────────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()
    styles = {}

    styles["h1"] = ParagraphStyle(
        "h1", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=22,
        textColor=colors.white, alignment=TA_CENTER,
        spaceAfter=4,
    )
    styles["h2"] = ParagraphStyle(
        "h2", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=13,
        textColor=NAVY, spaceBefore=14, spaceAfter=6,
        borderPad=0,
    )
    styles["h3"] = ParagraphStyle(
        "h3", parent=base["Normal"],
        fontName="Helvetica-Bold", fontSize=10,
        textColor=STEEL, spaceBefore=8, spaceAfter=4,
    )
    styles["body"] = ParagraphStyle(
        "body", parent=base["Normal"],
        fontName="Helvetica", fontSize=9,
        textColor=TEXT_DARK, leading=14,
    )
    styles["muted"] = ParagraphStyle(
        "muted", parent=base["Normal"],
        fontName="Helvetica", fontSize=8,
        textColor=TEXT_MUTED, leading=12,
    )
    styles["meta"] = ParagraphStyle(
        "meta", parent=base["Normal"],
        fontName="Helvetica", fontSize=9,
        textColor=colors.white, alignment=TA_CENTER,
        leading=16,
    )
    return styles


# ── Section heading with accent rule ─────────────────────────────────────────
def _section(title: str, styles) -> list:
    return [
        Paragraph(title, styles["h2"]),
        HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceAfter=6),
    ]


# ── Grade badge table ─────────────────────────────────────────────────────────
def _grade_badge(scan_result: ScanResult, styles) -> Table:
    grade = scan_result.grade
    gc = _grade_color(grade)
    summary = scan_result.summary()
    passed = summary["status_breakdown"].get("PASS", 0)
    high_risk = summary["high_risk_issues"]

    data = [
        [
            Paragraph(f'<font size="36"><b>{grade}</b></font>', ParagraphStyle(
                "grade_big", fontName="Helvetica-Bold", fontSize=36,
                textColor=colors.white, alignment=TA_CENTER,
            )),
            Table(
                [
                    [Paragraph("<b>Score</b>", ParagraphStyle("kl", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
                     Paragraph(f"{scan_result.score_percentage}%", ParagraphStyle("kv", fontName="Helvetica-Bold", fontSize=18, textColor=colors.white))],
                    [Paragraph("<b>Passed</b>", ParagraphStyle("kl", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
                     Paragraph(f"{passed} / {scan_result.total_checks}", ParagraphStyle("kv", fontName="Helvetica", fontSize=11, textColor=colors.white))],
                    [Paragraph("<b>High Risk</b>", ParagraphStyle("kl", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white)),
                     Paragraph(str(high_risk), ParagraphStyle("kv", fontName="Helvetica-Bold", fontSize=11, textColor=LIGHT_RED if high_risk > 0 else colors.white))],
                ],
                colWidths=[35*mm, 55*mm],
            ),
        ]
    ]

    t = Table(data, colWidths=[40*mm, 100*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), gc),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
    ]))
    return t


# ── Main generate function ────────────────────────────────────────────────────
def generate_pdf(scan_result: ScanResult, output_path: str, profile: str = "generic") -> None:
    """
    Generate a professional PDF security audit report from ScanResult.

    Args:
        scan_result: Complete scan results with checks and scoring
        output_path: Path to save PDF (e.g., "security_report.pdf")
    """
    styles = _build_styles()

    report_title = "Security Audit Report"
    on_first_page, on_later_pages = _make_page_callbacks(
        report_title, scan_result.target, []
    )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=MARGIN,
        leftMargin=MARGIN,
        topMargin=22 * mm,   # room for header bar
        bottomMargin=18 * mm,  # room for footer
        title=report_title,
        author="Security Audit Framework",
    )

    story = []

    # ── TITLE BANNER ──────────────────────────────────────────────────────────
    # Dark navy banner table acting as a cover block
    banner_data = [[
        Paragraph("Security Audit Framework", ParagraphStyle(
            "banner_sub", fontName="Helvetica", fontSize=11,
            textColor=colors.HexColor("#90CAF9"), alignment=TA_CENTER,
        )),
    ], [
        Paragraph(report_title, styles["h1"]),
    ], [
        Paragraph(
            f"<b>Target:</b> {scan_result.target}<br/>"
            f"<b>Scan Mode:</b> {scan_result.mode}<br/>"
            f"<b>Generated:</b> {scan_result.generated_at}",
            styles["meta"],
        ),
    ]]

    banner = Table(banner_data, colWidths=[PAGE_W - 2*MARGIN])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(banner)
    story.append(Spacer(1, 14))

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    story.extend(_section("Executive Summary", styles))
    story.append(_grade_badge(scan_result, styles))
    story.append(Spacer(1, 14))
    
    # ── AI NARRATIVE ──────────────────────────────────────────────────────────
    narrative_label_style = ParagraphStyle(
        "narrative_label", fontName="Helvetica-Bold", fontSize=8,
        textColor=ACCENT, leading=12, spaceAfter=4,
    )
    narrative_body_style = ParagraphStyle(
        "narrative_body", fontName="Helvetica", fontSize=9,
        textColor=TEXT_DARK, leading=14, wordWrap="CJK",
    )
    narrative_text = scan_result.executive_narrative()
    narrative_inner = Table(
        [
            [Paragraph("AI-GENERATED ASSESSMENT", narrative_label_style)],
            [Paragraph(narrative_text, narrative_body_style)],
        ],
        colWidths=[PAGE_W - 2*MARGIN - 14*mm],
    )
    narrative_inner.setStyle(TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING",   (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
    ]))
    narrative_card = Table([[narrative_inner]], colWidths=[PAGE_W - 2*MARGIN])
    narrative_card.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), colors.HexColor("#E3F2FD")),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",(0, 0), (-1, -1), 12),
        ("TOPPADDING",  (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("LINEBEFORE",  (0, 0), (0, -1), 4, ACCENT),
        ("BOX",         (0, 0), (-1, -1), 0.5, RULE_GREY),
    ]))
    story.append(narrative_card)
    story.append(Spacer(1, 14))

    # ── ATTACK SURFACE HEATMAP ────────────────────────────────────────────────
    story.extend(_section("Attack Surface Heatmap", styles))

    layer_data = scan_result.layer_summary()
    layers_order = ["app", "webserver", "container", "host"]
    layer_labels = {"app": "Web App", "webserver": "Web Server", "container": "Container", "host": "Host"}

    heatmap_rows = [[
        Paragraph("<b>Layer</b>", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=TA_CENTER)),
        Paragraph("<b>Pass Rate</b>", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=TA_CENTER)),
        Paragraph("<b>Status</b>", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=TA_CENTER)),
        Paragraph("<b>Risk</b>", ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=TA_CENTER)),
    ]]

    heatmap_style = [
        ("BACKGROUND", (0, 0), (-1, 0), STEEL),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
    ]

    _hm_cell = ParagraphStyle("hm_cell", fontName="Helvetica", fontSize=9,
                              textColor=TEXT_DARK, alignment=TA_CENTER, leading=12, wordWrap="CJK")
    _hm_pill = ParagraphStyle("hm_pill", fontName="Helvetica-Bold", fontSize=8,
                              textColor=colors.white, alignment=TA_CENTER, leading=11)

    # Map the raw color string from layer_summary() to palette colors + label
    STATUS_MAP = {
        # Plain string variants
        "green":  (PASS_GREEN, "PASS"),
        "amber":  (WARN_AMBER, "WARN"),
        "orange": (WARN_AMBER, "WARN"),
        "red":    (FAIL_RED,   "FAIL"),
        "grey":   (STEEL,      "N/A"),
        "gray":   (STEEL,      "N/A"),
        # Emoji variants (from layer_summary() in results.py)
        "🟢":     (PASS_GREEN, "PASS"),
        "🟡":     (WARN_AMBER, "WARN"),
        "🔴":     (FAIL_RED,   "FAIL"),
    }

    for i, layer in enumerate(layers_order, 1):
        if layer in layer_data:
            stats = layer_data[layer]
            risk       = stats.get("risk", "")
            raw_color  = str(stats.get("color", "")).lower().strip()
            pill_color, pill_label = STATUS_MAP.get(raw_color, (STEEL, raw_color.upper() or "—"))
            bg = _risk_bg(risk)

            # Status pill
            status_pill = Table(
                [[Paragraph(pill_label, _hm_pill)]],
                colWidths=[28*mm],
            )
            status_pill.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), pill_color),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("LEFTPADDING",  (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ]))

            heatmap_rows.append([
                Paragraph(layer_labels.get(layer, layer), _hm_cell),
                Paragraph(f"{stats['pass_rate']}%  ({stats['passed']}/{stats['total']})", _hm_cell),
                status_pill,
                Paragraph(str(risk), _hm_cell),
            ])
            heatmap_style.append(("BACKGROUND", (0, i), (-1, i), bg))

    heatmap_table = Table(heatmap_rows, colWidths=[40*mm, 55*mm, 30*mm, 45*mm])
    heatmap_table.setStyle(TableStyle(heatmap_style))
    story.append(heatmap_table)
    story.append(Spacer(1, 14))

    
    # ── TOP 5 PRIORITY FIXES ────────────────────────────────────────────────────
    story.extend(_section("Top 5 Priority Fixes", styles))

    fix_label_style = ParagraphStyle(
        "fix_label", fontName="Helvetica-Bold", fontSize=7,
        textColor=colors.white, alignment=TA_CENTER, leading=9,
    )
    fix_id_style = ParagraphStyle(
        "fix_id", fontName="Helvetica-Bold", fontSize=8,
        textColor=NAVY, leading=11, wordWrap="CJK",
    )
    fix_title_style = ParagraphStyle(
        "fix_title", fontName="Helvetica-Bold", fontSize=9,
        textColor=TEXT_DARK, leading=12, wordWrap="CJK",
    )
    fix_detail_style = ParagraphStyle(
        "fix_detail", fontName="Helvetica", fontSize=8,
        textColor=TEXT_MUTED, leading=11, wordWrap="CJK",
    )
    fix_tag_style = ParagraphStyle(
        "fix_tag", fontName="Helvetica-Bold", fontSize=7,
        textColor=colors.white, alignment=TA_CENTER, leading=10,
    )

    priority_fixes = scan_result.priority_fixes()

    if priority_fixes:
        SEVERITY_COLORS = {
            "CRITICAL": colors.HexColor("#B71C1C"),
            "HIGH":     FAIL_RED,
            "MEDIUM":   WARN_AMBER,
            "LOW":      PASS_GREEN,
            "INFO":     STEEL,
        }
        SEVERITY_BG = {
            "CRITICAL": colors.HexColor("#FFCDD2"),
            "HIGH":     LIGHT_RED,
            "MEDIUM":   LIGHT_AMBER,
            "LOW":      LIGHT_GREEN,
            "INFO":     colors.HexColor("#E3F2FD"),
        }

        # Header row
        hdr_s = ParagraphStyle("fhdr", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white, alignment=TA_CENTER)
        fix_header = Table(
            [[
                Paragraph("#",        hdr_s),
                Paragraph("Check ID", hdr_s),
                Paragraph("Fix",      hdr_s),
                Paragraph("Severity / Status", hdr_s),
                Paragraph("Layer",    hdr_s),
            ]],
            colWidths=[10*mm, 32*mm, 90*mm, 22*mm, 22*mm],
        )
        fix_header.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), NAVY),
            ("TOPPADDING",   (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
            ("LEFTPADDING",  (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(fix_header)

        # Handle both list-of-dicts and raw HTML/string fallback
        if isinstance(priority_fixes, list):
            fixes_iter = priority_fixes
        else:
            # Raw string fallback — display in a single styled callout
            fixes_iter = []
            fallback_card = Table(
                [[Paragraph(str(priority_fixes), fix_detail_style)]],
                colWidths=[PAGE_W - 2*MARGIN],
            )
            fallback_card.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), ROW_ALT),
                ("LEFTPADDING",  (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING",   (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
                ("BOX",          (0, 0), (-1, -1), 0.5, RULE_GREY),
            ]))
            story.append(fallback_card)

        for idx, fix in enumerate(fixes_iter[:5], 1):
            severity  = str(fix.get("severity", "HIGH")).upper()
            sev_color = SEVERITY_COLORS.get(severity, STEEL)
            sev_bg    = SEVERITY_BG.get(severity, ROW_ALT)
            row_bg    = sev_bg if idx % 2 != 0 else colors.white

            # Numbered badge cell
            badge_cell = Table(
                [[Paragraph(str(idx), fix_label_style)]],
                colWidths=[10*mm],
            )
            badge_cell.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), sev_color),
                ("TOPPADDING",   (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
                ("LEFTPADDING",  (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ]))

            # Status pill — FAIL=red, WARN=amber
            status       = str(fix.get("status", "FAIL")).upper()
            status_color = FAIL_RED if status == "FAIL" else WARN_AMBER if status == "WARN" else STEEL
            status_pill  = Table(
                [[Paragraph(status, fix_tag_style)]],
                colWidths=[22*mm],
            )
            status_pill.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), status_color),
                ("TOPPADDING",   (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
                ("LEFTPADDING",  (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ]))

            # Severity pill — stacked above status pill in same cell
            sev_pill = Table(
                [[Paragraph(severity, fix_tag_style)]],
                colWidths=[22*mm],
            )
            sev_pill.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), sev_color),
                ("TOPPADDING",   (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
                ("LEFTPADDING",  (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ]))

            # Combined pill cell: severity on top, status below
            pill_cell = Table(
                [[sev_pill], [Spacer(1, 2)], [status_pill]],
                colWidths=[22*mm],
            )
            pill_cell.setStyle(TableStyle([
                ("LEFTPADDING",  (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING",   (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
            ]))

            fix_row = Table(
                [[
                    badge_cell,
                    Paragraph(str(fix.get("id", "")), fix_id_style),
                    Table(
                        [
                            [Paragraph(str(fix.get("name", fix.get("title", "—"))), fix_title_style)],
                            [Paragraph(str(fix.get("details", fix.get("description", ""))), fix_detail_style)],
                        ],
                        colWidths=[90*mm],
                    ),
                    pill_cell,
                    Paragraph(str(fix.get("layer", "—")), fix_detail_style),
                ]],
                colWidths=[10*mm, 32*mm, 90*mm, 22*mm, 22*mm],
            )
            fix_row.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), row_bg),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",   (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
                ("LEFTPADDING",  (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("LINEBELOW",    (0, 0), (-1, 0), 0.5, RULE_GREY),
                ("LINEBEFORE",   (0, 0), (0, 0), 3, sev_color),
            ]))
            story.append(fix_row)

    else:
        story.append(Paragraph(
            "No priority fixes identified. System is within acceptable security parameters.",
            ParagraphStyle("no_fix", fontName="Helvetica", fontSize=9, textColor=PASS_GREEN, leading=13),
        ))

    story.append(Spacer(1, 14))
    
    # ── PRIORITISED HARDENING PLAN ────────────────────────────────────────────
    story.extend(_section("Prioritised Hardening Plan (Day 1 / Day 7 / Day 30)", styles))

    # Get plan items: either via planner module or ScanResult method
    try:
        plan_items = build_hardening_plan(scan_result)  # if using planner.py
        # plan_items = scan_result.hardening_plan()     # if using method on ScanResult
    except Exception:
        plan_items = []

    if not plan_items:
        story.append(
            Paragraph(
                "No outstanding issues requiring a hardening plan. All checks are passing.",
                styles["body"],
            )
        )
        story.append(Spacer(1, 14))
    else:
        # Limit to e.g. top 12 entries to keep table readable
        plan_subset = plan_items[:12]

        # Header row
        hp_hdr_style = ParagraphStyle(
            "hp_hdr", fontName="Helvetica-Bold", fontSize=8,
            textColor=colors.white, alignment=TA_CENTER,
        )
        hp_cell = ParagraphStyle(
            "hp_cell", fontName="Helvetica", fontSize=8,
            textColor=TEXT_DARK, leading=11, wordWrap="CJK",
        )

        hp_rows = [[
            Paragraph("Bucket", hp_hdr_style),
            Paragraph("Check ID", hp_hdr_style),
            Paragraph("Layer", hp_hdr_style),
            Paragraph("Severity", hp_hdr_style),
            Paragraph("Priority", hp_hdr_style),
            Paragraph("Recommended Fix", hp_hdr_style),
        ]]

        hp_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), STEEL),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
        ]

        for idx, item in enumerate(plan_subset, 1):
            bucket_label = {
                "DAY_1": "Day 1 (Immediate)",
                "DAY_7": "Day 7 (Short-term)",
                "DAY_30": "Day 30 (Medium-term)",
            }.get(item.get("bucket", ""), item.get("bucket", ""))

            # Alternate row backgrounds
            if idx % 2 == 0:
                hp_styles.append(("BACKGROUND", (0, idx), (-1, idx), ROW_ALT))

            hp_rows.append([
                Paragraph(bucket_label, hp_cell),
                Paragraph(item["id"], hp_cell),
                Paragraph(item["layer"], hp_cell),
                Paragraph(item["severity"], hp_cell),
                Paragraph(str(item["priority_score"]), hp_cell),
                Paragraph(item["recommendation"] or "-", hp_cell),
            ])

        hp_table = Table(
            hp_rows,
            colWidths=[30*mm, 25*mm, 20*mm, 22*mm, 20*mm, PAGE_W - 2*MARGIN - 117*mm],
            repeatRows=1,
        )
        hp_table.setStyle(TableStyle(hp_styles))
        story.append(hp_table)
        story.append(Spacer(1, 14))
    
    # ── OWASP TOP 5 RISK SUMMARY
    story.extend(_section("OWASP Top 5 Risk Summary (2025)", styles))

    owasp_data = scan_result.owasp_summary()
    top10_order = [
        "A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025",
        "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025",
    ]

    _ow_th = ParagraphStyle("owasp_th", fontName="Helvetica-Bold", fontSize=9,
                            textColor=colors.white, alignment=TA_LEFT, leading=12)
    _ow_td = ParagraphStyle("owasp_td", fontName="Helvetica", fontSize=8,
                            textColor=TEXT_DARK, leading=12, wordWrap="CJK")
    _ow_pill = ParagraphStyle("owasp_pill", fontName="Helvetica-Bold", fontSize=8,
                              textColor=colors.white, alignment=TA_CENTER, leading=11)

    def _fail_rate_pill(rate: float) -> Table:
        if rate >= 70:
            bg = FAIL_RED
        elif rate >= 40:
            bg = WARN_AMBER
        else:
            bg = PASS_GREEN
        pill = Table([[Paragraph(f"{rate}%", _ow_pill)]], colWidths=[23*mm])
        pill.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), bg),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
            ("LEFTPADDING",  (0, 0), (-1, -1), 2),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return pill

    owasp_rows = [[
        Paragraph("OWASP Category", _ow_th),
        Paragraph("Failed Checks", _ow_th),
        Paragraph("Fail Rate", _ow_th),
    ]]

    owasp_row_styles = [
        ("BACKGROUND",   (0, 0), (-1, 0), STEEL),
        ("ALIGN",        (1, 1), (-1, -1), "CENTER"),
        ("ALIGN",        (0, 0), (0, -1), "LEFT"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",         (0, 0), (-1, -1), 0.5, RULE_GREY),
        ("TOPPADDING",   (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]

    populated = [(cat, owasp_data.get(cat)) for cat in top10_order if owasp_data.get(cat)]

    if populated:
        for row_idx, (cat, data) in enumerate(populated, 1):
            fail_rate = float(data.get("fail_rate", 0))
            label = f"<b>{cat}</b> – {data['label']}"
            owasp_rows.append([
                Paragraph(label, _ow_td),
                Paragraph(str(data["failed"]), ParagraphStyle(
                    "owasp_fc", fontName="Helvetica-Bold", fontSize=9,
                    textColor=TEXT_DARK, alignment=TA_CENTER, leading=12,
                )),
                _fail_rate_pill(fail_rate),
            ])
            if row_idx % 2 == 0:
                owasp_row_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), ROW_ALT))
    else:
        owasp_rows.append([
            Paragraph("No OWASP Top 5 categories triggered by current checks.", _ow_td),
            Paragraph("—", _ow_td),
            Paragraph("—", _ow_td),
        ])

    owasp_table = Table(owasp_rows, colWidths=[100*mm, 32*mm, 25*mm])
    owasp_table.setStyle(TableStyle(owasp_row_styles))
    story.append(owasp_table)
    story.append(Spacer(1, 10))
    
    # ── OWASP CONTEXTUAL NARRATIVE ───────────────────────────────────────────
    owasp_narrative = generate_owasp_narrative(scan_result, profile)

    narrative_style = ParagraphStyle(
        "owasp_narr",
        fontName="Helvetica",
        fontSize=9,
        textColor=TEXT_DARK,
        leading=14,
        wordWrap="CJK",
    )

    owasp_narr_card = Table(
        [[Paragraph(owasp_narrative, narrative_style)]],
        colWidths=[PAGE_W - 2 * MARGIN],
    )
    owasp_narr_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#E8EAF6")),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor("#5C6BC0")),
        ("BOX", (0, 0), (-1, -1), 0.5, RULE_GREY),
    ]))
    story.append(owasp_narr_card)
    story.append(Spacer(1, 14))

    
    # ── 30-DAY HARDENING ROADMAP SIMULATION ─────────────────────────────────────
    story.extend(_section("30-Day Hardening Roadmap Simulation", styles))

    day1_items = [i for i in plan_items if i.get("bucket") == "DAY_1"]
    day7_items = [i for i in plan_items if i.get("bucket") == "DAY_7"]
    day30_items = [i for i in plan_items if i.get("bucket") == "DAY_30"]

    # Run simulations
    sim_day1 = scan_result.simulate_with_fixes([i["id"] for i in day1_items]) if day1_items else None
    sim_day7 = scan_result.simulate_with_fixes([i["id"] for i in day1_items + day7_items]) if day1_items or day7_items else None
    sim_day30 = scan_result.simulate_with_fixes([i["id"] for i in plan_items]) if plan_items else None

    # Build comprehensive table
    sim_data = [
        ["Phase", "Fixes", "Grade", "Score", "Attack Paths"],
        ["Current", "0", scan_result.grade.value, f"{scan_result.score_percentage}%", str(scan_result.attack_path_count)],
    ]

    if day1_items:
        sim_data.append(["Day 1", f"{len(day1_items)}", sim_day1["simulated_grade"], f"{sim_day1['simulated_score_percentage']}%", str(sim_day1["simulated_attack_path_count"])])

    if day7_items and sim_day7:
        sim_data.append(["Day 7", f"{len(day1_items + day7_items)}", sim_day7["simulated_grade"], f"{sim_day7['simulated_score_percentage']}%", str(sim_day7["simulated_attack_path_count"])])

    if day30_items and sim_day30:
        sim_data.append(["Day 30", f"{len(plan_items)}", sim_day30["simulated_grade"], f"{sim_day30['simulated_score_percentage']}%", str(sim_day30["simulated_attack_path_count"])])

    # Styled roadmap table
    roadmap_table = Table(sim_data, colWidths=[25*mm, 20*mm, 25*mm, 25*mm, 35*mm])
    roadmap_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), STEEL),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.8, colors.HexColor("#B0BEC5")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ROW_ALT]),
        
        # Phase column colors
        ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#FFCDD2")),  # Day 1: Light red
        ("FONTNAME", (0, 1), (0, 1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 2), (0, 2), colors.HexColor("#FFF3E0")),  # Day 7: Light orange  
        ("FONTNAME", (0, 2), (0, 2), "Helvetica-Bold"),
        ("BACKGROUND", (0, 3), (0, 3), colors.HexColor("#E8F5E8")),  # Day 30: Light green
    ]))

    story.append(roadmap_table)
    story.append(Spacer(1, 14))

    
    # ── CONFIGURATION DRIFT ───────────────────────────────────────────────────
    story.extend(_section("Configuration Drift vs Hardened Flask LMS", styles))
    drift = scan_result.compare_to_baseline(HARDENED_FLASK_BASELINE)

    improved = ", ".join(drift["improved_checks"]) or "None"
    regressed = ", ".join(drift["regressed_checks"]) or "None"

    _dk = ParagraphStyle("drift_key", fontName="Helvetica-Bold", fontSize=9, textColor=TEXT_DARK, leading=13, wordWrap="CJK")
    _dv = ParagraphStyle("drift_val", fontName="Helvetica", fontSize=9, textColor=TEXT_DARK, leading=13, wordWrap="CJK")

    drift_data = [
        [Paragraph("Grade Delta", _dk),    Paragraph(str(drift["grade_delta"]), _dv)],
        [Paragraph("Pass Delta", _dk),     Paragraph(f"{drift['pass_delta']} checks vs baseline", _dv)],
        [Paragraph("Improved Checks", _dk), Paragraph(improved, _dv)],
        [Paragraph("Regressed Checks", _dk), Paragraph(regressed, _dv)],
    ]

    drift_table = Table(drift_data, colWidths=[50*mm, PAGE_W - 2*MARGIN - 50*mm])
    drift_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, ROW_ALT]),
    ]))
    story.append(drift_table)
    story.append(Spacer(1, 14))

    # ── DETAILED FINDINGS BY LAYER ────────────────────────────────────────────
    layers: dict = {}
    for check in scan_result.checks:
        layers.setdefault(check.layer, []).append(check)

    for layer_name, checks in layers.items():
        story.extend(_section(f"{layer_name.upper()} Layer Findings", styles))

        col_hdr_style = ParagraphStyle("colhdr", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white, alignment=TA_CENTER)
        table_data = [[
            Paragraph("ID", col_hdr_style),
            Paragraph("Check", col_hdr_style),
            Paragraph("Status", col_hdr_style),
            Paragraph("Severity", col_hdr_style),
            Paragraph("Details", col_hdr_style),
        ]]

        row_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), STEEL),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
        ]

        cell_style = ParagraphStyle("cell", fontName="Helvetica", fontSize=8, textColor=TEXT_DARK, leading=11, wordWrap="CJK")
        cell_center = ParagraphStyle("cell_c", fontName="Helvetica", fontSize=8, textColor=TEXT_DARK, leading=11, alignment=TA_CENTER, wordWrap="CJK")

        for row_idx, check in enumerate(checks, 1):
            status = check.status.upper()
            status_label = {"PASS": "PASS", "FAIL": "FAIL", "WARN": "WARN"}.get(status, status)
            status_fg = _status_fg(status)
            status_bg = _status_bg(status)

            table_data.append([
                Paragraph(check.id, cell_style),
                Paragraph(check.name, cell_style),
                Paragraph(
                    f'<font color="{status_fg.hexval()}"><b>{status_label}</b></font>',
                    ParagraphStyle("status_cell", fontSize=8, alignment=TA_CENTER, leading=11, wordWrap="CJK"),
                ),
                Paragraph(str(check.severity), cell_center),
                Paragraph(check.details, cell_style),
            ])
            row_styles.append(("BACKGROUND", (2, row_idx), (2, row_idx), status_bg))
            if row_idx % 2 == 0:
                row_styles.append(("BACKGROUND", (0, row_idx), (1, row_idx), ROW_ALT))
                row_styles.append(("BACKGROUND", (3, row_idx), (4, row_idx), ROW_ALT))

        findings_table = Table(
            table_data,
            colWidths=[22*mm, 65*mm, 22*mm, 22*mm, PAGE_W - 2*MARGIN - 131*mm],
            repeatRows=1,
        )
        findings_table.setStyle(TableStyle(row_styles))
        story.append(KeepTogether(findings_table))
        story.append(Spacer(1, 16))

    # ── CRITICAL ATTACK PATHS ─────────────────────────────────────────────────
    story.extend(_section("Critical Attack Paths", styles))
    paths = scan_result.attack_paths()

    if paths:
        col_hdr_style = ParagraphStyle("colhdr2", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white, alignment=TA_CENTER)
        path_data = [[
            Paragraph("#", col_hdr_style),
            Paragraph("Attack Path", col_hdr_style),
            Paragraph("Risk", col_hdr_style),
            Paragraph("Score", col_hdr_style),
        ]]
        path_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), FAIL_RED),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]

        for i, path in enumerate(paths[:3], 1):
            risk = path.get("risk", "")
            path_data.append([
                str(i),
                path["name"][:55],
                risk,
                f"{path['score']:.1f}",
            ])
            path_styles.append(("BACKGROUND", (0, i), (-1, i), _risk_bg(risk)))

        path_table = Table(path_data, colWidths=[12*mm, 95*mm, 30*mm, 25*mm])
        path_table.setStyle(TableStyle(path_styles))
        story.append(KeepTogether(path_table))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"<b>{len(paths)}</b> attack path(s) identified. Remediate highest-score paths first.",
            styles["body"],
        ))
    else:
        story.append(Paragraph("No multi-layer attack paths detected.", styles["body"]))
        
    # ── RECOMMENDED NEXT ACTIONS ────────────────────────────────────────────────
    story.append(Spacer(1, 14))
    story.extend(_section("Recommended Next Actions", styles))

    recs = scan_result.remediation_recommendations()
    if recs:
        rec_label_style = ParagraphStyle(
            "rec_num", fontName="Helvetica-Bold", fontSize=10,
            textColor=colors.white, alignment=TA_CENTER, leading=13,
        )
        rec_text_style = ParagraphStyle(
            "rec_text", fontName="Helvetica", fontSize=9,
            textColor=TEXT_DARK, leading=13, wordWrap="CJK",
        )
        for idx, rec in enumerate(recs, 1):
            priority_color = (
                FAIL_RED   if idx == 1 else
                WARN_AMBER if idx == 2 else
                STEEL
            )
            badge = Table([[Paragraph(str(idx), rec_label_style)]],
                          colWidths=[8*mm])
            badge.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), priority_color),
                ("TOPPADDING",   (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
                ("LEFTPADDING",  (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ]))
            rec_row = Table(
                [[badge, Paragraph(rec, rec_text_style)]],
                colWidths=[10*mm, PAGE_W - 2*MARGIN - 10*mm],
            )
            rec_row.setStyle(TableStyle([
                ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",   (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
                ("LEFTPADDING",  (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("BACKGROUND",   (1, 0), (1, 0), ROW_ALT if idx % 2 == 0 else colors.white),
                ("BOX",          (0, 0), (-1, -1), 0.5, RULE_GREY),
                ("LINEAFTER",    (0, 0), (0, 0), 0.5, RULE_GREY),
            ]))
            story.append(rec_row)
            story.append(Spacer(1, 4))
    else:
        no_rec_style = ParagraphStyle(
            "no_rec", fontName="Helvetica", fontSize=9,
            textColor=PASS_GREEN, leading=13,
        )
        story.append(Paragraph(
            "No immediate remediation required. Maintain current configuration and monitor regularly.",
            no_rec_style,
        ))

    # ── SERVER FINGERPRINT ────────────────────────────────────────────────────
    story.append(Spacer(1, 14))
    story.extend(_section("Server Fingerprint", styles))
    
    versions = scan_result.server_fingerprint()

    fp_data = []
    for key, value in versions.items():
        label = {"os": "OS", "docker": "Docker", "webserver": "Web Server", "app": "App"}.get(key, key.title())
        bg_color = LIGHT_GREEN if value != "N/A" else LIGHT_AMBER
        fp_data.append([label, value])
    
    fp_table = Table(fp_data, colWidths=[50*mm, PAGE_W - 2*MARGIN - 50*mm])
    fp_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, RULE_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [bg_color, ROW_ALT]),
        ("TEXTCOLOR", (0, 0), (-1, -1), TEXT_DARK),
    ]))
    story.append(fp_table)

    # ── BUILD ─────────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    print(f"PDF report generated: {output_path}")