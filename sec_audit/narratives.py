"""
    CLI → generate_pdf(..., profile=...) → inside PDF, call generate_owasp_narrative(...) to get a string → render that string in a pretty card.
"""


from sec_audit.results import ScanResult


def generate_owasp_narrative(scan_result: ScanResult, profile: str) -> str:
    """
    Generate a contextual OWASP narrative based on user profile.
    """
    owasp_data = scan_result.owasp_summary()
    
    # Get top 2 failing categories
    failures = [
        (cat, data["failed"]) 
        for cat, data in owasp_data.items() 
        if data["failed"] > 0
    ]
    failures.sort(key=lambda x: x[1], reverse=True)
    top_risks = failures[:2] if failures else []
    
    grade = scan_result.grade.value
    
    # Profile-specific templates
    templates = {
        "student": (
            f"<b>Learning Context:</b> You're building foundational security knowledge. "
            f"The current grade ({grade}) reflects common beginner gaps. "
            f"{'Focus on ' + owasp_data[top_risks[0][0]]['label'] + ' and ' + owasp_data[top_risks[1][0]]['label'] if len(top_risks) >= 2 else 'Review basic security principles'}—"
            f"these are textbook vulnerabilities often tested in academic assessments. "
            f"Use this report to map theory (OWASP framework) to practice (actual misconfigurations)."
        ),
        "devops": (
            f"<b>Operational Context:</b> Your infrastructure automation needs hardening. "
            f"Grade {grade} indicates deployment pipeline gaps. "
            f"{'Priority: ' + owasp_data[top_risks[0][0]]['label'] if top_risks else 'Security misconfigurations'} "
            f"can be resolved through IaC templates, secret management (Vault/AWS Secrets), and CI/CD security gates. "
            f"Shift-left these fixes—automate validation before production."
        ),
        "pentester": (
            f"<b>Assessment Context:</b> Grade {grade} presents multiple entry points. "
            f"{'Attack chain: ' + owasp_data[top_risks[0][0]]['label'] + ' → ' + owasp_data[top_risks[1][0]]['label'] if len(top_risks) >= 2 else 'Multiple attack vectors present'}. "
            f"High-value targets include authentication bypass and privilege escalation paths. "
            f"Document exploit sequences for client report; recommend immediate remediation for critical paths."
        ),
        "cto": (
            f"<b>Executive Context:</b> Grade {grade} represents material cybersecurity risk. "
            f"{'Top exposure: ' + owasp_data[top_risks[0][0]]['label'] if top_risks else 'Multiple OWASP Top 10 categories triggered'}—"
            f"this is industry-standard vulnerability classification used by auditors and insurers. "
            f"Recommend immediate security sprint, penetration testing engagement, and quarterly reassessment. "
            f"Budget impact: {len([i for i in scan_result.checks if i.severity.value in ['CRITICAL', 'HIGH'] and i.status.value != 'PASS'])} "
            f"high-risk items require engineering time."
        ),
        "generic": (
            f"<b>Security Assessment:</b> Overall grade {grade}. "
            f"{'Primary concerns: ' + owasp_data[top_risks[0][0]]['label'] if top_risks else 'Multiple security gaps detected'}. "
            f"Review the prioritized hardening plan and address Day 1 items first. "
            f"OWASP alignment ensures industry-standard risk categorization."
        ),
    }
    
    return templates.get(profile, templates["generic"])