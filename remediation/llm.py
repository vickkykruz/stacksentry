"""
remediation/llm.py — Anthropic API integration for intelligent patch generation.
 
Uses Claude to generate context-aware, stack-specific patch files that go
beyond static templates by incorporating:
  - The actual details from the failed check (e.g. the exact nginx version)
  - The detected stack fingerprint (e.g. Flask + Nginx + Ubuntu)
  - The specific error or misconfiguration found
 
The response is structured JSON that the generator parses into a PatchResult.
"""
 
from __future__ import annotations
import json
import os
from typing import Optional
 
 
# ── Anthropic client (lazy import so the package is optional) ─────────────────
 
def _get_client(api_key: Optional[str] = None):
    """Return an Anthropic client, raising ImportError if not installed."""
    try:
        import anthropic
    except ImportError as e:
        raise ImportError(
            "The 'anthropic' package is required for LLM patch generation. "
            "Install it with: pip install anthropic"
        ) from e
 
    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise ValueError(
            "No Anthropic API key found. Set ANTHROPIC_API_KEY environment "
            "variable or pass --anthropic-key to the CLI."
        )
    return anthropic.Anthropic(api_key=key)
 
 
# ── System prompt ─────────────────────────────────────────────────────────────
 
_SYSTEM_PROMPT = """\
You are StackSentry's remediation engine. Your job is to generate precise,
safe, ready-to-apply patch files for security misconfigurations.
 
You will receive details about a failed security check including:
- The check ID and what it tests
- The exact details from the scan (what was found)
- The detected technology stack
- The recommended fix
 
You must respond with ONLY valid JSON in this exact structure — no prose,
no markdown, no code fences, just raw JSON:
 
{
  "filename": "CHECK-ID.ext",
  "file_type": "python|shell|nginx|dockerfile|yaml",
  "content": "...the complete patch file content...",
  "instructions": "Step-by-step instructions to apply this patch",
  "verification": "A single command to verify the fix was applied"
}
 
Rules for the patch content:
1. Always include a dry-run mode (show what would change without applying)
2. Always create backups before modifying existing files
3. Always validate changes before applying (e.g. nginx -t before reload)
4. Include the check ID and description as a comment at the top
5. Be specific — use the actual values from the check details
6. Shell scripts must start with #!/bin/bash and set -euo pipefail
7. Python scripts must include a --apply flag guard
8. Make patches idempotent — safe to run multiple times
"""
 
 
# ── LLM patch generator ───────────────────────────────────────────────────────
 
def generate_patch_with_llm(
    check_id: str,
    check_name: str,
    layer: str,
    details: str,
    severity: str,
    stack_fingerprint: str,
    recommendation: str,
    api_key: Optional[str] = None,
) -> Optional[dict]:
    """
    Call the Anthropic API to generate a context-aware patch.
 
    Returns a patch dict on success, None on any failure.
    The generator falls back to static templates when this returns None.
    """
    try:
        client = _get_client(api_key)
    except (ImportError, ValueError):
        return None
 
    user_message = f"""\
Generate a remediation patch for this security check failure:
 
Check ID:    {check_id}
Check Name:  {check_name}
Layer:       {layer}
Severity:    {severity}
Stack:       {stack_fingerprint}
 
What was found:
{details}
 
Recommended fix:
{recommendation}
 
Generate a complete, ready-to-apply patch file that fixes this specific issue.
Use the stack information to make the patch precise — for example, if the stack
includes "Nginx", generate nginx config; if it includes "Flask", generate Python.
"""
 
    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
 
        raw = response.content[0].text.strip()
 
        # Strip markdown code fences if Claude added them despite instructions
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
 
        patch_data = json.loads(raw)
 
        # Validate required keys are present
        required = {"filename", "file_type", "content", "instructions", "verification"}
        if not required.issubset(patch_data.keys()):
            return None
 
        return patch_data
 
    except Exception:
        # Any failure — JSON parse error, API error, timeout — returns None
        # and the generator falls back to the static template
        return None