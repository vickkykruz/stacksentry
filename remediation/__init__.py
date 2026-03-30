"""
StackSentry — Remediation engine.
 
Generates ready-to-apply patch files for every failed or warned check.
 
Public API:
    from remediation import PatchGenerator, PatchResult
 
Usage:
    generator = PatchGenerator(use_llm=True, api_key="sk-ant-...")
    results   = generator.generate_all(scan_result, output_dir="patches/")
"""
 
from remediation.generator import PatchGenerator, PatchResult
 
__all__ = ["PatchGenerator", "PatchResult"]