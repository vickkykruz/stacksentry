#!/usr/bin/env python3
 
 
"""
StackSentry CLI - Automated web application security configuration assessment.
 
Usage: python sec_audit.py --target http://example.com --output report.pdf
"""
 
 
# Load .env file before anything else so ANTHROPIC_API_KEY and other
# secrets are available to all modules without the user needing to
# manually set environment variables in the shell.
try:
    from dotenv import load_dotenv
    load_dotenv()  # loads .env from the current working directory
except ImportError:
    pass  # dotenv is optional — env vars can still be set manually
 
 
from sec_audit.cli import build_parser, run_from_args
 
 
def main():
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()
 
    try:
        run_from_args(args)
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user (Ctrl+C). Exiting...")
    except EOFError:
        print("\n[INFO] Input stream closed (EOF). Exiting...")
 
 
if __name__ == "__main__":
    main()