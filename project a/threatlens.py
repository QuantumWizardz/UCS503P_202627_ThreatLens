
# threatlens.py
#
# The main CLI entry point for ThreatLens.
# Usage:
#   python threatlens.py ./path-to-repository

import argparse
import sys
import os
import io

# Fix unicode encoding for Windows terminals
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from engine.security_engine import SecurityEngine
from scanners.gitleaks_scanner import GitleaksScanner
from scanners.osv_scanner import OsvScanner
from scanners.semgrep_scanner import SemgrepScanner
from reporting.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="ThreatLens - AI-Powered Code Security Platform")
    parser.add_argument(
        "repo_path", 
        nargs="?", 
        default=".", 
        help="Path to the repository to scan (default: current directory)"
    )
    
    args = parser.parse_args()
    repo_path = os.path.abspath(args.repo_path)
    
    if not os.path.isdir(repo_path):
        print(f" Error: Directory not found: {repo_path}")
        sys.exit(1)
        
    print(f" Starting ThreatLens scan on: {repo_path}")
    print(" Running scanners (Gitleaks, OSV-Scanner, Semgrep)... Please wait.")
    
    # 1. Initialize Engine
    engine = (
        SecurityEngine(repo_path=repo_path)
        .add_scanner("Gitleaks", GitleaksScanner())
        .add_scanner("OSV-Scanner", OsvScanner())
        .add_scanner("Semgrep", SemgrepScanner())
    )
    
    # 2. Run Scan
    report = engine.scan()
    
    # 3. Generate and Print Report
    reporter = ReportGenerator()
    text_report = reporter.generate_text_report(report)
    
    # Print the final beautifully formatted report
    print("\n" + text_report)

if __name__ == "__main__":
    main()
