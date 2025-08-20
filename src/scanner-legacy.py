#!/usr/bin/env python3
"""
AI Threat Scanner v0.1.1 - Backward Compatibility Wrapper
By Qu4ntik - Breaking AI to build better defenses
GitHub: https://github.com/Qu4ntikxyz/ai-threat-scanner

DEPRECATED: This file is maintained for backward compatibility.
Please use the new modular package: from ai_threat_scanner import AIThreatScanner
"""

import warnings

# Import everything from the new modular package
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from scanner import AIThreatScanner
from models import ThreatResult, CONTEXT_USER_INPUT, CONTEXT_LLM_RESPONSE, CONTEXT_UNKNOWN
from reporting import ReportGenerator, generate_report
from patterns import get_threat_patterns
from cli import main

# Show deprecation warning
warnings.warn(
    "Using src/scanner-legacy.py is deprecated. Please use the new modular imports from src/ instead.",
    DeprecationWarning,
    stacklevel=2
)

if __name__ == "__main__":
    main()
