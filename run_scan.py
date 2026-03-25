#!/usr/bin/env python3
"""
LiteLLM Supply Chain Attack Scanner — entry point.

Usage:
    python run_scan.py
    python -m scan_litellm_compromise
"""

from scan_litellm_compromise.scanner import main

if __name__ == "__main__":
    main()
