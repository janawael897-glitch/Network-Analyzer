#!/usr/bin/env python3
"""
Run this from your project root to check what routes your web_dashboard has:
    python check_routes.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'code'))

from web_dashboard import app

print("\nRoutes registered in your web_dashboard.py:")
for rule in app.url_map.iter_rules():
    print(f"  {rule.rule} -> {rule.endpoint}")

print("\nIf you see '/' pointing to 'home' and '/dashboard' pointing to 'dashboard', your file is correct.")
print("If '/' points to 'dashboard' or 'index', that's the old version — replace the file.\n")
