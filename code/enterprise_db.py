"""
Fix script for baseline_learning.py and auto_response.py
Run from your project root: python fix_enterprise_db.py
"""
import os, re

BASE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.join(BASE, "code")

<<<<<<< HEAD
# ─────────────────────────────────────────────────────────────
=======
# -------------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
bl_path = os.path.join(CODE, "baseline_learning.py")
if os.path.exists(bl_path):
    with open(bl_path, "r", encoding="utf-8") as f:
        bl = f.read()

    original_bl = bl

    # Fix 1a: INSERT → INSERT OR REPLACE for baseline_profiles
    bl = re.sub(
        r'\bINSERT\s+INTO\s+baseline_profiles\b',
        'INSERT OR REPLACE INTO baseline_profiles',
        bl
    )

    # Fix 1b: Also add WAL + timeout to any sqlite3.connect() calls in baseline_learning
    bl = re.sub(
        r'sqlite3\.connect\(([^,)]+)\)',
        r'sqlite3.connect(\1, timeout=10)',
        bl
    )
    # Add WAL pragma after connect if not already there
    bl = re.sub(
        r'(conn\s*=\s*sqlite3\.connect\([^)]+\))\s*\n(\s*)(conn\.row_factory)',
        r'\1\n\2conn.execute("PRAGMA journal_mode=WAL")\n\2conn.execute("PRAGMA busy_timeout=10000")\n\2\3',
        bl
    )

    if bl != original_bl:
        # Backup original
        with open(bl_path + ".bak", "w", encoding="utf-8") as f:
            f.write(original_bl)
        with open(bl_path, "w", encoding="utf-8") as f:
            f.write(bl)
        print(f"[OK] baseline_learning.py fixed (backup saved as .bak)")
    else:
        print(f"[WARN] baseline_learning.py - pattern not found, trying manual fix...")
        # Manual fallback: find the _persist_profile function and fix it
        if "INSERT INTO baseline_profiles" in bl:
            bl = bl.replace(
                "INSERT INTO baseline_profiles",
                "INSERT OR REPLACE INTO baseline_profiles"
            )
            with open(bl_path + ".bak", "w", encoding="utf-8") as f:
                f.write(original_bl)
            with open(bl_path, "w", encoding="utf-8") as f:
                f.write(bl)
            print(f"[OK] baseline_learning.py fixed with manual replace")
        else:
            print(f"[SKIP] 'INSERT INTO baseline_profiles' not found in baseline_learning.py")
else:
    print(f"[SKIP] baseline_learning.py not found at {bl_path}")


<<<<<<< HEAD
# ─────────────────────────────────────────────────────────────
=======
# -------------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)

ar_path = os.path.join(CODE, "auto_response.py")
if os.path.exists(ar_path):
    with open(ar_path, "r", encoding="utf-8") as f:
        ar = f.read()

    original_ar = ar

    # Add timeout to sqlite3.connect calls that don't have it
    ar = re.sub(
        r'sqlite3\.connect\(([^,)]+)\)(?!\s*,\s*timeout)',
        r'sqlite3.connect(\1, timeout=10)',
        ar
    )

    if ar != original_ar:
        with open(ar_path + ".bak", "w", encoding="utf-8") as f:
            f.write(original_ar)
        with open(ar_path, "w", encoding="utf-8") as f:
            f.write(ar)
        print(f"[OK] auto_response.py fixed (backup saved as .bak)")
    else:
        print(f"[INFO] auto_response.py already has timeout or pattern not matched")
else:
    print(f"[SKIP] auto_response.py not found at {ar_path}")


<<<<<<< HEAD
# ─────────────────────────────────────────────────────────────
# FIX 3: db_manager.py - enable WAL mode globally on startup
# ─────────────────────────────────────────────────────────────
=======
# -------------------------------------------------------------
# FIX 3: db_manager.py - enable WAL mode globally on startup
# -------------------------------------------------------------
>>>>>>> 943b830 (Added AI IDS modules and ML pipeline)
db_path = os.path.join(CODE, "db_manager.py")
if os.path.exists(db_path):
    with open(db_path, "r", encoding="utf-8") as f:
        db = f.read()

    original_db = db

    # Add WAL pragma to any get_db / get_connection function
    db = re.sub(
        r'sqlite3\.connect\(([^,)]+)\)(?!\s*,\s*timeout)',
        r'sqlite3.connect(\1, timeout=10)',
        db
    )

    if db != original_db:
        with open(db_path + ".bak", "w", encoding="utf-8") as f:
            f.write(original_db)
        with open(db_path, "w", encoding="utf-8") as f:
            f.write(db)
        print(f"[OK] db_manager.py fixed")
    else:
        print(f"[INFO] db_manager.py - no changes needed")
else:
    print(f"[SKIP] db_manager.py not found at {db_path}")


print("\nDone! Now restart Flask: python start.py")
print("Login should be instant and DB errors should stop.")
