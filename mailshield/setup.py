"""
MailShield Pro - Setup Script
Build executable: python setup.py build
"""
import sys
import os

# Check if cx_Freeze is available, otherwise use PyInstaller approach
try:
    from cx_Freeze import setup, Executable

    build_exe_options = {
        "packages": ["msal", "websockets", "asyncio", "sqlite3", "email",
                      "imaplib", "smtplib", "ssl", "json", "hashlib",
                      "threading", "mimetypes", "unicodedata", "secrets", "logging"],
        "include_files": [
            ("mailshield_dashboard.html", "mailshield_dashboard.html"),
            ("mailshield_settings.json", "mailshield_settings.json"),
        ],
        "excludes": ["tkinter", "unittest", "test", "numpy", "scipy",
                     "matplotlib", "pandas", "PIL", "cv2"],
        "optimize": 2,
    }

    setup(
        name="MailShield Pro",
        version="2.0.0",
        description="Client Email Securise avec Filtrage Intelligent",
        author="NetGuard AI",
        options={"build_exe": build_exe_options},
        executables=[
            Executable(
                "mailshield.py",
                base="Console",
                target_name="MailShieldPro.exe",
                icon=None,  # Add icon path here if available
            )
        ],
    )

except ImportError:
    print("""
    ============================================
    cx_Freeze non installe.

    Options pour creer un executable :

    Option 1 - cx_Freeze :
        pip install cx_Freeze
        python setup.py build

    Option 2 - PyInstaller :
        pip install pyinstaller
        pyinstaller --onefile --name MailShieldPro --add-data "mailshield_dashboard.html;." --add-data "mailshield_settings.json;." mailshield.py

    Option 3 - Nuitka (meilleure performance) :
        pip install nuitka
        nuitka --standalone --onefile --output-filename=MailShieldPro.exe mailshield.py
    ============================================
    """)
