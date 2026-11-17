@echo off
title CyberTrace - Digital Forensics and Cyber Incident Investigation Platform
color 0b
echo ===============================================================================
echo                CYBERTRACE DIGITAL FORENSICS PLATFORM
echo     ISO/IEC 27037 Compliant - Digital Evidence Collection & Incident Analysis
echo ===============================================================================
echo.
echo [*] Initializing SQLite Forensics Database...
echo [*] Launching CyberTrace Native API Server on http://127.0.0.1:8000 ...
echo [*] Serving Interactive Forensics Workbench at http://127.0.0.1:8000/
echo.
echo [!] Press CTRL+C at any time to shut down the forensics server.
echo.

start "" "http://127.0.0.1:8000/"
python backend\app\standalone_server.py 8000

pause

