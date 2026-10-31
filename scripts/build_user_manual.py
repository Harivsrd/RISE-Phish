"""
Builder for RISE_Phish_User_Manual.docx
Comprehensive User and Operations Manual for RISE-Phish.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from docx.shared import Inches, Pt
from scripts.docx_helpers import (
    create_base_document,
    add_title_page,
    add_heading_1,
    add_heading_2,
    add_heading_3,
    add_paragraph,
    add_bullet,
    add_numbered,
    add_callout,
    add_code_block,
    add_styled_table
)


def build_user_manual(output_path="docs/RISE_Phish_User_Manual.docx"):
    print(f"[*] Building User Manual: {output_path}")
    doc = create_base_document()

    title = "RISE-Phish: System User & Operations Manual"
    subtitle = "Complete Operations Guide for End-Users, Security Analysts, and System Administrators"
    add_title_page(doc, title, subtitle, "SYSTEM USER & OPERATIONS MANUAL", "OPERATIONAL USER GUIDE")

    # 1. INTRODUCTION & OVERVIEW
    add_heading_1(doc, "1. INTRODUCTION AND SYSTEM OVERVIEW")
    add_paragraph(doc,
        "Welcome to RISE-Phish, an advanced, explainable phishing detection platform designed to protect users and "
        "organizations against next-generation credential theft, brand impersonation, and adversarial Unicode homoglyph evasion. "
        "Unlike traditional antivirus or static URL blacklists that only inspect domain strings, RISE-Phish analyzes a webpage across "
        "five simultaneous representations—comparing raw source code, normalized text, and visual optical pixels to identify "
        "deceptive discrepancies.")

    add_paragraph(doc,
        "The RISE-Phish platform consists of three integrated interfaces:")
    add_bullet(doc, "A full-featured security operations dashboard for in-depth forensic investigation, representation diffing, and scan history.", "1. React Web Dashboard: ")
    add_bullet(doc, "A real-time endpoint assistant for Google Chrome and Microsoft Edge that automatically flags dangerous tabs and scans highlighted message text.", "2. Browser Extension: ")
    add_bullet(doc, "A high-performance asynchronous API service coordinating Playwright browser automation, Tesseract OCR, and discrepancy algorithms.", "3. FastAPI Backend: ")

    # 2. SYSTEM REQUIREMENTS
    add_heading_1(doc, "2. SYSTEM REQUIREMENTS AND PREREQUISITES")
    
    add_heading_2(doc, "2.1 Hardware Requirements")
    hw_data = [
        ("Processor (CPU)", "Intel Core i5 / AMD Ryzen 5 (4+ Cores)", "Intel Core i7 / AMD Ryzen 7 (8+ Cores)"),
        ("System Memory (RAM)", "8 GB DDR4", "16 GB DDR4 / DDR5"),
        ("Graphics (GPU)", "Standard Integrated Graphics (CPU fallback)", "NVIDIA GeForce RTX 3050 (4 GB VRAM) or higher"),
        ("Disk Storage", "5 GB free SSD space", "15 GB free NVMe SSD space"),
        ("Network Interface", "Standard broadband connection", "Low-latency broadband connection")
    ]
    add_styled_table(doc, ["Hardware Component", "Minimum Requirement (CPU Mode)", "Recommended (Local GPU Mode)"], hw_data,
                     [Inches(2.2), Inches(2.4), Inches(2.4)])

    add_heading_2(doc, "2.2 Software Prerequisites")
    add_bullet(doc, "Windows 11 / 10 (64-bit), Ubuntu 22.04 LTS, or macOS 13+.", "Operating System: ")
    add_bullet(doc, "Python 3.11 or 3.12 (64-bit) with pip and virtualenv.", "Python Runtime: ")
    add_bullet(doc, "Node.js 18.x or 20.x with npm (for building the web dashboard).", "Node.js Runtime: ")
    add_bullet(doc, "Tesseract-OCR 5.0+ installed and added to the system PATH environment variable.", "OCR Engine: ")
    add_bullet(doc, "Google Chrome or Microsoft Edge (Chromium version 110+).", "Supported Web Browsers: ")

    # 3. INSTALLATION & SETUP GUIDE
    add_heading_1(doc, "3. STEP-BY-STEP INSTALLATION GUIDE")
    
    add_heading_2(doc, "3.1 Native Local Backend Setup")
    add_paragraph(doc, "Follow these steps to set up and start the backend service on your workstation:")
    add_code_block(doc,
"""# 1. Open PowerShell or Terminal and navigate to the project root
cd C:\\path\\to\\RISE-Phish

# 2. Create and activate a Python virtual environment
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1    # On Windows
# source .venv/bin/activate       # On Linux/macOS

# 3. Install required Python packages
pip install -r requirements.txt

# 4. Install Playwright browser binaries
playwright install chromium

# 5. Initialize environment variables
cp .env.example .env

# 6. Launch the FastAPI server with auto-reload
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload""",
        "Backend Setup Commands")

    add_paragraph(doc,
        "Once launched, verify the backend is active by opening http://127.0.0.1:8000/health in your browser. "
        "You should receive a JSON response: {\"status\": \"healthy\", \"version\": \"2.0.0\"}.")

    add_heading_2(doc, "3.2 Web Dashboard Setup")
    add_paragraph(doc, "To launch the React frontend dashboard:")
    add_code_block(doc,
"""# Open a new terminal window
cd frontend

# Install Node dependencies
npm install

# Start the Vite development server
npm run dev""",
        "Frontend Launch Commands")
    add_paragraph(doc, "The dashboard will be accessible at http://localhost:5173.")

    # 4. BROWSER EXTENSION INSTALLATION
    add_heading_1(doc, "4. CHROME & EDGE EXTENSION INSTALLATION")
    add_paragraph(doc,
        "The RISE-Phish browser extension enables real-time protection while browsing the web and inspecting emails.")
    
    add_numbered(doc, "Open Google Chrome or Microsoft Edge and navigate to chrome://extensions or edge://extensions.", None, "Step 1:")
    add_numbered(doc, "Enable Developer Mode using the toggle switch located in the top-right corner of the extensions page.", None, "Step 2:")
    add_numbered(doc, "Click the 'Load unpacked' button located in the top-left toolbar.", None, "Step 3:")
    add_numbered(doc, "In the file picker dialog, navigate to the RISE-Phish repository and select the browser-extension folder.", None, "Step 4:")
    add_numbered(doc, "The RISE-Phish Shield icon will appear in your browser toolbar. Click the puzzle-piece icon and pin RISE-Phish for convenient access.", None, "Step 5:")

    add_callout(doc,
        "Extension Connectivity Check: Click the RISE-Phish extension icon in the toolbar. "
        "A green indicator dot labeled 'Backend Connected' confirms that the extension is successfully communicating with http://127.0.0.1:8000.",
        "CONNECTION VERIFICATION", "TIP")

    # 5. USING THE WEB DASHBOARD
    add_heading_1(doc, "5. OPERATING THE WEB DASHBOARD")
    
    add_heading_2(doc, "5.1 Submitting a URL for Inspection")
    add_paragraph(doc,
        "1. Open http://localhost:5173 in your browser.\n"
        "2. Paste any target URL (e.g., https://example-login-portal.com) into the primary search bar.\n"
        "3. Click 'Analyze Target'. The sandboxed crawler will fetch the DOM, capture a screenshot, run OCR, and compute discrepancy matrices.\n"
        "4. The analysis report displays within 1 to 2 seconds.")

    add_heading_2(doc, "5.2 Interpreting the Threat Meter & Operational Verdict")
    add_paragraph(doc, "The dashboard displays a large color-coded Threat Meter scored from 0 to 100:")
    add_bullet(doc, "Score 0 - 39 (Verdict: SAFE | Posture: ALLOW): No malicious indicators or deceptive discrepancies found. Normal navigation permitted.", "Green Badge: ")
    add_bullet(doc, "Score 40 - 69 (Verdict: INVESTIGATE | Posture: WARN_USER / ISOLATE): Moderate risk detected (e.g., brand name mentioned on unverified domain, minor Unicode anomalies). Caution advised.", "Yellow Badge: ")
    add_bullet(doc, "Score 70 - 100 (Verdict: PHISHING | Posture: BLOCK_ACCESS): Severe threat confirmed (e.g., VNC homoglyph signature detected, credential harvesting form targeting a spoofed brand). Navigation blocked immediately.", "Red Badge: ")

    add_heading_2(doc, "5.3 Multi-Representation Forensic Inspector")
    add_paragraph(doc,
        "For SOC analysts, clicking the 'Forensic Inspector' tab reveals the five simultaneous representations ($R_1-R_5$) "
        "and their pairwise discrepancy distances. In particular, check the $R_1 \\text{ vs } R_2$ and $R_1 \\text{ vs } R_3$ divergence scores: "
        "scores above 0.25 indicate that hidden characters or homoglyphs are present in the HTML that look entirely different on screen.")

    # 6. USING THE BROWSER EXTENSION
    add_heading_1(doc, "6. USING THE BROWSER EXTENSION")
    
    add_heading_2(doc, "6.1 Real-Time In-Page Security Banners")
    add_paragraph(doc,
        "As you navigate the web, RISE-Phish continuously monitors the destination URL. If you land on a webpage flagged as INVESTIGATE or PHISHING, "
        "an interstitial security banner immediately slides down from the top of the browser tab with clear guidance: "
        "'Warning: This page appears to be impersonating PayPal. Do not enter passwords or financial information.'")

    add_heading_2(doc, "6.2 Inspecting Suspicious Emails & Messages")
    add_paragraph(doc,
        "Attackers frequently distribute phishing links via webmail (Gmail, Outlook 365) or chat applications (Slack, Teams, WhatsApp Web). "
        "To scan an email snippet before clicking any embedded links:")
    add_numbered(doc, "Highlight the email body or message text with your mouse.", None, "1.")
    add_numbered(doc, "Right-click the highlighted text to open the browser context menu.", None, "2.")
    add_numbered(doc, "Select 'Scan selected text with RISE-Phish'.", None, "3.")
    add_numbered(doc, "A popup notification will display the message risk score, identifying hidden links, urgency keywords, and spoofed domains.", None, "4.")

    # 7. TROUBLESHOOTING & FAQ
    add_heading_1(doc, "7. TROUBLESHOOTING, ERROR CODES, AND FAQ")
    
    faq_data = [
        ("Tesseract Not Found Error", "Tesseract is not installed or not in PATH.", "Install Tesseract-OCR and add 'C:\\Program Files\\Tesseract-OCR' to your System PATH environment variable. Restart your terminal."),
        ("Playwright Browser Missing", "Playwright chromium binaries have not been downloaded.", "Run 'playwright install chromium' inside your activated Python virtual environment."),
        ("Extension Shows 'Backend Disconnected'", "FastAPI backend is not running on port 8000.", "Ensure uvicorn is running: 'uvicorn backend.app.main:app --port 8000'. Check that no other service is occupying port 8000."),
        ("Analysis Times Out After 15 Seconds", "Target website is slow, blocking bots, or unreachable.", "RISE-Phish enforces a strict 15-second cap to prevent hanging. The system automatically falls back to URL lexical analysis."),
        ("Is my private browsing data sent to the cloud?", "No external cloud transmission.", "All crawling, OCR, Unicode analysis, and SLM reasoning occur entirely on your local workstation. Zero data is transmitted to third-party APIs.")
    ]
    add_styled_table(doc, ["Issue / Symptom", "Underlying Cause", "Resolution Steps"], faq_data, [Inches(2.0), Inches(2.2), Inches(2.8)])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc.save(output_path)
    print(f"[+] Successfully built: {output_path} ({os.path.getsize(output_path)} bytes)")


if __name__ == "__main__":
    build_user_manual()
