"""Interactive demo targets for live viva presentations and testing.

Provides realistic simulation targets (Zero-Day Math symbols, Cyrillic Homoglyphs,
Credential Harvesting, and Authentic Portals) served directly by the backend
so users and examiners can test real live crawls without depending on volatile external domains.
"""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/demo", tags=["Demo Simulation Targets"])

MATH_SPOOF_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Sign in to 𝐌𝐢𝐜𝐫𝐨𝐬𝐨𝐟𝐭 Online Services</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #eef2f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .card { background: #ffffff; padding: 44px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.08); width: 380px; }
    h1 { font-size: 24px; color: #1e293b; margin-bottom: 8px; font-weight: 700; }
    p { font-size: 14px; color: #64748b; margin-bottom: 24px; line-height: 1.5; }
    .input-group { margin-bottom: 16px; }
    label { display: block; font-size: 12px; font-weight: 600; color: #475569; margin-bottom: 6px; text-transform: uppercase; }
    input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 12px 14px; border: 1.5px solid #cbd5e1; border-radius: 6px; font-size: 14px; outline: none; }
    input:focus { border-color: #2563eb; }
    button { width: 100%; padding: 12px; background: #0067b8; color: white; border: none; border-radius: 6px; font-size: 15px; font-weight: 600; cursor: pointer; margin-top: 8px; }
    button:hover { background: #005da6; }
    .footer { margin-top: 24px; text-align: center; font-size: 11px; color: #94a3b8; }
  </style>
</head>
<body>
  <div class="card">
    <!-- Notice: Mathematical Alphanumeric bold Unicode symbols bypass raw text filters -->
    <h1>Sign in to 𝐌𝐢𝐜𝐫𝐨𝐬𝐨𝐟𝐭</h1>
    <p>Your cloud session requires verification. Sign in to your 𝐌𝐢𝐜𝐫𝐨𝐬𝐨𝐟𝐭 account to prevent suspension.</p>
    <form action="http://127.0.0.1:8000/demo/harvest" method="POST">
      <div class="input-group">
        <label>Account Identity</label>
        <input type="text" name="login_identity" placeholder="Email, phone, or Skype" required />
      </div>
      <div class="input-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter your domain password" required />
      </div>
      <button type="submit">Next</button>
    </form>
    <div class="footer">Protected by 𝐌𝐢𝐜𝐫𝐨𝐬𝐨𝐟𝐭 Enterprise Security</div>
  </div>
</body>
</html>
"""

CYRILLIC_SPOOF_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Log in to your PаyPаl Account</title>
  <style>
    body { font-family: Helvetica, Arial, sans-serif; background: #f5f7fa; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .box { background: white; border: 1px solid #e1e7ec; border-radius: 8px; padding: 40px; width: 400px; box-shadow: 0 4px 14px rgba(0,0,0,0.06); text-align: center; }
    h2 { color: #003087; margin-bottom: 20px; font-size: 26px; }
    .tagline { color: #555; font-size: 14px; margin-bottom: 24px; }
    input { width: 100%; box-sizing: border-box; padding: 13px; margin-bottom: 14px; border: 1px solid #ccc; border-radius: 4px; font-size: 14px; }
    .btn { width: 100%; background: #0070ba; color: white; padding: 13px; border: none; border-radius: 20px; font-weight: bold; font-size: 15px; cursor: pointer; }
    .btn:hover { background: #005ea6; }
    .card-row { display: flex; gap: 8px; }
  </style>
</head>
<body>
  <div class="box">
    <!-- Notice: Mixed-script Cyrillic 'а' (U+0430) disguised inside PayPal -->
    <h2>Log in to PаyPаl</h2>
    <p class="tagline">Confirm your billing details to resolve an unusual activity hold.</p>
    <form action="http://127.0.0.1:8000/demo/harvest" method="POST">
      <input type="text" name="email" placeholder="Email or mobile number" required />
      <input type="password" name="password" placeholder="Password" required />
      <input type="text" name="card_number" placeholder="Debit or Credit Card Number" required />
      <div class="card-row">
        <input type="text" name="exp_date" placeholder="MM/YY" style="width: 50%;" />
        <input type="password" name="cvv" placeholder="CVV" style="width: 50%;" />
      </div>
      <button type="submit" class="btn">Log In</button>
    </form>
  </div>
</body>
</html>
"""

CREDENTIAL_HARVEST_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Google Workspace - Re-authenticate Session</title>
  <style>
    body { font-family: Roboto, Arial, sans-serif; background: #ffffff; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .wrapper { border: 1px solid #dadce0; border-radius: 8px; padding: 40px; width: 380px; text-align: center; }
    h1 { font-size: 22px; font-weight: 500; color: #202124; margin: 16px 0 8px; }
    p { font-size: 14px; color: #5f6368; margin-bottom: 28px; }
    input { width: 100%; box-sizing: border-box; padding: 14px; margin-bottom: 16px; border: 1px solid #dadce0; border-radius: 4px; font-size: 15px; }
    button { background: #1a73e8; color: white; padding: 12px 24px; border: none; border-radius: 4px; font-weight: 500; cursor: pointer; float: right; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div style="font-size: 28px; font-weight: bold; color: #4285F4;">Google</div>
    <h1>Verify Account Access</h1>
    <p>Suspicious sign-in blocked. Confirm your password to proceed.</p>
    <form action="http://127.0.0.1:8000/demo/harvest" method="POST">
      <input type="text" name="identifier" placeholder="Email or phone" required />
      <input type="password" name="password" placeholder="Enter your password" required />
      <button type="submit">Verify</button>
    </form>
  </div>
</body>
</html>
"""

BENIGN_PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Global Open Knowledge Repository</title>
  <style>
    body { font-family: Georgia, serif; line-height: 1.6; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #333; }
    h1 { color: #111; border-bottom: 1px solid #ccc; padding-bottom: 10px; }
    nav a { margin-right: 15px; color: #0066cc; text-decoration: none; }
    .content { margin-top: 30px; }
  </style>
</head>
<body>
  <h1>Global Open Knowledge Repository</h1>
  <nav>
    <a href="#about">About</a>
    <a href="#articles">Articles</a>
    <a href="#contact">Contact</a>
  </nav>
  <div class="content">
    <p>Welcome to the public knowledge repository. This service provides free and open access to academic research, historical documents, and educational curricula.</p>
    <p>No account registration or personal credentials are required to read our archives.</p>
  </div>
</body>
</html>
"""


@router.get("/zero-day-math", response_class=HTMLResponse)
async def get_demo_zero_day_math():
    """Serves a live phishing page employing Mathematical Alphanumeric Unicode deception."""
    return HTMLResponse(content=MATH_SPOOF_HTML)


@router.get("/cyrillic-homoglyph", response_class=HTMLResponse)
async def get_demo_cyrillic_homoglyph():
    """Serves a live phishing page employing Cyrillic homoglyph spoofing."""
    return HTMLResponse(content=CYRILLIC_SPOOF_HTML)


@router.get("/credential-harvest", response_class=HTMLResponse)
async def get_demo_credential_harvest():
    """Serves a credential harvesting login portal mimicking Google Workspace."""
    return HTMLResponse(content=CREDENTIAL_HARVEST_HTML)


@router.get("/authentic-portal", response_class=HTMLResponse)
async def get_demo_authentic_portal():
    """Serves an authentic public documentation portal (benign baseline control)."""
    return HTMLResponse(content=BENIGN_PORTAL_HTML)


@router.post("/harvest")
async def dummy_harvest():
    """Dummy sink endpoint for form actions."""
    return {"status": "received"}
