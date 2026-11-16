# Two-Factor Authentication (TOTP) Login System
**Project Code:** CSL-G50  
**Student:** Aayush Sankhla (23ESKCY001)  
**Course:** Cyber Security Lab (7CS4-22)  
**Institute:** SKIT, Jaipur | Session 2026-27

## Description
A web-based login system that implements:
- Secure password storage using strong hashing (Werkzeug / PBKDF2)
- Time-based One-Time Password (TOTP) second factor – fully compatible with Google Authenticator, Authy, Microsoft Authenticator, etc.
- One-time backup / recovery codes (stored as SHA-256 hashes)
- Linked to RTU Cyber Security Lab Experiment 8 (Secure Storage, Transmission & Digital Signature)

## Features
1. User Registration & Login
2. Password hashing (never store plaintext)
3. Enable / Disable TOTP 2FA with QR code provisioning
4. Login flow: Password → TOTP (or Backup Code)
5. Backup code generation & one-time consumption
6. Session management

## How to Run
```bash
pip install -r requirements.txt
python app.py
```
Then open http://127.0.0.1:5000

**Demo credentials:** username `demo` / password `demo123`

## Tech Stack
- Python 3
- Flask
- pyotp (RFC 6238 TOTP)
- qrcode + Pillow
- Werkzeug security helpers

## Ethical Note
This project is for educational purposes only. All testing must be performed on systems you own or control.
