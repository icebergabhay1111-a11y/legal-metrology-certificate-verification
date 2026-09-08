# ⚖️ Legal Metrology Certificate Verification System

A web-based certificate generation and verification system designed to simplify the verification of Legal Metrology certificates using **QR-based digital verification**.

## 🚀 Overview

The Legal Metrology Certificate Verification System provides a simple digital workflow for generating certificates and verifying their authenticity.

Instead of relying only on physical certificates, each generated certificate is assigned a **unique Certificate ID** and a **QR code**. Scanning the QR code opens a verification page where the certificate details and validity status can be checked.

The system is designed as a working prototype for demonstrating how certificate verification can be made faster, easier and more accessible.

---

## ✨ Key Features

- 📄 Generate digital Legal Metrology certificates
- 🔢 Automatically generate unique Certificate IDs
- 🧾 Store certificate information in a database
- 📅 Record verification and expiry dates
- 🔳 Automatically generate QR codes
- 📱 Scan QR codes using a smartphone
- 🔍 Verify certificates through a dedicated verification page
- ✅ Display certificate validity status
- ❌ Identify expired or unavailable certificates
- 🌐 Web-based interface accessible through a browser
- 🗄️ SQLite database for certificate records

---

## 🔄 System Workflow

```text
User enters certificate details
          ↓
     Submit Form
          ↓
Certificate stored in Database
          ↓
 Unique Certificate ID generated
          ↓
    Certificate generated
          ↓
       QR Code
          ↓
   Scan QR Code
          ↓
 Verification URL opened
          ↓
 Certificate details retrieved
          ↓
 VALID / EXPIRED / NOT FOUND
