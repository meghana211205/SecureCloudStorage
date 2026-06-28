# Secure Post-Quantum Cloud Storage Vault

![Python](https://img.shields.io/badge/Python-3.13+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-green.svg)
![Cryptography](https://img.shields.io/badge/Cryptography-AES--256%20%7C%20RSA--2048%20%7C%20ML--KEM-red.svg)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey.svg)

A highly secure, hybrid-cryptography cloud storage application built for an academic B.Tech Cybersecurity project. This platform allows users to securely upload, encrypt, and store files using an advanced Key Encapsulation mechanism that successfully pivots between Classical Cryptography (RSA) and Post-Quantum Cryptography (NIST FIPS-203 ML-KEM).

---

## 🔒 Security Architecture

This architecture fundamentally defeats future Shor's Algorithm attacks while maintaining extreme speeds.

1. **Payload Encryption (AES-256-GCM):** The actual user files are heavily encrypted in-memory using military-grade symmetric AES cryptography before they ever touch the hard drive. 
2. **Key Encapsulation (ML-KEM / RSA):** 
   - **Post-Quantum:** Utilizes the pure-Python `mlkem` implementation of CRYSTALS-Kyber (ML-KEM-768) to dynamically output the AES key and simultaneously wrap it inside an unbreakable multi-dimensional Lattice ciphertext.
   - **Classical Fallback:** Retains backwards compatibility with RSA-2048 OAEP Key Wrapping.
3. **Data Integrity:** Strict SHA-256 cryptographic hashing verifies file authenticity immediately upon download to prevent tampering.

## 🚀 Features

- **Hybrid Crypto Dashboard:** Users explicitly select between Post-Quantum ML-KEM or Classical RSA-2048 routing natively within the web dashboard.
- **Zero Raw Storage:** Original files are never saved to the disk. Only AES-encrypted blobs are stored in the server's `storage/` registry.
- **Automated Benchmarking:** Includes independent stress-testing script modules to measure latency deltas between RSA and ML-KEM mathematical pipelines.

## 📁 Project Structure

```text
cyproj/
├── app.py                      # Main Flask Backend Server
├── config.py                   # Global System Configuration
├── models/                     # SQLite Database Schema Definitions
│   └── models.py               # Houses User and File Tables (Algorithms and Keys)
├── crypto/                     # Core Cryptographic Machinery
│   ├── aes_util.py             # AES-256 GCM Logic
│   ├── rsa_util.py             # Classical RSA-2048 Logic
│   ├── kem_util.py             # Post-Quantum ML-KEM Logic
│   └── hash_util.py            # SHA-256 Integration
├── templates/                  # Frontend HTML Dashboard UI
├── benchmark_rsa.py            # Automated RSA Speed Tester
└── benchmark_mlkem.py          # Automated ML-KEM Speed Tester
```

## ⚙️ Installation & Usage

### 1. Requirements Setup
Ensure Python is installed on your machine. Initialize your virtual environment and install the required PIP modules:

```bash
# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install the exact dependencies
pip install Flask Flask-SQLAlchemy pycryptodomex mlkem
```

### 2. Booting the Server
If you change the Database schema, make sure to delete `cloud_storage.db` so the system can reconstruct it. Then, start the primary Flask node:

```bash
python app.py
```

### 3. Usage
Navigate to `http://127.0.0.1:5000` in your web browser. Register a new user, and start securely encapsulating your uploads into the `storage/` vault natively from the dashboard!

---
*Developed as an Academic Concept Proof for "Zero-Knowledge" scale paths regarding Key Distribution and Post-Quantum integrations.*
