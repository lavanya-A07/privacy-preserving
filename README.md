# Privacy-Preserving Customer Data Platform

## FLYYY.AI Student Engineering Challenge

A privacy-focused customer data platform designed to discover, classify, protect, and securely manage sensitive customer information while supporting controlled access and auditability.

## Project Overview

The system follows a **"Protected by Default • Reveal by Exception"** approach for handling Personally Identifiable Information (PII).

It provides mechanisms for identifying sensitive customer data, protecting it using encryption and tokenization, controlling data access, and maintaining audit records.

## Key Features

- PII Discovery and Classification
- Format-Preserving Encryption (FPE)
- Tokenization
- Protected Customer Data Storage
- Privacy Gateway
- Controlled Data Reveal
- Email and Bounce Handling
- Batch Processing
- Audit Logging

## Project Structure

```text
privacy-preserving/
│
├── backend/
│   ├── app.py
│   ├── audit.py
│   ├── audit_service.py
│   ├── batch_service.py
│   ├── config.py
│   ├── customers.py
│   ├── database.py
│   ├── discovery.py
│   ├── email_service.py
│   ├── fpe_service.py
│   ├── gateway.py
│   ├── gateway_service.py
│   ├── models.py
│   ├── protection.py
│   ├── protection_service.py
│   ├── security.py
│   ├── token_service.py
│   ├── vault.py
│   ├── vault_service.py
│   └── requirements.txt
│
├── data/
│   └── customers.csv
│
├── frontend/
│   └── index.html
│
├── routes/
│   ├── audit.py
│   ├── batches.py
│   ├── customers.py
│   ├── discovery.py
│   ├── marketing.py
│   ├── policies.py
│   └── reveal.py
│
├── services/
│   └── pii_service.py
│
└── README.md
