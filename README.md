# VerifyIt V1.2 — Pilot

VerifyIt is a prototype product-record verification platform for brands.

## Core flow
1. Business creates an account.
2. Business registers a product.
3. VerifyIt creates a unique verification code.
4. Business generates a QR code for that product.
5. Customer scans the QR or enters the code.
6. VerifyIt checks whether the code matches an active registered product record.

## Important positioning
A positive result means the submitted code matches a registered record. VerifyIt does not independently inspect the physical item and should not be marketed as an absolute guarantee of authenticity.

## Run locally
```bash
npm install
JWT_SECRET="replace-with-a-long-random-secret" npm start
```

Optional:
- `PORT`
- `DB_PATH`
- `PUBLIC_BASE_URL`

## Production notes
The current prototype uses SQLite. For production, move to a persistent managed database or persistent volume, add rate limiting/anti-automation, stronger account verification and authorization, backups, monitoring, HTTPS, privacy/terms, and a proper business onboarding process.

## Standards direction
The product identity model can later be extended toward GS1 identifiers and GS1 Digital Link. GS1 describes Digital Link as a standardized way to connect product identifiers to online information and supports data such as GTIN, batch/lot and serial numbers.
