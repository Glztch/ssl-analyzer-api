# SSL/TLS Config Analyzer API

Production-ready FastAPI service for analyzing SSL/TLS configurations, certificates, and security vulnerabilities.

## Public URL

**Base URL:** `https://port-spears-checked-warm.trycloudflare.com`

*(Note: This is a temporary tunnel URL. For production, deploy to Render/Railway and update the URL.)*

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Service info |
| GET | `/health` | Health check |
| POST | `/analyze` | Analyze SSL/TLS config |
| GET | `/docs` | Swagger UI |
| GET | `/openapi.json` | OpenAPI spec |

## API Usage

### Analyze a Hostname

```bash
curl -X POST https://port-spears-checked-warm.trycloudflare.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"hostname": "google.com", "port": 443}'
```

### Response

```json
{
  "hostname": "google.com",
  "port": 443,
  "certificate": {
    "subject": {"commonName": "*.google.com"},
    "issuer": {"organizationName": "Google Trust Services"},
    "not_before": "May  7 15:51:36 2026 GMT",
    "not_after": "Jul 30 15:51:35 2026 GMT",
    "san": ["*.google.com", "google.com"],
    "fingerprint_sha256": "...",
    "days_until_expiry": 70,
    "expired": false
  },
  "ssl_version": "TLSv1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "vulnerabilities": [],
  "grade": "A",
  "timestamp": "2026-05-20T20:30:54.637932"
}
```

## Grade Scale

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90+ | Excellent configuration |
| B | 80-89 | Good, minor improvements possible |
| C | 70-79 | Fair, some vulnerabilities |
| D | 60-69 | Poor, multiple issues |
| F | <60 | Critical vulnerabilities |

## Detected Vulnerabilities

- Expired certificates
- Certificates expiring within 30 days
- Self-signed certificates
- Deprecated SSL versions (SSLv2, SSLv3)
- Deprecated TLS versions (TLS 1.0, TLS 1.1)
- Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, MD5)

## Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

## Docker

```bash
docker build -t ssl-analyzer .
docker run -p 8000:8000 ssl-analyzer
```

## Deployment

### Render
1. Push to GitHub
2. Connect repo to Render
3. Select "Web Service"
4. Build command: `docker build -t ssl-analyzer .`
5. Start command: `docker run -p $PORT:8000 ssl-analyzer`

### Railway
```bash
railway login
railway init
railway up
```

## RapidAPI Listing Info

- **Category:** Security / SSL
- **Pricing:** Free: 50/day | Basic: $29/mo (10K) | Pro: $99/mo (100K) | Enterprise: $299/mo
- **OpenAPI Spec:** Available at `/openapi.json`

## License

MIT
