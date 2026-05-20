from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import ssl
import socket
import datetime
from urllib.parse import urlparse
import hashlib

app = FastAPI(
    title="SSL/TLS Config Analyzer",
    description="Analyze SSL/TLS configuration, certificate details, and security vulnerabilities for any hostname.",
    version="1.0.0"
)

class AnalyzeRequest(BaseModel):
    hostname: str
    port: int = 443

class AnalyzeResponse(BaseModel):
    hostname: str
    port: int
    certificate: dict
    ssl_version: str
    cipher_suite: str
    vulnerabilities: list
    grade: str
    timestamp: str

@app.get("/")
def root():
    return {
        "service": "SSL/TLS Config Analyzer",
        "version": "1.0.0",
        "endpoints": {
            "analyze": "POST /analyze — Analyze a hostname's SSL/TLS config",
            "health": "GET /health — Check service status"
        },
        "docs": "/docs"
    }

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.datetime.utcnow().isoformat()}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_ssl(request: AnalyzeRequest):
    hostname = request.hostname.replace("https://", "").replace("http://", "").split("/")[0]
    port = request.port

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_binary = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                ssl_version = ssock.version()
                
                # Certificate details
                cert_info = {
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {},
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {},
                    "serial_number": str(cert.get("serial_number")) if cert.get("serial_number") else None,
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [x[1] for x in cert.get("subjectAltName", [])] if cert.get("subjectAltName") else [],
                    "fingerprint_sha256": hashlib.sha256(cert_binary).hexdigest() if cert_binary else None
                }

                # Check expiry
                not_after_str = cert.get("notAfter", "")
                days_until_expiry = None
                expired = False
                if not_after_str:
                    try:
                        not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_until_expiry = (not_after - datetime.datetime.utcnow()).days
                        expired = days_until_expiry < 0
                    except:
                        pass

                cert_info["days_until_expiry"] = days_until_expiry
                cert_info["expired"] = expired

                # Vulnerability checks
                vulnerabilities = []
                
                # SSL Version checks
                if ssl_version in ["SSLv2", "SSLv3"]:
                    vulnerabilities.append({
                        "name": "Deprecated SSL Version",
                        "severity": "critical",
                        "description": f"Server supports {ssl_version} which is cryptographically broken"
                    })
                elif ssl_version == "TLSv1":
                    vulnerabilities.append({
                        "name": "TLS 1.0 Supported",
                        "severity": "high",
                        "description": "TLS 1.0 is deprecated and has known vulnerabilities (BEAST)"
                    })
                elif ssl_version == "TLSv1.1":
                    vulnerabilities.append({
                        "name": "TLS 1.1 Supported",
                        "severity": "medium",
                        "description": "TLS 1.1 is deprecated. TLS 1.2+ recommended"
                    })

                # Weak cipher checks
                cipher_name = cipher[0] if cipher else ""
                weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
                if any(w in cipher_name for w in weak_ciphers):
                    vulnerabilities.append({
                        "name": "Weak Cipher Suite",
                        "severity": "high",
                        "description": f"Cipher {cipher_name} uses weak cryptography"
                    })

                # Expiry check
                if expired:
                    vulnerabilities.append({
                        "name": "Expired Certificate",
                        "severity": "critical",
                        "description": "SSL certificate has expired"
                    })
                elif days_until_expiry is not None and days_until_expiry < 30:
                    vulnerabilities.append({
                        "name": "Certificate Expiring Soon",
                        "severity": "medium",
                        "description": f"Certificate expires in {days_until_expiry} days"
                    })

                # Self-signed check
                subject = cert_info.get("subject", {})
                issuer = cert_info.get("issuer", {})
                if subject == issuer:
                    vulnerabilities.append({
                        "name": "Self-Signed Certificate",
                        "severity": "high",
                        "description": "Certificate is self-signed and not trusted by default"
                    })

                # Grade calculation
                grade = calculate_grade(ssl_version, vulnerabilities, days_until_expiry)

                return {
                    "hostname": hostname,
                    "port": port,
                    "certificate": cert_info,
                    "ssl_version": ssl_version,
                    "cipher_suite": cipher_name,
                    "vulnerabilities": vulnerabilities,
                    "grade": grade,
                    "timestamp": datetime.datetime.utcnow().isoformat()
                }

    except socket.timeout:
        raise HTTPException(status_code=408, detail="Connection timed out")
    except socket.gaierror:
        raise HTTPException(status_code=404, detail="Hostname not found")
    except ssl.SSLError as e:
        raise HTTPException(status_code=400, detail=f"SSL Error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

def calculate_grade(ssl_version, vulnerabilities, days_until_expiry):
    score = 100
    
    for vuln in vulnerabilities:
        if vuln["severity"] == "critical":
            score -= 30
        elif vuln["severity"] == "high":
            score -= 20
        elif vuln["severity"] == "medium":
            score -= 10
        elif vuln["severity"] == "low":
            score -= 5

    if ssl_version == "TLSv1.2":
        score -= 5
    elif ssl_version == "TLSv1.3":
        score += 5

    if days_until_expiry is not None and days_until_expiry < 7:
        score -= 15

    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
