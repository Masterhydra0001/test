#!/usr/bin/env python3
"""
URL Security Scanner Microservice
Provides comprehensive URL security analysis using multiple detection methods.
"""

import requests
import ssl
import socket
import urllib.parse
from datetime import datetime
import json
import hashlib
import re
from typing import Dict, List, Any

class URLSecurityScanner:
    def __init__(self):
        self.malicious_patterns = [
            r'bit\.ly/[a-zA-Z0-9]+',  # Suspicious short URLs
            r'tinyurl\.com/[a-zA-Z0-9]+',
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.tk',  # Suspicious TLD patterns
        ]
        
        self.safe_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'github.com',
            'stackoverflow.com', 'wikipedia.org', 'mozilla.org'
        ]

    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive URL security scan
        """
        try:
            parsed_url = urllib.parse.urlparse(url)
            
            # Basic security checks
            security_score = 100
            threats = []
            warnings = []
            
            # Check protocol
            if parsed_url.scheme != 'https':
                security_score -= 30
                threats.append("Insecure HTTP connection")
            
            # Check for suspicious patterns
            for pattern in self.malicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    security_score -= 40
                    threats.append(f"Suspicious URL pattern detected: {pattern}")
            
            # Check domain reputation
            domain = parsed_url.netloc.lower()
            if any(safe_domain in domain for safe_domain in self.safe_domains):
                security_score += 10
                warnings.append("Domain appears in safe list")
            
            # SSL Certificate check
            if parsed_url.scheme == 'https':
                try:
                    ssl_info = self._check_ssl_certificate(domain, 443)
                    if ssl_info['valid']:
                        security_score += 10
                    else:
                        security_score -= 50
                        threats.append("Invalid or expired SSL certificate")
                except Exception as e:
                    security_score -= 20
                    warnings.append("Could not verify SSL certificate")
            
            # Determine threat level
            if security_score >= 80:
                threat_level = "safe"
            elif security_score >= 60:
                threat_level = "warning"
            else:
                threat_level = "dangerous"
            
            return {
                "url": url,
                "threat_level": threat_level,
                "security_score": max(0, security_score),
                "threats": threats,
                "warnings": warnings,
                "scan_timestamp": datetime.now().isoformat(),
                "details": {
                    "domain": domain,
                    "protocol": parsed_url.scheme,
                    "has_ssl": parsed_url.scheme == 'https'
                }
            }
            
        except Exception as e:
            return {
                "url": url,
                "threat_level": "error",
                "security_score": 0,
                "threats": [f"Scan error: {str(e)}"],
                "warnings": [],
                "scan_timestamp": datetime.now().isoformat(),
                "details": {}
            }

    def _check_ssl_certificate(self, hostname: str, port: int) -> Dict[str, Any]:
        """
        Check SSL certificate validity
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    is_valid = not_after > datetime.now()
                    
                    return {
                        "valid": is_valid,
                        "expires": not_after.isoformat(),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "subject": dict(x[0] for x in cert['subject'])
                    }
        except Exception as e:
            return {"valid": False, "error": str(e)}

# Example usage
if __name__ == "__main__":
    scanner = URLSecurityScanner()
    
    # Test URLs
    test_urls = [
        "https://google.com",
        "http://suspicious-site.tk",
        "https://github.com/user/repo"
    ]
    
    for url in test_urls:
        result = scanner.scan_url(url)
        print(f"URL: {url}")
        print(f"Threat Level: {result['threat_level']}")
        print(f"Security Score: {result['security_score']}")
        print(f"Threats: {result['threats']}")
        print("-" * 50)
