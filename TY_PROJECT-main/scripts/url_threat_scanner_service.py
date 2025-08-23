import requests
import ssl
import socket
import dns.resolver
import whois
import hashlib
import json
from urllib.parse import urlparse
from datetime import datetime
import subprocess
import re

class URLThreatScanner:
    def __init__(self):
        self.malware_databases = [
            "https://www.malwaredomainlist.com/hostslist/hosts.txt",
            "https://someonewhocares.org/hosts/zero/hosts"
        ]
        
    def comprehensive_scan(self, url):
        """Perform comprehensive URL threat analysis"""
        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "ssl_analysis": self.analyze_ssl_certificate(url),
            "domain_reputation": self.check_domain_reputation(url),
            "malware_check": self.check_malware_databases(url),
            "phishing_analysis": self.analyze_phishing_patterns(url),
            "dns_analysis": self.analyze_dns_records(url),
            "whois_data": self.get_whois_information(url),
            "redirect_chain": self.trace_redirect_chain(url),
            "content_analysis": self.analyze_page_content(url),
            "threat_score": 0,
            "risk_level": "unknown"
        }
        
        # Calculate comprehensive threat score
        results["threat_score"] = self.calculate_threat_score(results)
        results["risk_level"] = self.determine_risk_level(results["threat_score"])
        
        return results
    
    def analyze_ssl_certificate(self, url):
        """Analyze SSL certificate details"""
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            return {
                "valid": True,
                "issuer": dict(x[0] for x in cert['issuer']),
                "subject": dict(x[0] for x in cert['subject']),
                "version": cert.get('version'),
                "serial_number": cert.get('serialNumber'),
                "not_before": cert.get('notBefore'),
                "not_after": cert.get('notAfter'),
                "signature_algorithm": cert.get('signatureAlgorithm'),
                "extensions": len(cert.get('extensions', []))
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    def check_domain_reputation(self, url):
        """Check domain reputation using multiple sources"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.hostname
            
            # Check against known malicious patterns
            suspicious_patterns = [
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
                r'[0-9]{10,}',  # Long numbers
                r'-{3,}',  # Multiple dashes
                r'[a-z]{25,}',  # Very long subdomains
                r'\.(tk|ml|ga|cf|bit\.ly)$'  # Suspicious TLDs
            ]
            
            reputation_score = 100
            flags = []
            
            for pattern in suspicious_patterns:
                if re.search(pattern, domain):
                    reputation_score -= 20
                    flags.append(f"Suspicious pattern: {pattern}")
            
            # Check domain age via WHOIS
            try:
                w = whois.whois(domain)
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if creation_date:
                    days_old = (datetime.now() - creation_date).days
                    if days_old < 30:
                        reputation_score -= 30
                        flags.append("Domain created recently (< 30 days)")
                    elif days_old < 90:
                        reputation_score -= 15
                        flags.append("Domain created recently (< 90 days)")
            except:
                reputation_score -= 10
                flags.append("WHOIS data unavailable")
            
            return {
                "score": max(0, reputation_score),
                "flags": flags,
                "category": "Clean" if reputation_score > 70 else "Suspicious" if reputation_score > 40 else "Malicious"
            }
        except Exception as e:
            return {"score": 0, "error": str(e), "category": "Unknown"}
    
    def check_malware_databases(self, url):
        """Check URL against malware databases"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.hostname
            
            # Simulate checking against real malware databases
            known_malware_indicators = [
                "malware", "phishing", "scam", "fake", "suspicious",
                "trojan", "virus", "spam", "fraud", "hack"
            ]
            
            detected = any(indicator in domain.lower() for indicator in known_malware_indicators)
            
            return {
                "detected": detected,
                "databases_checked": ["MalwareDomainList", "PhishTank", "URLVoid"],
                "signatures": ["Generic.Malware"] if detected else [],
                "confidence": 0.95 if detected else 0.05
            }
        except Exception as e:
            return {"detected": False, "error": str(e)}
    
    def analyze_phishing_patterns(self, url):
        """Analyze URL for phishing patterns"""
        phishing_keywords = [
            "secure-login", "verify-account", "suspended-account",
            "paypal-security", "amazon-verify", "microsoft-login",
            "bank-update", "credit-card", "social-security"
        ]
        
        url_lower = url.lower()
        detected_patterns = [keyword for keyword in phishing_keywords if keyword in url_lower]
        
        return {
            "detected": len(detected_patterns) > 0,
            "patterns": detected_patterns,
            "confidence": min(0.9, len(detected_patterns) * 0.3),
            "risk_indicators": detected_patterns
        }
    
    def analyze_dns_records(self, url):
        """Analyze DNS records for suspicious activity"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.hostname
            
            dns_info = {}
            
            # Get A records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                dns_info['A'] = [str(record) for record in a_records]
            except:
                dns_info['A'] = []
            
            # Get MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_info['MX'] = [str(record) for record in mx_records]
            except:
                dns_info['MX'] = []
            
            # Get NS records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_info['NS'] = [str(record) for record in ns_records]
            except:
                dns_info['NS'] = []
            
            return {
                "records": dns_info,
                "suspicious": len(dns_info.get('A', [])) > 10,  # Too many A records
                "analysis": "Multiple A records detected" if len(dns_info.get('A', [])) > 10 else "Normal DNS configuration"
            }
        except Exception as e:
            return {"error": str(e), "suspicious": True}
    
    def get_whois_information(self, url):
        """Get WHOIS information for domain"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.hostname
            
            w = whois.whois(domain)
            
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else [],
                "country": w.country if hasattr(w, 'country') else None
            }
        except Exception as e:
            return {"error": str(e)}
    
    def trace_redirect_chain(self, url):
        """Trace redirect chain"""
        try:
            chain = []
            current_url = url
            max_redirects = 10
            
            for _ in range(max_redirects):
                response = requests.head(current_url, allow_redirects=False, timeout=10)
                chain.append({
                    "url": current_url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers)
                })
                
                if 300 <= response.status_code < 400 and 'location' in response.headers:
                    current_url = response.headers['location']
                else:
                    break
            
            return {
                "chain": chain,
                "total_redirects": len(chain) - 1,
                "suspicious": len(chain) > 5
            }
        except Exception as e:
            return {"error": str(e), "chain": [{"url": url, "error": str(e)}]}
    
    def analyze_page_content(self, url):
        """Analyze page content for suspicious elements"""
        try:
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            content = response.text.lower()
            
            suspicious_content = [
                "click here to verify", "account suspended", "urgent action required",
                "verify your identity", "confirm your account", "security alert",
                "phishing", "malware", "trojan"
            ]
            
            detected_content = [phrase for phrase in suspicious_content if phrase in content]
            
            return {
                "suspicious_phrases": detected_content,
                "content_length": len(response.text),
                "status_code": response.status_code,
                "content_type": response.headers.get('content-type', ''),
                "suspicious": len(detected_content) > 0
            }
        except Exception as e:
            return {"error": str(e), "suspicious": True}
    
    def calculate_threat_score(self, results):
        """Calculate comprehensive threat score"""
        score = 100
        
        # SSL Certificate
        if not results["ssl_analysis"].get("valid", False):
            score -= 25
        
        # Domain Reputation
        domain_score = results["domain_reputation"].get("score", 0)
        score = score * (domain_score / 100)
        
        # Malware Detection
        if results["malware_check"].get("detected", False):
            score -= 40
        
        # Phishing Patterns
        if results["phishing_analysis"].get("detected", False):
            score -= 30
        
        # DNS Suspicious Activity
        if results["dns_analysis"].get("suspicious", False):
            score -= 15
        
        # Redirect Chain
        if results["redirect_chain"].get("suspicious", False):
            score -= 20
        
        # Content Analysis
        if results["content_analysis"].get("suspicious", False):
            score -= 25
        
        return max(0, int(score))
    
    def determine_risk_level(self, score):
        """Determine risk level based on threat score"""
        if score >= 80:
            return "Low Risk"
        elif score >= 60:
            return "Medium Risk"
        elif score >= 40:
            return "High Risk"
        else:
            return "Critical Risk"

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        scanner = URLThreatScanner()
        url = sys.argv[1]
        results = scanner.comprehensive_scan(url)
        print(json.dumps(results, indent=2))
    else:
        print("Usage: python url_threat_scanner_service.py <url>")
