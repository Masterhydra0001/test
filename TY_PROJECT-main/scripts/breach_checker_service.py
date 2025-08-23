#!/usr/bin/env python3
"""
Data Breach Checker Microservice
Checks email addresses against known data breach databases.
"""

import requests
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

class BreachChecker:
    def __init__(self):
        # In a real implementation, you would use actual breach APIs
        # like HaveIBeenPwned, but here we'll simulate the functionality
        self.mock_breaches = {
            "test@example.com": [
                {
                    "name": "DataCorp Breach 2023",
                    "date": "2023-08-15",
                    "data_types": ["Email addresses", "Passwords", "Names", "Phone numbers"],
                    "threat_level": "High",
                    "description": "Major data breach affecting 2.5 million users",
                    "source": "Corporate database hack"
                },
                {
                    "name": "SocialNet Leak 2022",
                    "date": "2022-03-10",
                    "data_types": ["Email addresses", "Profile data", "Messages"],
                    "threat_level": "Medium",
                    "description": "Social media platform data exposure",
                    "source": "Configuration error"
                }
            ],
            "admin@test.com": [
                {
                    "name": "TechCorp Incident 2024",
                    "date": "2024-01-20",
                    "data_types": ["Email addresses", "Encrypted passwords", "User preferences"],
                    "threat_level": "Low",
                    "description": "Limited exposure of user account data",
                    "source": "Third-party service breach"
                }
            ]
        }

    def check_email_breaches(self, email: str) -> Dict[str, Any]:
        """
        Check if an email address appears in known data breaches
        """
        try:
            email = email.lower().strip()
            
            # Validate email format
            if not self._is_valid_email(email):
                return {
                    "error": "Invalid email format",
                    "email": email,
                    "is_compromised": False,
                    "breaches": [],
                    "check_timestamp": datetime.now().isoformat()
                }
            
            # Check against breach databases
            breaches = self._query_breach_databases(email)
            
            # Calculate risk assessment
            risk_assessment = self._calculate_risk(breaches)
            
            return {
                "email": email,
                "is_compromised": len(breaches) > 0,
                "breach_count": len(breaches),
                "breaches": breaches,
                "risk_assessment": risk_assessment,
                "check_timestamp": datetime.now().isoformat(),
                "recommendations": self._generate_recommendations(breaches)
            }
            
        except Exception as e:
            return {
                "error": f"Breach check failed: {str(e)}",
                "email": email,
                "is_compromised": False,
                "breaches": [],
                "check_timestamp": datetime.now().isoformat()
            }

    def _is_valid_email(self, email: str) -> bool:
        """
        Basic email validation
        """
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def _query_breach_databases(self, email: str) -> List[Dict[str, Any]]:
        """
        Query multiple breach databases for the email
        """
        breaches = []
        
        # Check mock database
        if email in self.mock_breaches:
            breaches.extend(self.mock_breaches[email])
        
        # In a real implementation, you would query actual APIs:
        # - HaveIBeenPwned API
        # - DeHashed API
        # - LeakCheck API
        # - Custom breach databases
        
        # Simulate API delay
        import time
        time.sleep(0.5)
        
        return breaches

    def _calculate_risk(self, breaches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall risk assessment based on breaches
        """
        if not breaches:
            return {
                "level": "Safe",
                "score": 0,
                "description": "No known breaches found"
            }
        
        # Calculate risk score
        risk_score = 0
        critical_data_exposed = False
        
        for breach in breaches:
            threat_level = breach.get("threat_level", "Medium")
            data_types = breach.get("data_types", [])
            
            # Score based on threat level
            if threat_level == "Critical":
                risk_score += 40
            elif threat_level == "High":
                risk_score += 30
            elif threat_level == "Medium":
                risk_score += 20
            else:  # Low
                risk_score += 10
            
            # Additional score for sensitive data
            if any(sensitive in str(data_types).lower() 
                   for sensitive in ["password", "ssn", "credit card", "financial"]):
                risk_score += 20
                critical_data_exposed = True
        
        # Determine risk level
        if risk_score >= 80:
            level = "Critical"
        elif risk_score >= 60:
            level = "High"
        elif risk_score >= 30:
            level = "Medium"
        else:
            level = "Low"
        
        return {
            "level": level,
            "score": min(risk_score, 100),
            "critical_data_exposed": critical_data_exposed,
            "description": f"Risk level: {level} based on {len(breaches)} breach(es)"
        }

    def _generate_recommendations(self, breaches: List[Dict[str, Any]]) -> List[str]:
        """
        Generate security recommendations based on breaches
        """
        if not breaches:
            return ["Your email appears to be safe from known breaches."]
        
        recommendations = [
            "Change passwords for all accounts associated with this email",
            "Enable two-factor authentication where possible",
            "Monitor your accounts for suspicious activity"
        ]
        
        # Check for specific data types
        all_data_types = []
        for breach in breaches:
            all_data_types.extend(breach.get("data_types", []))
        
        if any("password" in dt.lower() for dt in all_data_types):
            recommendations.append("Use a password manager to generate unique passwords")
        
        if any("financial" in dt.lower() or "credit" in dt.lower() for dt in all_data_types):
            recommendations.append("Monitor your credit reports and bank statements")
            recommendations.append("Consider placing a fraud alert on your credit file")
        
        if any("ssn" in dt.lower() or "social security" in dt.lower() for dt in all_data_types):
            recommendations.append("Consider identity theft protection services")
        
        return recommendations

# Example usage
if __name__ == "__main__":
    checker = BreachChecker()
    
    test_emails = [
        "test@example.com",
        "safe@example.com",
        "admin@test.com"
    ]
    
    for email in test_emails:
        result = checker.check_email_breaches(email)
        print(f"\nEmail: {email}")
        print(f"Compromised: {result['is_compromised']}")
        if result['is_compromised']:
            print(f"Breaches: {result['breach_count']}")
            print(f"Risk Level: {result['risk_assessment']['level']}")
            print("Recommendations:")
            for rec in result['recommendations']:
                print(f"  - {rec}")
        print("-" * 50)
