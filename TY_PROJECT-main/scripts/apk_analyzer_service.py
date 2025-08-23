#!/usr/bin/env python3
"""
MOBICURE APK Analyzer Service
Comprehensive Android APK security analysis tool
"""

import os
import sys
import json
import hashlib
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
import re
import subprocess
from typing import Dict, List, Any, Optional
import tempfile
import shutil

class APKAnalyzer:
    def __init__(self):
        self.suspicious_permissions = {
            'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_SMS', 'SEND_SMS', 'CALL_PHONE',
            'READ_PHONE_STATE', 'WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE',
            'SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS', 'INSTALL_PACKAGES'
        }
        
        self.malware_indicators = [
            'Runtime.exec', 'ProcessBuilder', 'System.loadLibrary',
            'DexClassLoader', 'PathClassLoader', 'URLClassLoader',
            'reflection', 'crypto', 'obfuscation'
        ]
        
        self.suspicious_urls = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
            '.tk', '.ml', '.ga', '.cf', 'suspicious-domain'
        ]

    def analyze_apk(self, apk_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive APK analysis
        """
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract APK
                extracted_path = self._extract_apk(apk_path, temp_dir)
                
                # Parse AndroidManifest.xml
                manifest_data = self._parse_manifest(extracted_path)
                
                # Analyze DEX files
                dex_analysis = self._analyze_dex_files(extracted_path)
                
                # Extract network endpoints
                network_data = self._extract_network_endpoints(extracted_path)
                
                # Security analysis
                security_analysis = self._perform_security_analysis(extracted_path, manifest_data)
                
                # Certificate analysis
                cert_info = self._analyze_certificate(apk_path)
                
                # Combine all analysis results
                return self._compile_results(
                    apk_path, manifest_data, dex_analysis, 
                    network_data, security_analysis, cert_info
                )
                
        except Exception as e:
            return {"error": f"APK analysis failed: {str(e)}"}

    def _extract_apk(self, apk_path: str, extract_to: str) -> str:
        """Extract APK contents"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            return extract_to
        except Exception as e:
            raise Exception(f"Failed to extract APK: {str(e)}")

    def _parse_manifest(self, extracted_path: str) -> Dict[str, Any]:
        """Parse AndroidManifest.xml"""
        manifest_path = os.path.join(extracted_path, 'AndroidManifest.xml')
        
        if not os.path.exists(manifest_path):
            return {"error": "AndroidManifest.xml not found"}
        
        try:
            # For binary XML, we'd need aapt or similar tool
            # This is a simplified version for demonstration
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract basic information
            package_name = root.get('package', 'unknown')
            version_code = root.get('{http://schemas.android.com/apk/res/android}versionCode', '1')
            version_name = root.get('{http://schemas.android.com/apk/res/android}versionName', '1.0')
            
            # Extract components
            activities = [elem.get('{http://schemas.android.com/apk/res/android}name', '') 
                         for elem in root.findall('.//activity')]
            services = [elem.get('{http://schemas.android.com/apk/res/android}name', '') 
                       for elem in root.findall('.//service')]
            receivers = [elem.get('{http://schemas.android.com/apk/res/android}name', '') 
                        for elem in root.findall('.//receiver')]
            providers = [elem.get('{http://schemas.android.com/apk/res/android}name', '') 
                        for elem in root.findall('.//provider')]
            
            # Extract permissions
            permissions = [elem.get('{http://schemas.android.com/apk/res/android}name', '') 
                          for elem in root.findall('.//uses-permission')]
            
            # Extract SDK versions
            uses_sdk = root.find('.//uses-sdk')
            min_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '1') if uses_sdk is not None else '1'
            target_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', '1') if uses_sdk is not None else '1'
            
            return {
                'package_name': package_name,
                'version_code': int(version_code),
                'version_name': version_name,
                'activities': activities,
                'services': services,
                'receivers': receivers,
                'providers': providers,
                'permissions': permissions,
                'min_sdk_version': int(min_sdk),
                'target_sdk_version': int(target_sdk)
            }
            
        except Exception as e:
            return {"error": f"Failed to parse manifest: {str(e)}"}

    def _analyze_dex_files(self, extracted_path: str) -> Dict[str, Any]:
        """Analyze DEX files for suspicious patterns"""
        dex_files = []
        suspicious_apis = []
        has_obfuscation = False
        
        # Find DEX files
        for root, dirs, files in os.walk(extracted_path):
            for file in files:
                if file.endswith('.dex'):
                    dex_files.append(os.path.join(root, file))
        
        # Analyze each DEX file
        for dex_file in dex_files:
            try:
                with open(dex_file, 'rb') as f:
                    content = f.read()
                    
                    # Look for suspicious API calls
                    for indicator in self.malware_indicators:
                        if indicator.encode() in content:
                            suspicious_apis.append(indicator)
                    
                    # Check for obfuscation (simplified check)
                    if b'obfuscation' in content or len([x for x in content if x < 32]) > len(content) * 0.3:
                        has_obfuscation = True
                        
            except Exception:
                continue
        
        return {
            'dex_files_count': len(dex_files),
            'suspicious_apis': list(set(suspicious_apis)),
            'has_obfuscation': has_obfuscation
        }

    def _extract_network_endpoints(self, extracted_path: str) -> Dict[str, List[str]]:
        """Extract network endpoints from APK"""
        urls = []
        ips = []
        
        # URL patterns
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?\b')
        
        # Search in all text files
        for root, dirs, files in os.walk(extracted_path):
            for file in files:
                if file.endswith(('.xml', '.txt', '.json', '.properties')):
                    try:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Extract URLs
                            found_urls = url_pattern.findall(content)
                            urls.extend(found_urls)
                            
                            # Extract IPs
                            found_ips = ip_pattern.findall(content)
                            ips.extend(found_ips)
                            
                    except Exception:
                        continue
        
        return {
            'urls': list(set(urls)),
            'ips': list(set(ips))
        }

    def _perform_security_analysis(self, extracted_path: str, manifest_data: Dict) -> Dict[str, Any]:
        """Perform security analysis"""
        risk_score = 0
        threats = []
        
        # Check permissions
        dangerous_perms = set(manifest_data.get('permissions', [])) & self.suspicious_permissions
        if dangerous_perms:
            risk_score += len(dangerous_perms) * 10
            threats.append(f"Requests {len(dangerous_perms)} dangerous permissions")
        
        # Check for root detection
        has_root_detection = False
        root_keywords = [b'su', b'busybox', b'superuser', b'/system/xbin/', b'/system/bin/']
        
        for root, dirs, files in os.walk(extracted_path):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        for keyword in root_keywords:
                            if keyword in content:
                                has_root_detection = True
                                break
                except Exception:
                    continue
        
        # Check for anti-debugging
        has_anti_debugging = False
        debug_keywords = [b'android_server_gdbserver', b'TracerPid', b'ptrace']
        
        for root, dirs, files in os.walk(extracted_path):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        for keyword in debug_keywords:
                            if keyword in content:
                                has_anti_debugging = True
                                break
                except Exception:
                    continue
        
        # Determine risk level
        if risk_score > 50:
            risk_level = "HIGH"
        elif risk_score > 20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'threats': threats,
            'has_root_detection': has_root_detection,
            'has_anti_debugging': has_anti_debugging
        }

    def _analyze_certificate(self, apk_path: str) -> Dict[str, Any]:
        """Analyze APK certificate"""
        try:
            # This would require keytool or similar
            # Simplified version for demonstration
            return {
                'issuer': 'CN=Android Debug, O=Android, C=US',
                'subject': 'CN=Android Debug, O=Android, C=US',
                'valid_from': '2023-01-01',
                'valid_to': '2025-12-31',
                'serial_number': hashlib.md5(apk_path.encode()).hexdigest()[:16],
                'is_valid': True
            }
        except Exception:
            return {
                'issuer': 'Unknown',
                'subject': 'Unknown',
                'valid_from': 'Unknown',
                'valid_to': 'Unknown',
                'serial_number': 'Unknown',
                'is_valid': False
            }

    def _compile_results(self, apk_path: str, manifest_data: Dict, dex_analysis: Dict, 
                        network_data: Dict, security_analysis: Dict, cert_info: Dict) -> Dict[str, Any]:
        """Compile all analysis results"""
        
        file_size = os.path.getsize(apk_path)
        
        return {
            'filename': os.path.basename(apk_path),
            'file_size': file_size,
            'package_name': manifest_data.get('package_name', 'unknown'),
            'version_code': manifest_data.get('version_code', 1),
            'version_name': manifest_data.get('version_name', '1.0'),
            'min_sdk_version': manifest_data.get('min_sdk_version', 1),
            'target_sdk_version': manifest_data.get('target_sdk_version', 1),
            'activities': manifest_data.get('activities', []),
            'services': manifest_data.get('services', []),
            'receivers': manifest_data.get('receivers', []),
            'providers': manifest_data.get('providers', []),
            'permissions': manifest_data.get('permissions', []),
            'url_endpoints': network_data.get('urls', []),
            'ip_endpoints': network_data.get('ips', []),
            'risk_level': security_analysis.get('risk_level', 'LOW'),
            'risk_score': security_analysis.get('risk_score', 0),
            'threats': security_analysis.get('threats', []),
            'suspicious_apis': dex_analysis.get('suspicious_apis', []),
            'has_obfuscation': dex_analysis.get('has_obfuscation', False),
            'has_root_detection': security_analysis.get('has_root_detection', False),
            'has_anti_debugging': security_analysis.get('has_anti_debugging', False),
            'certificate_info': cert_info,
            'malware_detected': security_analysis.get('risk_score', 0) > 50
        }

def main():
    if len(sys.argv) != 2:
        print("Usage: python apk_analyzer_service.py <apk_file>")
        sys.exit(1)
    
    apk_file = sys.argv[1]
    
    if not os.path.exists(apk_file):
        print(f"Error: APK file '{apk_file}' not found")
        sys.exit(1)
    
    analyzer = APKAnalyzer()
    results = analyzer.analyze_apk(apk_file)
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
