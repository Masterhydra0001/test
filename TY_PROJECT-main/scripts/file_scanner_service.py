#!/usr/bin/env python3
"""
MOBICURE File Scanner Service
Comprehensive file analysis and security scanning
"""

import sys
import json
import os
import hashlib
import magic
import time
import re
from datetime import datetime
from typing import Dict, List, Any

class FileScanner:
    def __init__(self):
        self.suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar',
            '.app', '.deb', '.rpm', '.dmg', '.pkg', '.msi', '.run'
        ]
        
        self.document_types = [
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf'
        ]
        
        self.archive_types = [
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'
        ]
        
        self.image_types = [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.webp'
        ]

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive file analysis"""
        start_time = time.time()
        
        # Basic file information
        file_stat = os.stat(file_path)
        file_name = os.path.basename(file_path)
        file_size = file_stat.st_size
        file_ext = os.path.splitext(file_name)[1].lower()
        
        # Calculate hashes
        hashes = self.calculate_hashes(file_path)
        
        # Detect file type
        file_type = self.detect_file_type(file_path)
        
        # Security analysis
        security_analysis = self.perform_security_analysis(file_path, file_ext, file_size)
        
        # Metadata extraction
        metadata = self.extract_metadata(file_path, file_type)
        
        # Risk assessment
        risk_assessment = self.assess_risk(file_path, file_ext, file_size, security_analysis)
        
        scan_time = round(time.time() - start_time, 2)
        
        return {
            "file_info": {
                "name": file_name,
                "size": file_size,
                "extension": file_ext,
                "type": file_type,
                "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            },
            "hashes": hashes,
            "security_analysis": security_analysis,
            "metadata": metadata,
            "risk_assessment": risk_assessment,
            "scan_time": scan_time,
            "timestamp": datetime.now().isoformat(),
            "service": "MOBICURE File Scanner v1.0.0"
        }

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes"""
        hashes = {}
        
        with open(file_path, 'rb') as f:
            content = f.read()
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
        
        return hashes

    def detect_file_type(self, file_path: str) -> str:
        """Detect actual file type using magic numbers"""
        try:
            # Try to use python-magic if available
            import magic
            return magic.from_file(file_path)
        except ImportError:
            # Fallback to extension-based detection
            ext = os.path.splitext(file_path)[1].lower()
            type_map = {
                '.txt': 'Text file',
                '.pdf': 'PDF document',
                '.jpg': 'JPEG image',
                '.png': 'PNG image',
                '.zip': 'ZIP archive',
                '.exe': 'Windows executable',
                '.dll': 'Windows DLL',
                '.doc': 'Microsoft Word document',
                '.docx': 'Microsoft Word document',
            }
            return type_map.get(ext, f'Unknown file type ({ext})')

    def perform_security_analysis(self, file_path: str, file_ext: str, file_size: int) -> Dict[str, Any]:
        """Perform security analysis on the file"""
        threats = []
        warnings = []
        
        # Check for suspicious extensions
        if file_ext in self.suspicious_extensions:
            threats.append({
                "type": "Suspicious Extension",
                "severity": "high",
                "description": f"File has potentially dangerous extension: {file_ext}",
                "recommendation": "Exercise extreme caution when opening this file"
            })
        
        # Check file size anomalies
        if file_size == 0:
            warnings.append({
                "type": "Empty File",
                "severity": "low",
                "description": "File is empty (0 bytes)",
                "recommendation": "Verify if this is expected"
            })
        elif file_size < 10:
            warnings.append({
                "type": "Very Small File",
                "severity": "medium",
                "description": f"File is unusually small ({file_size} bytes)",
                "recommendation": "Small files can sometimes hide malicious content"
            })
        elif file_size > 100 * 1024 * 1024:  # 100MB
            warnings.append({
                "type": "Large File",
                "severity": "low",
                "description": f"File is very large ({file_size / (1024*1024):.1f} MB)",
                "recommendation": "Large files may consume significant resources"
            })
        
        # Content analysis for text files
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000)  # Read first 10KB
                
                # Check for suspicious patterns
                suspicious_patterns = [
                    (r'eval\s*\(', "Code Injection"),
                    (r'exec\s*\(', "Code Execution"),
                    (r'system\s*\(', "System Command"),
                    (r'shell_exec', "Shell Execution"),
                    (r'base64_decode', "Base64 Decoding"),
                    (r'document\.write', "DOM Manipulation"),
                    (r'innerHTML', "HTML Injection"),
                    (r'XMLHttpRequest', "AJAX Request"),
                ]
                
                for pattern, threat_name in suspicious_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        threats.append({
                            "type": threat_name,
                            "severity": "medium",
                            "description": f"Detected {threat_name.lower()} pattern in file content",
                            "recommendation": "Review file content carefully"
                        })
                
                # Check for URLs
                url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\']*'
                urls = re.findall(url_pattern, content)
                if urls:
                    suspicious_domains = ['bit.ly', 'tinyurl', 'pastebin', 'discord.gg', 't.me']
                    suspicious_urls = [url for url in urls if any(domain in url.lower() for domain in suspicious_domains)]
                    
                    if suspicious_urls:
                        threats.append({
                            "type": "Suspicious URLs",
                            "severity": "high",
                            "description": f"Found {len(suspicious_urls)} suspicious URLs",
                            "recommendation": "Do not visit these URLs without verification"
                        })
        except:
            pass  # Binary file or encoding issues
        
        return {
            "threats": threats,
            "warnings": warnings,
            "threat_count": len(threats),
            "warning_count": len(warnings)
        }

    def extract_metadata(self, file_path: str, file_type: str) -> Dict[str, Any]:
        """Extract file metadata"""
        metadata = {}
        
        try:
            # Basic file permissions
            file_stat = os.stat(file_path)
            metadata['permissions'] = oct(file_stat.st_mode)[-3:]
            
            # Try to extract more specific metadata based on file type
            if 'PDF' in file_type.upper():
                metadata.update(self.extract_pdf_metadata(file_path))
            elif any(img_type in file_type.upper() for img_type in ['JPEG', 'PNG', 'TIFF']):
                metadata.update(self.extract_image_metadata(file_path))
            elif 'ZIP' in file_type.upper():
                metadata.update(self.extract_archive_metadata(file_path))
                
        except Exception as e:
            metadata['extraction_error'] = str(e)
        
        return metadata

    def extract_pdf_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract PDF metadata"""
        metadata = {}
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Read first 1KB
                if b'%PDF' in content:
                    metadata['pdf_version'] = 'Detected'
                    if b'/JavaScript' in content or b'/JS' in content:
                        metadata['contains_javascript'] = True
                    if b'/EmbeddedFile' in content:
                        metadata['contains_embedded_files'] = True
        except:
            pass
        return metadata

    def extract_image_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract image metadata"""
        metadata = {}
        try:
            # Basic image analysis
            with open(file_path, 'rb') as f:
                header = f.read(100)
                if header.startswith(b'\xff\xd8\xff'):
                    metadata['format'] = 'JPEG'
                elif header.startswith(b'\x89PNG'):
                    metadata['format'] = 'PNG'
                elif header.startswith(b'GIF8'):
                    metadata['format'] = 'GIF'
        except:
            pass
        return metadata

    def extract_archive_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract archive metadata"""
        metadata = {}
        try:
            import zipfile
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, 'r') as zip_file:
                    file_list = zip_file.namelist()
                    metadata['file_count'] = len(file_list)
                    metadata['compressed_size'] = sum(info.compress_size for info in zip_file.infolist())
                    metadata['uncompressed_size'] = sum(info.file_size for info in zip_file.infolist())
                    
                    # Check for suspicious files in archive
                    suspicious_files = [f for f in file_list if any(f.lower().endswith(ext) for ext in self.suspicious_extensions)]
                    if suspicious_files:
                        metadata['suspicious_files'] = suspicious_files[:5]  # Limit to first 5
        except:
            pass
        return metadata

    def assess_risk(self, file_path: str, file_ext: str, file_size: int, security_analysis: Dict) -> Dict[str, Any]:
        """Assess overall file risk"""
        risk_score = 0
        risk_factors = []
        
        # Extension-based risk
        if file_ext in self.suspicious_extensions:
            risk_score += 40
            risk_factors.append("Potentially dangerous file extension")
        
        # Threat-based risk
        threat_count = security_analysis.get('threat_count', 0)
        risk_score += threat_count * 20
        
        if threat_count > 0:
            risk_factors.append(f"{threat_count} security threats detected")
        
        # Size-based risk
        if file_size == 0:
            risk_score += 10
            risk_factors.append("Empty file")
        elif file_size < 10:
            risk_score += 15
            risk_factors.append("Unusually small file")
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            "risk_score": min(100, risk_score),
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "recommendation": self.get_recommendation(risk_level)
        }

    def get_recommendation(self, risk_level: str) -> str:
        """Get security recommendation based on risk level"""
        recommendations = {
            "HIGH": "DO NOT OPEN - File poses significant security risk. Scan with multiple antivirus tools.",
            "MEDIUM": "CAUTION ADVISED - Review file carefully before opening. Consider scanning with antivirus.",
            "LOW": "MINOR RISK - File appears mostly safe but exercise normal caution.",
            "MINIMAL": "SAFE - File appears to pose minimal security risk."
        }
        return recommendations.get(risk_level, "Unknown risk level")

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python3 file_scanner_service.py <file_path>"}))
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(json.dumps({"error": "File not found"}))
        sys.exit(1)
    
    try:
        scanner = FileScanner()
        result = scanner.analyze_file(file_path)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(json.dumps({"error": f"Analysis failed: {str(e)}"}))
        sys.exit(1)

if __name__ == "__main__":
    main()
