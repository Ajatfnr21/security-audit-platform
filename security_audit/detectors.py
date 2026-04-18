"""
Vulnerability detection and compliance checking.
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
import aiohttp

from .scanner import Severity, Vulnerability, ScanTarget, ScanResult, ScanType

logger = logging.getLogger(__name__)


class VulnerabilityDetector:
    """Detects common vulnerabilities in web applications."""
    
    SQLI_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"exec(\s|\+)+(s|x)p\w+",
        r"UNION\s+SELECT",
        r"INSERT\s+INTO",
        r"DELETE\s+FROM",
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>[\s\S]*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe",
        r"<object",
        r"<embed",
    ]
    
    def __init__(self):
        self.sqli_regex = [re.compile(p, re.IGNORECASE) for p in self.SQLI_PATTERNS]
        self.xss_regex = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
    
    async def detect_sqli(self, target: ScanTarget) -> List[Vulnerability]:
        """Test for SQL injection vulnerabilities."""
        vulnerabilities = []
        
        test_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "1 AND 1=1",
            "1' AND 1=1--",
        ]
        
        # This is a simplified check - real implementation would
        # actually test the endpoints with payloads
        return vulnerabilities
    
    async def detect_xss(self, target: ScanTarget, content: str) -> List[Vulnerability]:
        """Detect XSS vulnerabilities in content."""
        vulnerabilities = []
        
        for pattern in self.xss_regex:
            if pattern.search(content):
                vulnerabilities.append(Vulnerability(
                    id="XSS-001",
                    title="Potential XSS Vulnerability",
                    description="Content may contain XSS attack vectors",
                    severity=Severity.HIGH,
                    remediation="Sanitize user input and encode output"
                ))
                break
        
        return vulnerabilities
    
    async def check_dependencies(self, package_file: str) -> List[Vulnerability]:
        """Check dependencies for known vulnerabilities."""
        vulnerabilities = []
        
        # Parse package.json, requirements.txt, etc.
        file_path = Path(package_file)
        if not file_path.exists():
            return vulnerabilities
        
        content = file_path.read_text()
        
        # Check against known vulnerable versions
        # This is simplified - real implementation would use vulnerability DB
        known_vulns = {
            "django<3.2.14": (Severity.HIGH, "CVE-2022-28346", "SQL injection vulnerability"),
            "requests<2.31.0": (Severity.MEDIUM, "CVE-2023-32681", "Potential credential leak"),
            "flask<2.3.2": (Severity.MEDIUM, "CVE-2023-30861", "Cookie security issue"),
        }
        
        for dep_pattern, (severity, cve, desc) in known_vulns.items():
            if dep_pattern in content.lower():
                vulnerabilities.append(Vulnerability(
                    id=cve,
                    title=f"Vulnerable Dependency: {dep_pattern}",
                    description=desc,
                    severity=severity,
                    cve_id=cve,
                    remediation=f"Update {dep_pattern.split('<')[0]} to latest version"
                ))
        
        return vulnerabilities


class ComplianceChecker:
    """Check compliance with security standards."""
    
    STANDARDS = {
        "OWASP_TOP_10": [
            "Injection",
            "Broken Authentication",
            "Sensitive Data Exposure",
            "XML External Entities",
            "Broken Access Control",
            "Security Misconfiguration",
            "Cross-Site Scripting (XSS)",
            "Insecure Deserialization",
            "Using Components with Known Vulnerabilities",
            "Insufficient Logging and Monitoring"
        ],
        "PCI_DSS": [
            "Install and maintain firewall",
            "Change vendor-supplied defaults",
            "Protect stored cardholder data",
            "Encrypt transmission of cardholder data",
            "Use anti-virus software",
            "Develop secure systems",
            "Restrict access by need-to-know",
            "Assign unique user IDs",
            "Restrict physical access",
            "Track network resources",
            "Test security systems",
            "Maintain information security policy"
        ],
        "SOC2": [
            "Security",
            "Availability",
            "Processing Integrity",
            "Confidentiality",
            "Privacy"
        ]
    }
    
    def __init__(self, standard: str = "OWASP_TOP_10"):
        self.standard = standard
        self.requirements = self.STANDARDS.get(standard, [])
    
    def check(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Check compliance against scan results."""
        findings = {
            "standard": self.standard,
            "checked_at": datetime.now().isoformat(),
            "requirements": [],
            "score": 0,
            "passed": False
        }
        
        all_vulns = []
        for result in scan_results:
            all_vulns.extend(result.vulnerabilities)
        
        # Map vulnerabilities to requirements
        requirement_scores = {}
        for req in self.requirements:
            # Simplified scoring - real implementation would be more sophisticated
            score = 100
            for vuln in all_vulns:
                if self._vuln_maps_to_req(vuln, req):
                    score -= 25 if vuln.severity == Severity.CRITICAL else \
                             15 if vuln.severity == Severity.HIGH else \
                             10 if vuln.severity == Severity.MEDIUM else 5
            
            requirement_scores[req] = max(0, score)
            findings["requirements"].append({
                "name": req,
                "score": requirement_scores[req],
                "status": "pass" if requirement_scores[req] >= 80 else "fail"
            })
        
        overall_score = sum(requirement_scores.values()) / len(requirement_scores) if requirement_scores else 0
        findings["score"] = round(overall_score, 2)
        findings["passed"] = overall_score >= 80
        
        return findings
    
    def _vuln_maps_to_req(self, vuln: Vulnerability, requirement: str) -> bool:
        """Check if a vulnerability maps to a compliance requirement."""
        vuln_text = f"{vuln.title} {vuln.description}".lower()
        req_lower = requirement.lower()
        
        # Simple keyword matching
        keywords = {
            "injection": ["sql", "injection", "sqli"],
            "authentication": ["auth", "login", "session"],
            "data exposure": ["exposure", "leak", "sensitive"],
            "access control": ["access", "permission", "authorization"],
            "xss": ["xss", "cross-site", "script"],
        }
        
        for key, words in keywords.items():
            if key in req_lower:
                return any(word in vuln_text for word in words)
        
        return False
