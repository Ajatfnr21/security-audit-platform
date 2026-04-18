"""
Security scanner with async capabilities.
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path
import aiohttp
import ssl
import socket

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanType(Enum):
    PORT_SCAN = "port_scan"
    SSL_TLS = "ssl_tls"
    HEADERS = "headers"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    DEPENDENCIES = "dependencies"


@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: Severity
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class ScanTarget:
    url: Optional[str] = None
    ip: Optional[str] = None
    domain: Optional[str] = None
    port: int = 443
    path: str = "/"
    
    def get_full_url(self) -> str:
        if self.url:
            return self.url
        scheme = "https" if self.port == 443 else "http"
        host = self.domain or self.ip
        return f"{scheme}://{host}:{self.port}{self.path}"


@dataclass
class ScanResult:
    target: ScanTarget
    scan_type: ScanType
    timestamp: datetime
    duration_ms: float
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)
    passed: bool = False
    error: Optional[str] = None
    
    def get_severity_counts(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts


class SecurityScanner:
    """Multi-purpose security scanner."""
    
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
    
    def __init__(self, timeout: int = 30, max_concurrent: int = 10):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if not self._session:
            connector = aiohttp.TCPConnector(limit=self.max_concurrent)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self._session
    
    async def scan_port(self, target: ScanTarget, port: int) -> Dict[str, Any]:
        """Scan a single port."""
        host = target.domain or target.ip
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5
            )
            writer.close()
            await writer.wait_closed()
            return {"port": port, "open": True}
        except:
            return {"port": port, "open": False}
    
    async def scan_ports(self, target: ScanTarget, ports: Optional[List[int]] = None) -> ScanResult:
        """Perform port scan."""
        start = datetime.now()
        ports = ports or self.COMMON_PORTS
        
        tasks = [self.scan_port(target, p) for p in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r["open"]]
        duration = (datetime.now() - start).total_seconds() * 1000
        
        vulnerabilities = []
        dangerous_ports = {21: "FTP", 23: "Telnet", 3389: "RDP"}
        
        for port_info in open_ports:
            port = port_info["port"]
            if port in dangerous_ports:
                vulnerabilities.append(Vulnerability(
                    id=f"OPEN-{port}",
                    title=f"Dangerous Port Open: {dangerous_ports[port]}",
                    description=f"Port {port} ({dangerous_ports[port]}) is open and accessible",
                    severity=Severity.HIGH,
                    remediation=f"Close port {port} or restrict access"
                ))
        
        return ScanResult(
            target=target,
            scan_type=ScanType.PORT_SCAN,
            timestamp=start,
            duration_ms=duration,
            vulnerabilities=vulnerabilities,
            findings={"open_ports": [p["port"] for p in open_ports], "total_scanned": len(ports)},
            passed=len(vulnerabilities) == 0
        )
    
    async def scan_ssl(self, target: ScanTarget) -> ScanResult:
        """Scan SSL/TLS configuration."""
        start = datetime.now()
        vulnerabilities = []
        findings = {}
        
        host = target.domain or target.ip
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, target.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    findings["certificate"] = cert
                    findings["cipher"] = cipher
                    findings["tls_version"] = version
                    
                    # Check TLS version
                    if version in ["TLSv1", "TLSv1.1"]:
                        vulnerabilities.append(Vulnerability(
                            id="SSL-001",
                            title="Outdated TLS Version",
                            description=f"Server supports {version} which is deprecated",
                            severity=Severity.HIGH,
                            remediation="Disable TLS 1.0 and 1.1, use TLS 1.2 or 1.3"
                        ))
                    
                    # Check certificate expiration
                    if cert and 'notAfter' in cert:
                        from datetime import datetime as dt
                        exp_date = dt.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if exp_date < dt.now():
                            vulnerabilities.append(Vulnerability(
                                id="SSL-002",
                                title="Expired SSL Certificate",
                                description=f"Certificate expired on {exp_date}",
                                severity=Severity.CRITICAL,
                                remediation="Renew SSL certificate immediately"
                            ))
                    
                    findings["certificate_valid"] = len(vulnerabilities) == 0
                    
        except Exception as e:
            findings["error"] = str(e)
        
        duration = (datetime.now() - start).total_seconds() * 1000
        
        return ScanResult(
            target=target,
            scan_type=ScanType.SSL_TLS,
            timestamp=start,
            duration_ms=duration,
            vulnerabilities=vulnerabilities,
            findings=findings,
            passed=len(vulnerabilities) == 0
        )
    
    async def scan_headers(self, target: ScanTarget) -> ScanResult:
        """Scan HTTP security headers."""
        start = datetime.now()
        session = await self._get_session()
        
        vulnerabilities = []
        findings = {}
        
        try:
            async with session.get(target.get_full_url()) as response:
                headers = dict(response.headers)
                findings["status_code"] = response.status
                findings["headers"] = {k: v for k, v in headers.items()}
                
                # Security headers to check
                security_headers = {
                    'Strict-Transport-Security': ('HSTS', Severity.HIGH),
                    'Content-Security-Policy': ('CSP', Severity.MEDIUM),
                    'X-Frame-Options': ('Clickjacking Protection', Severity.MEDIUM),
                    'X-Content-Type-Options': ('MIME Sniffing Protection', Severity.LOW),
                    'Referrer-Policy': ('Referrer Policy', Severity.LOW),
                    'Permissions-Policy': ('Permissions Policy', Severity.LOW),
                }
                
                for header, (name, severity) in security_headers.items():
                    if header not in headers:
                        vulnerabilities.append(Vulnerability(
                            id=f"HDR-{header}",
                            title=f"Missing Security Header: {name}",
                            description=f"The {header} header is not set",
                            severity=severity,
                            remediation=f"Add '{header}' header to all responses"
                        ))
                
                # Check for information disclosure headers
                info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
                for header in info_headers:
                    if header in headers:
                        vulnerabilities.append(Vulnerability(
                            id=f"HDR-INFO",
                            title="Information Disclosure",
                            description=f"{header} header reveals server information",
                            severity=Severity.LOW,
                            remediation=f"Remove or obfuscate {header} header"
                        ))
                        
        except Exception as e:
            findings["error"] = str(e)
        
        duration = (datetime.now() - start).total_seconds() * 1000
        
        return ScanResult(
            target=target,
            scan_type=ScanType.HEADERS,
            timestamp=start,
            duration_ms=duration,
            vulnerabilities=vulnerabilities,
            findings=findings,
            passed=len(vulnerabilities) == 0
        )
    
    async def run_full_scan(self, target: ScanTarget) -> List[ScanResult]:
        """Run all scan types against a target."""
        tasks = [
            self.scan_ports(target),
            self.scan_ssl(target),
            self.scan_headers(target)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Scan failed: {result}")
            else:
                valid_results.append(result)
        
        return valid_results
    
    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None
