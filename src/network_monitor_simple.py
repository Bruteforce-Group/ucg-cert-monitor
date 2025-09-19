#!/usr/bin/env python3
"""
UCG Certificate Monitor - Simplified Network Traffic Monitor
Focuses on passive certificate collection without complex TLS parsing
"""

import asyncio
import socket
import ssl
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import structlog

logger = structlog.get_logger(__name__)


class PassiveCertificateCollector:
    """Collect certificates from known endpoints without interception"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.endpoints = []
        self.collected_certificates = {}
        
    def add_endpoint(self, host: str, port: int = 443):
        """Add endpoint to monitor"""
        self.endpoints.append((host, port))
        
    async def collect_certificates(self):
        """Collect certificates from all endpoints"""
        tasks = []
        for host, port in self.endpoints:
            task = asyncio.create_task(self._get_certificate(host, port))
            tasks.append(task)
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    
    async def _get_certificate(self, host: str, port: int):
        """Get certificate from specific endpoint"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get the certificate in DER format
                    cert_der = ssock.getpeercert(binary_form=True)
                    certificate = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    cert_info = {
                        'host': host,
                        'port': port,
                        'timestamp': datetime.now(),
                        'subject': certificate.subject.rfc4514_string(),
                        'issuer': certificate.issuer.rfc4514_string(),
                        'not_before': certificate.not_valid_before,
                        'not_after': certificate.not_valid_after,
                        'fingerprint_sha256': certificate.fingerprint(hashes.SHA256()).hex(),
                        'serial_number': str(certificate.serial_number),
                        'signature_algorithm': certificate.signature_algorithm_oid._name,
                        'raw_certificate': cert_der
                    }
                    
                    key = f"{host}:{port}"
                    self.collected_certificates[key] = cert_info
                    
                    logger.info("Certificate collected",
                               host=host,
                               port=port,
                               subject=cert_info['subject'])
                    
                    return cert_info
                    
        except Exception as e:
            logger.error("Error collecting certificate",
                        host=host, port=port, error=str(e))
            return None


class NetworkTrafficMonitor:
    """Simplified network monitor - currently focuses on passive collection"""
    
    def __init__(self, config: Dict, certificate_callback: Optional[Callable] = None):
        self.config = config
        self.certificate_callback = certificate_callback
        self.running = False
        self.captured_certificates = {}
        self.packet_count = 0
        self.start_time = None
        
        logger.warning("Network traffic monitoring using simplified mode")
        
    def start_monitoring(self):
        """Start monitoring - currently a no-op placeholder"""
        self.running = True
        self.start_time = datetime.now()
        logger.info("Network monitoring started (simplified mode)")
        
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        logger.info("Network monitoring stopped")
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        runtime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            'running': self.running,
            'runtime_seconds': runtime,
            'packets_processed': self.packet_count,
            'certificates_captured': len(self.captured_certificates),
            'packets_per_second': self.packet_count / runtime if runtime > 0 else 0,
            'mode': 'simplified'
        }
    
    def get_captured_certificates(self) -> Dict:
        """Get all captured certificates"""
        return self.captured_certificates.copy()


if __name__ == "__main__":
    # Example usage
    import yaml
    import asyncio
    
    async def test_collection():
        # Load configuration
        try:
            with open('../config/config.yaml', 'r') as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            config = {}
        
        # Test passive collection
        collector = PassiveCertificateCollector(config)
        collector.add_endpoint('google.com', 443)
        collector.add_endpoint('github.com', 443)
        
        print("Collecting certificates...")
        certificates = await collector.collect_certificates()
        
        for cert_info in certificates:
            if cert_info:
                print(f"\nCertificate for {cert_info['host']}:{cert_info['port']}:")
                print(f"Subject: {cert_info['subject']}")
                print(f"Issuer: {cert_info['issuer']}")
                print(f"Expires: {cert_info['not_after']}")
                print(f"Fingerprint: {cert_info['fingerprint_sha256'][:32]}...")
            else:
                print("Failed to collect certificate")
    
    # Run test
    asyncio.run(test_collection())
