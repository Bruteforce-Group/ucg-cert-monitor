#!/usr/bin/env python3
"""
UCG Certificate Monitor - UCG API Integration
Client for interfacing with Universal Customer Gateway APIs
"""

import asyncio
import json
import ssl
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import socket

import aiohttp
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import structlog

logger = structlog.get_logger(__name__)


class UCGAPIClient:
    """Client for UCG API integration"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.ucg_config = config.get('ucg', {})
        self.api_endpoints = self.ucg_config.get('api_endpoints', [])
        self.auth_config = self.ucg_config.get('auth', {})
        self.polling_interval = self.ucg_config.get('polling_interval', 300)
        self.timeout = self.ucg_config.get('timeout', 30)
        self.session = None
        self._authenticated_endpoints = {}
        
    async def initialize(self):
        """Initialize API client and authenticate with endpoints"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(verify_ssl=False)  # UCG may use self-signed certs
        )
        
        # Authenticate with all endpoints
        for endpoint in self.api_endpoints:
            try:
                if await self._authenticate_endpoint(endpoint):
                    logger.info("Successfully authenticated with UCG endpoint", endpoint=endpoint)
                else:
                    logger.warning("Failed to authenticate with UCG endpoint", endpoint=endpoint)
            except Exception as e:
                logger.error("Error authenticating with UCG endpoint", endpoint=endpoint, error=str(e))
    
    async def close(self):
        """Close API client session"""
        if self.session:
            await self.session.close()
    
    async def _authenticate_endpoint(self, endpoint: str) -> bool:
        """Authenticate with a specific UCG endpoint"""
        try:
            auth_url = urljoin(endpoint, '/auth/login')
            
            # Prepare authentication data
            auth_data = {
                'username': self.auth_config.get('username'),
                'password': self.auth_config.get('password')
            }
            
            # Try API key authentication first (including UniFi X-API-KEY)
            if self.auth_config.get('api_key'):
                headers = {'X-API-KEY': self.auth_config.get('api_key'), 'Accept': 'application/json'}
                
                # Try UniFi-specific status endpoints first
                unifi_test_endpoints = [
                    '/proxy/network/integration/v1/sites',
                    '/api/s/default/stat/sysinfo',
                    '/api/status'
                ]
                
                for test_endpoint in unifi_test_endpoints:
                    try:
                        test_url = urljoin(endpoint, test_endpoint)
                        logger.debug("Testing UniFi API endpoint", endpoint=endpoint, test_url=test_url)
                        async with self.session.get(test_url, headers=headers) as resp:
                            logger.debug("UniFi API test response", endpoint=endpoint, status=resp.status, test_endpoint=test_endpoint)
                            if resp.status == 200:
                                # Verify it returns JSON (UniFi APIs return JSON)
                                try:
                                    data = await resp.json()
                                    logger.info("UniFi API key authentication successful", endpoint=endpoint, test_endpoint=test_endpoint, response_keys=list(data.keys()) if isinstance(data, dict) else 'non-dict')
                                    self._authenticated_endpoints[endpoint] = {'type': 'api_key', 'headers': headers}
                                    return True
                                except Exception as json_error:
                                    logger.debug("Failed to parse JSON response", endpoint=endpoint, error=str(json_error))
                                    continue
                    except Exception as e:
                        logger.debug("Failed UniFi API key test", endpoint=endpoint, test_endpoint=test_endpoint, error=str(e))
                        continue
            
            # Try basic authentication
            auth = aiohttp.BasicAuth(auth_data['username'], auth_data['password'])
            async with self.session.post(auth_url, json=auth_data, auth=auth) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if 'token' in data:
                        headers = {'Authorization': f'Bearer {data["token"]}'}
                        self._authenticated_endpoints[endpoint] = {'type': 'bearer', 'headers': headers}
                        return True
                    else:
                        # Basic auth successful
                        self._authenticated_endpoints[endpoint] = {'type': 'basic', 'auth': auth}
                        return True
            
            return False
            
        except Exception as e:
            logger.error("Authentication error", endpoint=endpoint, error=str(e))
            return False
    
    async def get_device_certificates(self, endpoint: str) -> List[Dict]:
        """Get certificates from UCG device"""
        certificates = []
        
        try:
            if endpoint not in self._authenticated_endpoints:
                logger.warning("Endpoint not authenticated", endpoint=endpoint)
                return certificates
            
            auth_info = self._authenticated_endpoints[endpoint]
            headers = auth_info.get('headers', {})
            auth = auth_info.get('auth')
            
            # Common UCG certificate endpoints (including UniFi)
            cert_endpoints = [
                '/api/v1/certificates',
                '/api/certificates', 
                '/cgi-bin/certificates',
                '/api/system/certificates',
                '/api/ssl/certificates',
                # UniFi specific endpoints
                '/proxy/network/integration/v1/sites',
                '/proxy/network/integration/v1/settings/certificates',
                '/proxy/network/api/s/default/rest/setting/super_identity',
                '/api/s/default/rest/setting/super_identity'
            ]
            
            for cert_endpoint in cert_endpoints:
                try:
                    url = urljoin(endpoint, cert_endpoint)
                    async with self.session.get(url, headers=headers, auth=auth) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            certs = self._parse_ucg_certificates(data, endpoint)
                            certificates.extend(certs)
                            logger.info("Retrieved certificates from UCG", 
                                       endpoint=endpoint, count=len(certs))
                            break
                except Exception as e:
                    logger.debug("Failed to get certificates from endpoint", 
                                url=url, error=str(e))
                    continue
            
        except Exception as e:
            logger.error("Error getting device certificates", endpoint=endpoint, error=str(e))
        
        return certificates
    
    def _parse_ucg_certificates(self, data: Dict, endpoint: str) -> List[Dict]:
        """Parse UCG certificate response data"""
        certificates = []
        
        try:
            # Handle different UCG response formats
            cert_list = data
            
            if isinstance(data, dict):
                # Try common keys
                for key in ['certificates', 'certs', 'ssl_certificates', 'data']:
                    if key in data:
                        cert_list = data[key]
                        break
            
            if not isinstance(cert_list, list):
                cert_list = [cert_list] if cert_list else []
            
            for cert_data in cert_list:
                try:
                    cert_info = self._extract_certificate_info(cert_data, endpoint)
                    if cert_info:
                        certificates.append(cert_info)
                except Exception as e:
                    logger.error("Error parsing certificate", error=str(e))
                    continue
                    
        except Exception as e:
            logger.error("Error parsing UCG certificates", error=str(e))
        
        return certificates
    
    def _extract_certificate_info(self, cert_data: Dict, endpoint: str) -> Optional[Dict]:
        """Extract certificate information from UCG data"""
        try:
            # Parse certificate from different formats
            cert_pem = None
            cert_der = None
            
            # Try to find certificate data
            for key in ['certificate', 'cert', 'pem', 'der', 'data']:
                if key in cert_data:
                    if key == 'der':
                        cert_der = cert_data[key]
                    else:
                        cert_pem = cert_data[key]
                    break
            
            # Parse certificate
            certificate = None
            if cert_pem:
                if isinstance(cert_pem, str):
                    cert_pem = cert_pem.encode('utf-8')
                certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
            elif cert_der:
                if isinstance(cert_der, str):
                    import base64
                    cert_der = base64.b64decode(cert_der)
                certificate = x509.load_der_x509_certificate(cert_der, default_backend())
            
            if not certificate:
                return None
            
            # Extract certificate information
            parsed_url = urlparse(endpoint)
            host = parsed_url.hostname or 'unknown'
            port = parsed_url.port or 443
            
            cert_info = {
                'host': host,
                'port': port,
                'source': 'ucg_api',
                'endpoint': endpoint,
                'timestamp': datetime.now(),
                'subject': certificate.subject.rfc4514_string(),
                'issuer': certificate.issuer.rfc4514_string(),
                'serial_number': str(certificate.serial_number),
                'not_before': certificate.not_valid_before,
                'not_after': certificate.not_valid_after,
                'fingerprint_sha256': certificate.fingerprint(x509.hashes.SHA256()).hex(),
                'signature_algorithm': certificate.signature_algorithm_oid._name,
                'raw_certificate': cert_der or cert_pem,
                'ucg_metadata': {
                    'name': cert_data.get('name', ''),
                    'type': cert_data.get('type', ''),
                    'status': cert_data.get('status', ''),
                    'usage': cert_data.get('usage', ''),
                    'id': cert_data.get('id', '')
                }
            }
            
            return cert_info
            
        except Exception as e:
            logger.error("Error extracting certificate info", error=str(e))
            return None
    
    async def get_ucg_configuration(self, endpoint: str) -> Dict:
        """Get UCG configuration that might affect certificates"""
        try:
            if endpoint not in self._authenticated_endpoints:
                return {}
            
            auth_info = self._authenticated_endpoints[endpoint]
            headers = auth_info.get('headers', {})
            auth = auth_info.get('auth')
            
            config_endpoints = [
                '/api/v1/config',
                '/api/configuration',
                '/api/system/config',
                '/cgi-bin/config',
                # UniFi specific endpoints
                '/proxy/network/integration/v1/settings',
                '/proxy/network/api/s/default/rest/setting',
                '/api/s/default/rest/setting'
            ]
            
            for config_endpoint in config_endpoints:
                try:
                    url = urljoin(endpoint, config_endpoint)
                    async with self.session.get(url, headers=headers, auth=auth) as resp:
                        if resp.status == 200:
                            return await resp.json()
                except Exception as e:
                    continue
            
            return {}
            
        except Exception as e:
            logger.error("Error getting UCG configuration", endpoint=endpoint, error=str(e))
            return {}
    
    async def get_system_status(self, endpoint: str) -> Dict:
        """Get UCG system status"""
        try:
            if endpoint not in self._authenticated_endpoints:
                return {}
            
            auth_info = self._authenticated_endpoints[endpoint]
            headers = auth_info.get('headers', {})
            auth = auth_info.get('auth')
            
            status_endpoints = [
                '/api/v1/status',
                '/api/status',
                '/api/system/status',
                '/cgi-bin/status',
                # UniFi specific endpoints
                '/proxy/network/integration/v1/sites',
                '/proxy/network/api/s/default/stat/sysinfo',
                '/api/s/default/stat/sysinfo'
            ]
            
            for status_endpoint in status_endpoints:
                try:
                    url = urljoin(endpoint, status_endpoint)
                    async with self.session.get(url, headers=headers, auth=auth) as resp:
                        if resp.status == 200:
                            return await resp.json()
                except Exception as e:
                    continue
            
            return {}
            
        except Exception as e:
            logger.error("Error getting system status", endpoint=endpoint, error=str(e))
            return {}
    
    async def poll_all_endpoints(self) -> Dict:
        """Poll all configured UCG endpoints for certificates"""
        results = {
            'certificates': [],
            'configurations': {},
            'statuses': {},
            'errors': []
        }
        
        tasks = []
        for endpoint in self.api_endpoints:
            if endpoint in self._authenticated_endpoints:
                tasks.append(self._poll_endpoint(endpoint))
        
        if tasks:
            endpoint_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(endpoint_results):
                endpoint = self.api_endpoints[i]
                if isinstance(result, Exception):
                    results['errors'].append({'endpoint': endpoint, 'error': str(result)})
                else:
                    results['certificates'].extend(result.get('certificates', []))
                    results['configurations'][endpoint] = result.get('configuration', {})
                    results['statuses'][endpoint] = result.get('status', {})
        
        return results
    
    async def _poll_endpoint(self, endpoint: str) -> Dict:
        """Poll a single endpoint for all information"""
        result = {
            'certificates': [],
            'configuration': {},
            'status': {}
        }
        
        try:
            # Get certificates
            result['certificates'] = await self.get_device_certificates(endpoint)
            
            # Get configuration
            result['configuration'] = await self.get_ucg_configuration(endpoint)
            
            # Get status
            result['status'] = await self.get_system_status(endpoint)
            
            logger.info("Polled UCG endpoint successfully", 
                       endpoint=endpoint,
                       certificates=len(result['certificates']))
            
        except Exception as e:
            logger.error("Error polling endpoint", endpoint=endpoint, error=str(e))
            raise
        
        return result


class UCGDiscovery:
    """Discover UCG devices on the network"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.network_ranges = config.get('ucg', {}).get('discovery_ranges', ['192.168.1.0/24'])
        self.common_ports = [80, 443, 8080, 8443, 9000]
        self.ucg_indicators = [
            'ucg', 'gateway', 'modem', 'router',
            'technicolor', 'vantiva', 'sagemcom',
            'arris', 'cisco', 'motorola'
        ]
    
    async def discover_ucg_devices(self) -> List[Dict]:
        """Discover UCG devices on the network"""
        discovered_devices = []
        
        for network_range in self.network_ranges:
            try:
                import ipaddress
                network = ipaddress.ip_network(network_range)
                
                # Create tasks for scanning hosts
                tasks = []
                for host in network.hosts():
                    task = asyncio.create_task(self._scan_host(str(host)))
                    tasks.append(task)
                
                # Execute scans with reasonable concurrency
                results = []
                for i in range(0, len(tasks), 50):  # Process in batches of 50
                    batch = tasks[i:i+50]
                    batch_results = await asyncio.gather(*batch, return_exceptions=True)
                    results.extend([r for r in batch_results if not isinstance(r, Exception) and r])
                
                discovered_devices.extend(results)
                
            except Exception as e:
                logger.error("Error discovering devices in range", 
                           network_range=network_range, error=str(e))
        
        logger.info("UCG discovery completed", discovered=len(discovered_devices))
        return discovered_devices
    
    async def _scan_host(self, host: str) -> Optional[Dict]:
        """Scan a single host for UCG indicators"""
        for port in self.common_ports:
            try:
                # Check if port is open
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                
                # Try to get HTTP response
                device_info = await self._identify_ucg_device(host, port)
                if device_info:
                    return device_info
                    
            except Exception:
                continue
        
        return None
    
    async def _identify_ucg_device(self, host: str, port: int) -> Optional[Dict]:
        """Try to identify if device is a UCG"""
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{host}:{port}"
            
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5),
                connector=aiohttp.TCPConnector(verify_ssl=False)
            ) as session:
                
                # Try common UCG paths
                paths = ['/', '/api/status', '/cgi-bin/status', '/api/v1/info']
                
                for path in paths:
                    try:
                        async with session.get(f"{base_url}{path}") as resp:
                            if resp.status == 200:
                                content = await resp.text()
                                headers = dict(resp.headers)
                                
                                # Check for UCG indicators
                                if self._is_ucg_device(content, headers):
                                    return {
                                        'host': host,
                                        'port': port,
                                        'base_url': base_url,
                                        'device_type': self._identify_device_type(content, headers),
                                        'discovered_at': datetime.now()
                                    }
                    except Exception:
                        continue
            
        except Exception as e:
            logger.debug("Error identifying device", host=host, port=port, error=str(e))
        
        return None
    
    def _is_ucg_device(self, content: str, headers: Dict) -> bool:
        """Check if response indicates UCG device"""
        content_lower = content.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Check content for UCG indicators
        for indicator in self.ucg_indicators:
            if indicator in content_lower:
                return True
        
        # Check headers
        server = headers_lower.get('server', '')
        for indicator in self.ucg_indicators:
            if indicator in server:
                return True
        
        # Check for common UCG endpoints in content
        ucg_endpoints = ['/api/certificates', '/cgi-bin/config', '/api/v1/status']
        for endpoint in ucg_endpoints:
            if endpoint in content_lower:
                return True
        
        return False
    
    def _identify_device_type(self, content: str, headers: Dict) -> str:
        """Try to identify specific UCG device type"""
        content_lower = content.lower()
        
        if 'technicolor' in content_lower:
            return 'technicolor'
        elif 'vantiva' in content_lower:
            return 'vantiva'
        elif 'sagemcom' in content_lower:
            return 'sagemcom'
        elif 'arris' in content_lower:
            return 'arris'
        elif 'cisco' in content_lower:
            return 'cisco'
        elif 'motorola' in content_lower:
            return 'motorola'
        else:
            return 'unknown_ucg'


class UCGCertificatePoller:
    """Continuous polling service for UCG certificates"""
    
    def __init__(self, config: Dict, certificate_callback: Optional[callable] = None):
        self.config = config
        self.certificate_callback = certificate_callback
        self.api_client = UCGAPIClient(config)
        self.running = False
        self.poll_task = None
    
    async def start_polling(self):
        """Start continuous polling"""
        if self.running:
            return
        
        self.running = True
        await self.api_client.initialize()
        
        self.poll_task = asyncio.create_task(self._polling_loop())
        logger.info("UCG certificate polling started")
    
    async def stop_polling(self):
        """Stop polling"""
        self.running = False
        if self.poll_task:
            self.poll_task.cancel()
            try:
                await self.poll_task
            except asyncio.CancelledError:
                pass
        
        await self.api_client.close()
        logger.info("UCG certificate polling stopped")
    
    async def _polling_loop(self):
        """Main polling loop"""
        while self.running:
            try:
                results = await self.api_client.poll_all_endpoints()
                
                # Process certificates
                for cert_info in results['certificates']:
                    if self.certificate_callback:
                        self.certificate_callback(cert_info)
                
                # Log results
                logger.info("UCG polling completed",
                           certificates=len(results['certificates']),
                           errors=len(results['errors']))
                
                if results['errors']:
                    for error in results['errors']:
                        logger.warning("UCG polling error", **error)
                
                # Wait for next poll
                await asyncio.sleep(self.api_client.polling_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in polling loop", error=str(e))
                await asyncio.sleep(60)  # Wait before retrying


if __name__ == "__main__":
    # Example usage
    import yaml
    
    async def test_ucg_client():
        # Load configuration
        with open('../config/config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        
        # Test discovery
        discovery = UCGDiscovery(config)
        devices = await discovery.discover_ucg_devices()
        print(f"Discovered {len(devices)} UCG devices")
        
        # Test API client
        api_client = UCGAPIClient(config)
        await api_client.initialize()
        
        results = await api_client.poll_all_endpoints()
        print(f"Retrieved {len(results['certificates'])} certificates")
        
        await api_client.close()
    
    # Run test
    asyncio.run(test_ucg_client())
