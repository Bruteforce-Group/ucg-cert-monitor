#!/usr/bin/env python3
"""
UniFi Flow Logs Client
Collects network traffic flow data from UniFi controllers for security monitoring
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

import aiohttp
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class FlowRecord:
    """Represents a network flow record"""
    timestamp: datetime
    source_mac: str
    source_ip: str
    source_hostname: Optional[str]
    device_type: str
    uplink_name: str
    network: str
    tx_bytes: int
    rx_bytes: int
    tx_packets: int
    rx_packets: int
    tx_rate: int  # bps
    rx_rate: int  # bps
    protocol: str  # wifi or wired
    channel: Optional[int]
    signal_strength: Optional[int]
    satisfaction: Optional[int]
    port_info: Optional[str]  # For TLS/SSL analysis
    has_tls_traffic: bool


@dataclass
class TrafficSummary:
    """Summary of traffic patterns for certificate monitoring"""
    timestamp: datetime
    total_flows: int
    tls_flows: int
    high_volume_flows: List[FlowRecord]
    new_devices: List[FlowRecord]
    certificate_candidates: List[FlowRecord]  # Devices likely using certificates


class UniFiFlowLogClient:
    """Client for collecting UniFi network traffic flow data"""
    
    def __init__(self, config: Dict):
        # Apply environment variable substitution
        self.config = self._substitute_env_vars(config)
        self.ucg_config = self.config.get('ucg', {})
        self.api_endpoints = self.ucg_config.get('api_endpoints', [])
        self.auth_config = self.ucg_config.get('auth', {})
        self.session = None
        self._authenticated_endpoints = {}
        self.flow_history = {}  # MAC -> last seen flow data
        
        # Traffic analysis settings
        self.high_volume_threshold = 100 * 1024 * 1024  # 100MB
        self.tls_ports = {443, 8443, 993, 995, 465, 587, 636, 989, 990}
        
    async def initialize(self):
        """Initialize the flow log client"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(verify_ssl=False)
        )
        
        # Authenticate with endpoints
        for endpoint in self.api_endpoints:
            try:
                if await self._authenticate_endpoint(endpoint):
                    logger.info("Flow log client authenticated", endpoint=endpoint)
                else:
                    logger.warning("Flow log client authentication failed", endpoint=endpoint)
            except Exception as e:
                logger.error("Flow log authentication error", endpoint=endpoint, error=str(e))
    
    async def close(self):
        """Close the client session"""
        if self.session:
            await self.session.close()
    
    async def _authenticate_endpoint(self, endpoint: str) -> bool:
        """Authenticate with UniFi endpoint"""
        try:
            headers = {
                'X-API-KEY': self.auth_config.get('api_key'),
                'Accept': 'application/json'
            }
            
            # Test authentication with sites endpoint
            async with self.session.get(
                f"{endpoint}/proxy/network/integration/v1/sites",
                headers=headers
            ) as resp:
                if resp.status == 200:
                    self._authenticated_endpoints[endpoint] = {'headers': headers}
                    return True
        except Exception as e:
            logger.debug("Flow log authentication failed", endpoint=endpoint, error=str(e))
        
        return False
    
    async def collect_flow_logs(self, endpoint: str) -> List[FlowRecord]:
        """Collect network flow data from UniFi endpoint"""
        if endpoint not in self._authenticated_endpoints:
            logger.warning("Endpoint not authenticated for flow logs", endpoint=endpoint)
            return []
        
        flow_records = []
        auth_info = self._authenticated_endpoints[endpoint]
        headers = auth_info['headers']
        
        try:
            # Get station data (connected devices)
            async with self.session.get(
                f"{endpoint}/proxy/network/api/s/default/stat/sta",
                headers=headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stations = data.get('data', [])
                    
                    for station in stations:
                        flow_record = self._parse_station_to_flow(station)
                        if flow_record:
                            flow_records.append(flow_record)
                            
                    logger.info("Collected flow records", endpoint=endpoint, count=len(flow_records))
                else:
                    logger.warning("Failed to get station data", endpoint=endpoint, status=resp.status)
                    
        except Exception as e:
            logger.error("Error collecting flow logs", endpoint=endpoint, error=str(e))
        
        return flow_records
    
    def _parse_station_to_flow(self, station: Dict) -> Optional[FlowRecord]:
        """Convert UniFi station data to flow record"""
        try:
            mac = station.get('mac', '')
            if not mac:
                return None
            
            # Detect if this device likely uses TLS/certificates
            has_tls = self._analyze_tls_usage(station)
            
            # Calculate traffic rates
            current_time = datetime.now()
            tx_rate, rx_rate = self._calculate_rates(mac, station, current_time)
            
            flow_record = FlowRecord(
                timestamp=current_time,
                source_mac=mac,
                source_ip=station.get('ip', station.get('last_ip', '')),
                source_hostname=station.get('hostname', ''),
                device_type=self._get_device_type(station),
                uplink_name=station.get('last_uplink_name', 'unknown'),
                network=station.get('network', station.get('last_connection_network_name', 'unknown')),
                tx_bytes=station.get('tx_bytes', station.get('wired-tx_bytes', 0)),
                rx_bytes=station.get('rx_bytes', station.get('wired-rx_bytes', 0)),
                tx_packets=station.get('tx_packets', station.get('wired-tx_packets', 0)),
                rx_packets=station.get('rx_packets', station.get('wired-rx_packets', 0)),
                tx_rate=tx_rate,
                rx_rate=rx_rate,
                protocol='wired' if station.get('is_wired') else 'wifi',
                channel=station.get('channel'),
                signal_strength=station.get('signal'),
                satisfaction=station.get('satisfaction'),
                port_info=self._analyze_port_usage(station),
                has_tls_traffic=has_tls
            )
            
            return flow_record
            
        except Exception as e:
            logger.error("Error parsing station to flow", error=str(e), mac=station.get('mac'))
            return None
    
    def _analyze_tls_usage(self, station: Dict) -> bool:
        """Analyze if device likely uses TLS/certificates"""
        # Check device characteristics that suggest TLS usage
        hostname = station.get('hostname', '').lower()
        device_type = station.get('dev_cat', 0)
        confidence = station.get('confidence', 0)
        
        # High confidence devices are more likely to use proper TLS
        if confidence >= 80:
            return True
            
        # Web servers, cameras, IoT hubs often use certificates
        tls_device_categories = {47, 49, 63, 144, 147}  # Apple TV, servers, IoT devices, etc.
        if device_type in tls_device_categories:
            return True
            
        # Devices with server-like hostnames
        server_indicators = ['server', 'camera', 'hub', 'gateway', 'nvr', 'nas']
        if any(indicator in hostname for indicator in server_indicators):
            return True
            
        # High traffic volume often indicates TLS usage
        tx_bytes = station.get('tx_bytes', station.get('wired-tx_bytes', 0))
        rx_bytes = station.get('rx_bytes', station.get('wired-rx_bytes', 0))
        total_bytes = tx_bytes + rx_bytes
        
        if total_bytes > self.high_volume_threshold:
            return True
            
        return False
    
    def _get_device_type(self, station: Dict) -> str:
        """Get human-readable device type"""
        device_categories = {
            1: 'Computer',
            41: 'IoT Device', 
            44: 'Mobile Device',
            47: 'Media Player',
            49: 'Server',
            53: 'Smart Home',
            63: 'Climate Control',
            67: 'Vehicle',
            144: 'Hub/Gateway',
            146: 'Printer',
            147: 'Security Device'
        }
        
        dev_cat = station.get('dev_cat', 0)
        base_type = device_categories.get(dev_cat, 'Unknown')
        
        # Add vendor info if available
        vendor = station.get('oui', '')
        if vendor:
            return f"{base_type} ({vendor})"
        
        return base_type
    
    def _calculate_rates(self, mac: str, station: Dict, current_time: datetime) -> Tuple[int, int]:
        """Calculate traffic rates (bytes per second)"""
        tx_bytes = station.get('tx_bytes', station.get('wired-tx_bytes', 0))
        rx_bytes = station.get('rx_bytes', station.get('wired-rx_bytes', 0))
        
        if mac not in self.flow_history:
            # First time seeing this device
            self.flow_history[mac] = {
                'last_seen': current_time,
                'last_tx_bytes': tx_bytes,
                'last_rx_bytes': rx_bytes
            }
            return 0, 0
        
        # Calculate rates based on previous measurement
        history = self.flow_history[mac]
        time_diff = (current_time - history['last_seen']).total_seconds()
        
        if time_diff <= 0:
            return 0, 0
        
        tx_diff = max(0, tx_bytes - history['last_tx_bytes'])
        rx_diff = max(0, rx_bytes - history['last_rx_bytes'])
        
        tx_rate = int(tx_diff / time_diff) if time_diff > 0 else 0
        rx_rate = int(rx_diff / time_diff) if time_diff > 0 else 0
        
        # Update history
        history.update({
            'last_seen': current_time,
            'last_tx_bytes': tx_bytes,
            'last_rx_bytes': rx_bytes
        })
        
        return tx_rate, rx_rate
    
    def _analyze_port_usage(self, station: Dict) -> Optional[str]:
        """Analyze potential port usage for certificate monitoring"""
        # For now, we can infer from device type and traffic patterns
        device_type = station.get('dev_cat', 0)
        
        if device_type == 49:  # Server
            return "443,80,8080,8443"
        elif device_type in {144, 147}:  # Hub/Gateway, Security
            return "443,8443,993,995"
        elif device_type == 47:  # Media Player  
            return "443,80"
        
        return None
    
    async def analyze_traffic_patterns(self, flow_records: List[FlowRecord]) -> TrafficSummary:
        """Analyze traffic patterns for certificate monitoring insights"""
        current_time = datetime.now()
        
        # Identify interesting flows
        tls_flows = [f for f in flow_records if f.has_tls_traffic]
        high_volume_flows = [f for f in flow_records if (f.tx_bytes + f.rx_bytes) > self.high_volume_threshold]
        
        # Identify new devices (first time seen)
        new_devices = []
        for flow in flow_records:
            if flow.source_mac not in self.flow_history:
                new_devices.append(flow)
        
        # Identify certificate candidates (devices likely to use certificates)
        certificate_candidates = []
        for flow in flow_records:
            if (flow.has_tls_traffic and 
                (flow.satisfaction is None or flow.satisfaction >= 80) and
                (flow.tx_bytes + f.rx_bytes) > 1024 * 1024):  # > 1MB traffic
                certificate_candidates.append(flow)
        
        return TrafficSummary(
            timestamp=current_time,
            total_flows=len(flow_records),
            tls_flows=len(tls_flows),
            high_volume_flows=high_volume_flows[:10],  # Top 10
            new_devices=new_devices,
            certificate_candidates=certificate_candidates
        )
    
    async def get_tls_certificate_candidates(self) -> List[Dict]:
        """Get devices that are likely using TLS certificates"""
        all_flows = []
        
        for endpoint in self._authenticated_endpoints.keys():
            flows = await self.collect_flow_logs(endpoint)
            all_flows.extend(flows)
        
        # Filter for certificate candidates
        candidates = []
        for flow in all_flows:
            if flow.has_tls_traffic and flow.source_ip:
                candidate = {
                    'hostname': flow.source_hostname or flow.source_ip,
                    'ip_address': flow.source_ip,
                    'mac_address': flow.source_mac,
                    'device_type': flow.device_type,
                    'traffic_volume': flow.tx_bytes + flow.rx_bytes,
                    'network': flow.network,
                    'confidence_score': self._calculate_certificate_confidence(flow),
                    'suggested_ports': [443, 8443] if flow.port_info else [443],
                    'last_seen': flow.timestamp
                }
                candidates.append(candidate)
        
        # Sort by confidence score
        candidates.sort(key=lambda x: x['confidence_score'], reverse=True)
        
        return candidates
    
    def _calculate_certificate_confidence(self, flow: FlowRecord) -> int:
        """Calculate confidence that device uses certificates (0-100)"""
        score = 0
        
        # Base score for TLS indication
        if flow.has_tls_traffic:
            score += 40
        
        # Traffic volume indicates active usage
        total_bytes = flow.tx_bytes + flow.rx_bytes
        if total_bytes > 100 * 1024 * 1024:  # > 100MB
            score += 30
        elif total_bytes > 10 * 1024 * 1024:  # > 10MB
            score += 20
        elif total_bytes > 1 * 1024 * 1024:  # > 1MB
            score += 10
        
        # Device satisfaction (network performance)
        if flow.satisfaction and flow.satisfaction >= 90:
            score += 15
        elif flow.satisfaction and flow.satisfaction >= 70:
            score += 10
        
        # Device type confidence
        if 'Server' in flow.device_type or 'Hub' in flow.device_type:
            score += 15
        elif 'Media Player' in flow.device_type:
            score += 10
        
        return min(100, score)
    
    def _substitute_env_vars(self, config: Dict) -> Dict:
        """Substitute environment variables in configuration"""
        import os
        import re
        
        def substitute_value(value):
            if isinstance(value, str):
                # Replace ${VAR} with environment variable
                def replace_env(match):
                    var_name = match.group(1)
                    return os.getenv(var_name, match.group(0))
                
                return re.sub(r'\$\{([^}]+)\}', replace_env, value)
            elif isinstance(value, dict):
                return {k: substitute_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [substitute_value(item) for item in value]
            else:
                return value
        
        return substitute_value(config)


async def main():
    """Example usage"""
    import yaml
    from dotenv import load_dotenv
    
    # Load configuration
    load_dotenv('.env')
    
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Initialize flow log client
    client = UniFiFlowLogClient(config)
    
    try:
        await client.initialize()
        
        # Get certificate candidates
        candidates = await client.get_tls_certificate_candidates()
        
        print(f"Found {len(candidates)} potential certificate-using devices:")
        for candidate in candidates[:10]:  # Top 10
            print(f"  - {candidate['hostname']} ({candidate['ip_address']})")
            print(f"    Device: {candidate['device_type']}")
            print(f"    Traffic: {candidate['traffic_volume']:,} bytes")
            print(f"    Confidence: {candidate['confidence_score']}%")
            print()
            
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
