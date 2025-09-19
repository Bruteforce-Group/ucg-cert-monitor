#!/usr/bin/env python3
"""
Flow Logs and Certificate Monitoring Integration
Combines UniFi flow data with certificate monitoring for comprehensive security analysis
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import structlog

from unifi_flow_logs import UniFiFlowLogClient, FlowRecord
from network_monitor import PassiveCertificateCollector

logger = structlog.get_logger(__name__)


class FlowCertificateCorrelator:
    """Correlates flow log data with certificate monitoring"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.flow_client = UniFiFlowLogClient(config)
        self.cert_collector = PassiveCertificateCollector(config)
        self.correlation_history = {}
        
    async def initialize(self):
        """Initialize the correlator"""
        await self.flow_client.initialize()
        logger.info("Flow-Certificate correlator initialized")
    
    async def close(self):
        """Close the correlator"""
        await self.flow_client.close()
    
    async def discover_and_monitor_certificates(self) -> Dict:
        """Discover devices using flow logs and monitor their certificates"""
        results = {
            'flow_analysis': {},
            'certificate_discoveries': [],
            'high_value_targets': [],
            'monitoring_recommendations': []
        }
        
        try:
            # Get certificate candidates from flow analysis
            candidates = await self.flow_client.get_tls_certificate_candidates()
            logger.info("Flow analysis found certificate candidates", count=len(candidates))
            
            results['flow_analysis'] = {
                'timestamp': datetime.now(),
                'total_candidates': len(candidates),
                'high_confidence': len([c for c in candidates if c['confidence_score'] >= 80]),
                'candidates': candidates[:20]  # Top 20
            }
            
            # For high-confidence candidates, try to collect certificates
            high_confidence_candidates = [
                c for c in candidates 
                if c['confidence_score'] >= 70 and c['ip_address']
            ]
            
            certificate_results = []
            for candidate in high_confidence_candidates[:10]:  # Limit to top 10 to avoid overload
                cert_info = await self._collect_certificate_from_candidate(candidate)
                if cert_info:
                    certificate_results.append({
                        'candidate': candidate,
                        'certificate': cert_info,
                        'correlation_score': self._calculate_correlation_score(candidate, cert_info)
                    })
            
            results['certificate_discoveries'] = certificate_results
            
            # Identify high-value targets (devices with both high traffic and certificates)
            high_value_targets = self._identify_high_value_targets(certificate_results)
            results['high_value_targets'] = high_value_targets
            
            # Generate monitoring recommendations
            recommendations = self._generate_monitoring_recommendations(candidates, certificate_results)
            results['monitoring_recommendations'] = recommendations
            
            logger.info("Flow-certificate correlation completed", 
                       certificates_found=len(certificate_results),
                       high_value_targets=len(high_value_targets))
            
        except Exception as e:
            logger.error("Error in flow-certificate correlation", error=str(e))
        
        return results
    
    async def _collect_certificate_from_candidate(self, candidate: Dict) -> Optional[Dict]:
        """Try to collect certificate from a flow analysis candidate"""
        hostname = candidate['hostname']
        ip_address = candidate['ip_address']
        suggested_ports = candidate.get('suggested_ports', [443])
        
        # Try each suggested port
        for port in suggested_ports:
            try:
                # Add endpoint to collector
                self.cert_collector.add_endpoint(ip_address, port)
                
                # Collect certificates
                certificates = await self.cert_collector.collect_certificates()
                
                for cert_info in certificates:
                    if cert_info and cert_info.get('host') == ip_address:
                        logger.info("Certificate collected from flow candidate", 
                                   hostname=hostname, ip=ip_address, port=port)
                        
                        # Add flow correlation metadata
                        cert_info['flow_correlation'] = {
                            'discovered_via_flow': True,
                            'device_type': candidate['device_type'],
                            'traffic_volume': candidate['traffic_volume'],
                            'confidence_score': candidate['confidence_score'],
                            'discovery_timestamp': datetime.now()
                        }
                        
                        return cert_info
                        
            except Exception as e:
                logger.debug("Failed to collect certificate from candidate", 
                           hostname=hostname, ip=ip_address, port=port, error=str(e))
                continue
        
        return None
    
    def _calculate_correlation_score(self, candidate: Dict, cert_info: Dict) -> int:
        """Calculate how well the flow data correlates with certificate info"""
        score = 0
        
        # Base score from flow confidence
        score += min(50, candidate['confidence_score'])
        
        # Bonus for certificate validity
        if cert_info.get('not_after'):
            try:
                expiry = cert_info['not_after']
                if isinstance(expiry, str):
                    from dateutil.parser import parse
                    expiry = parse(expiry)
                
                days_to_expiry = (expiry - datetime.now()).days
                if days_to_expiry > 30:
                    score += 20
                elif days_to_expiry > 0:
                    score += 10
            except:
                pass
        
        # Bonus for subject/hostname match
        subject = cert_info.get('subject', '')
        hostname = candidate['hostname']
        if hostname and hostname.lower() in subject.lower():
            score += 15
        
        # Bonus for certificate authority trust
        issuer = cert_info.get('issuer', '')
        trusted_cas = ['Let\'s Encrypt', 'DigiCert', 'Sectigo', 'ZeroSSL', 'GlobalSign']
        if any(ca in issuer for ca in trusted_cas):
            score += 10
        
        # Traffic volume correlation
        traffic_mb = candidate['traffic_volume'] / (1024 * 1024)
        if traffic_mb > 1000:  # > 1GB
            score += 5
        
        return min(100, score)
    
    def _identify_high_value_targets(self, certificate_results: List[Dict]) -> List[Dict]:
        """Identify high-value targets for monitoring"""
        high_value = []
        
        for result in certificate_results:
            candidate = result['candidate']
            cert_info = result['certificate']
            correlation_score = result['correlation_score']
            
            # High-value criteria
            is_high_value = False
            reasons = []
            
            # High traffic volume
            if candidate['traffic_volume'] > 100 * 1024 * 1024:  # > 100MB
                is_high_value = True
                reasons.append("High traffic volume")
            
            # Server or critical infrastructure
            device_type = candidate['device_type']
            if any(keyword in device_type for keyword in ['Server', 'Hub', 'Gateway']):
                is_high_value = True
                reasons.append("Critical infrastructure")
            
            # High correlation score
            if correlation_score >= 80:
                is_high_value = True
                reasons.append("High correlation confidence")
            
            # Certificate characteristics
            if cert_info.get('issuer'):
                issuer = cert_info['issuer']
                if 'ZeroSSL' in issuer or 'DigiCert' in issuer:
                    is_high_value = True
                    reasons.append("Commercial certificate")
            
            if is_high_value:
                high_value.append({
                    'hostname': candidate['hostname'],
                    'ip_address': candidate['ip_address'],
                    'device_type': device_type,
                    'traffic_volume': candidate['traffic_volume'],
                    'certificate_subject': cert_info.get('subject', ''),
                    'certificate_issuer': cert_info.get('issuer', ''),
                    'correlation_score': correlation_score,
                    'reasons': reasons,
                    'monitoring_priority': 'HIGH' if correlation_score >= 85 else 'MEDIUM'
                })
        
        # Sort by correlation score
        high_value.sort(key=lambda x: x['correlation_score'], reverse=True)
        return high_value
    
    def _generate_monitoring_recommendations(self, candidates: List[Dict], certificate_results: List[Dict]) -> List[Dict]:
        """Generate recommendations for ongoing monitoring"""
        recommendations = []
        
        # Recommend monitoring for high-traffic devices without certificates found
        unmonitored_candidates = []
        monitored_ips = {r['candidate']['ip_address'] for r in certificate_results}
        
        for candidate in candidates:
            if (candidate['ip_address'] not in monitored_ips and 
                candidate['confidence_score'] >= 60 and
                candidate['traffic_volume'] > 10 * 1024 * 1024):  # > 10MB
                unmonitored_candidates.append(candidate)
        
        if unmonitored_candidates:
            recommendations.append({
                'type': 'monitor_unverified_devices',
                'priority': 'MEDIUM',
                'description': f'Monitor {len(unmonitored_candidates)} devices with high traffic but no certificate verification',
                'devices': unmonitored_candidates[:5],  # Top 5
                'action': 'Add to passive certificate collection'
            })
        
        # Recommend certificate expiry monitoring
        expiring_soon = []
        for result in certificate_results:
            cert_info = result['certificate']
            if cert_info.get('not_after'):
                try:
                    expiry = cert_info['not_after']
                    if isinstance(expiry, str):
                        from dateutil.parser import parse
                        expiry = parse(expiry)
                    
                    days_to_expiry = (expiry - datetime.now()).days
                    if days_to_expiry <= 30:
                        expiring_soon.append({
                            'hostname': result['candidate']['hostname'],
                            'days_to_expiry': days_to_expiry,
                            'subject': cert_info.get('subject', '')
                        })
                except:
                    pass
        
        if expiring_soon:
            recommendations.append({
                'type': 'certificate_expiry_monitoring',
                'priority': 'HIGH',
                'description': f'{len(expiring_soon)} certificates expire within 30 days',
                'certificates': expiring_soon,
                'action': 'Enable expiry alerting'
            })
        
        # Recommend baseline establishment for high-value targets
        recommendations.append({
            'type': 'establish_baselines',
            'priority': 'MEDIUM',
            'description': 'Establish certificate baselines for discovered devices',
            'action': 'Add discovered certificates to baseline for change detection',
            'count': len(certificate_results)
        })
        
        return recommendations


async def main():
    """Demo the flow-certificate integration"""
    import yaml
    from dotenv import load_dotenv
    
    # Load configuration
    load_dotenv('.env')
    
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    correlator = FlowCertificateCorrelator(config)
    
    try:
        await correlator.initialize()
        
        print("🔄 Running Flow-Certificate Correlation Analysis...")
        results = await correlator.discover_and_monitor_certificates()
        
        print(f"\n📊 Flow Analysis Results:")
        flow_analysis = results['flow_analysis']
        print(f"   Total candidates: {flow_analysis.get('total_candidates', 0)}")
        print(f"   High confidence: {flow_analysis.get('high_confidence', 0)}")
        
        print(f"\n🔐 Certificate Discovery Results:")
        cert_discoveries = results['certificate_discoveries']
        print(f"   Certificates found: {len(cert_discoveries)}")
        
        for discovery in cert_discoveries[:5]:  # Top 5
            candidate = discovery['candidate']
            cert_info = discovery['certificate']
            score = discovery['correlation_score']
            
            print(f"   - {candidate['hostname']} ({candidate['ip_address']})")
            print(f"     Certificate: {cert_info.get('subject', 'Unknown')}")
            print(f"     Correlation Score: {score}%")
        
        print(f"\n🎯 High-Value Targets:")
        high_value = results['high_value_targets']
        print(f"   Identified: {len(high_value)}")
        
        for target in high_value[:3]:  # Top 3
            print(f"   - {target['hostname']} ({target['ip_address']})")
            print(f"     Priority: {target['monitoring_priority']}")
            print(f"     Reasons: {', '.join(target['reasons'])}")
        
        print(f"\n💡 Monitoring Recommendations:")
        recommendations = results['monitoring_recommendations']
        for rec in recommendations:
            print(f"   [{rec['priority']}] {rec['description']}")
            print(f"                Action: {rec['action']}")
        
    finally:
        await correlator.close()


if __name__ == "__main__":
    asyncio.run(main())
