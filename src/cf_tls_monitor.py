#!/usr/bin/env python3
"""
Cloudflare Zero Trust TLS Inspection Monitor
Integrates with existing certificate monitoring to track TLS policy violations
"""

import os
import sys
import json
import time
import requests
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from src.certificate_monitor import CertificateMonitor
except ImportError:
    # Mock certificate monitor if not available
    class CertificateMonitor:
        def __init__(self):
            pass

@dataclass
class TLSPolicyViolation:
    """TLS policy violation event"""
    timestamp: str
    policy_name: str
    action: str
    source_ip: str
    destination: str
    certificate_issuer: str
    certificate_subject: str
    violation_type: str
    blocked: bool
    user_agent: Optional[str] = None
    referer: Optional[str] = None

@dataclass
class CertificateInspectionEvent:
    """Certificate inspection event"""
    timestamp: str
    host: str
    certificate_fingerprint: str
    certificate_issuer: str
    certificate_subject: str
    certificate_valid_from: str
    certificate_valid_to: str
    certificate_status: str
    tls_version: str
    cipher_suite: str
    inspection_result: str

class CloudflareTLSMonitor:
    def __init__(self, account_id: str = None, api_token: str = None):
        self.account_id = account_id or os.getenv("CLOUDFLARE_ACCOUNT_ID")
        self.api_token = api_token or os.getenv("CLOUDFLARE_API_TOKEN")
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.setup_logging()
        
        if not self.account_id or not self.api_token:
            self.logger.warning("Cloudflare credentials not found. Monitoring will be limited.")
            
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        } if self.api_token else {}
        
        # Integration with existing certificate monitor
        self.cert_monitor = CertificateMonitor()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cf_tls_monitor.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def get_gateway_logs(self, start_time: datetime = None, end_time: datetime = None) -> List[Dict]:
        """Fetch Gateway logs from Cloudflare API"""
        if not self.account_id or not self.api_token:
            self.logger.error("Cloudflare credentials required for API access")
            return []
            
        if not start_time:
            start_time = datetime.now() - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now()
            
        url = f"{self.base_url}/accounts/{self.account_id}/gateway/logs"
        
        params = {
            "start": start_time.isoformat(),
            "end": end_time.isoformat(),
            "per_page": 1000
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            
            data = response.json()
            return data.get("result", [])
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch Gateway logs: {e}")
            return []
            
    def parse_tls_events(self, logs: List[Dict]) -> List[TLSPolicyViolation]:
        """Parse TLS-related events from Gateway logs"""
        violations = []
        
        for log_entry in logs:
            # Check if this is a TLS/certificate related event
            if not self._is_tls_event(log_entry):
                continue
                
            try:
                violation = TLSPolicyViolation(
                    timestamp=log_entry.get("timestamp", ""),
                    policy_name=log_entry.get("rule_name", "Unknown"),
                    action=log_entry.get("action", "unknown"),
                    source_ip=log_entry.get("source_ip", ""),
                    destination=log_entry.get("destination", ""),
                    certificate_issuer=log_entry.get("tls", {}).get("certificate_issuer", ""),
                    certificate_subject=log_entry.get("tls", {}).get("certificate_subject", ""),
                    violation_type=self._determine_violation_type(log_entry),
                    blocked=log_entry.get("action") == "block",
                    user_agent=log_entry.get("user_agent"),
                    referer=log_entry.get("referer")
                )
                violations.append(violation)
                
            except Exception as e:
                self.logger.warning(f"Failed to parse log entry: {e}")
                continue
                
        return violations
        
    def _is_tls_event(self, log_entry: Dict) -> bool:
        """Determine if log entry is TLS/certificate related"""
        tls_indicators = [
            "ssl", "tls", "certificate", "cipher", "handshake",
            "expired", "invalid", "self-signed", "revoked"
        ]
        
        # Check rule name
        rule_name = log_entry.get("rule_name", "").lower()
        if any(indicator in rule_name for indicator in tls_indicators):
            return True
            
        # Check if TLS data is present
        if log_entry.get("tls"):
            return True
            
        # Check blocked reason
        block_reason = log_entry.get("block_reason", "").lower()
        if any(indicator in block_reason for indicator in tls_indicators):
            return True
            
        return False
        
    def _determine_violation_type(self, log_entry: Dict) -> str:
        """Determine the type of TLS violation"""
        rule_name = log_entry.get("rule_name", "").lower()
        block_reason = log_entry.get("block_reason", "").lower()
        
        violation_mapping = {
            "invalid": "Invalid Certificate",
            "expired": "Expired Certificate", 
            "self-signed": "Self-Signed Certificate",
            "revoked": "Revoked Certificate",
            "weak": "Weak Encryption",
            "untrusted": "Untrusted CA",
            "ct": "Certificate Transparency",
            "hsts": "HSTS Violation",
            "mixed": "Mixed Content"
        }
        
        for key, violation_type in violation_mapping.items():
            if key in rule_name or key in block_reason:
                return violation_type
                
        return "Other TLS Violation"
        
    def get_certificate_inspection_events(self, start_time: datetime = None) -> List[CertificateInspectionEvent]:
        """Get detailed certificate inspection events"""
        logs = self.get_gateway_logs(start_time)
        inspection_events = []
        
        for log_entry in logs:
            tls_data = log_entry.get("tls", {})
            if not tls_data:
                continue
                
            try:
                event = CertificateInspectionEvent(
                    timestamp=log_entry.get("timestamp", ""),
                    host=log_entry.get("destination", ""),
                    certificate_fingerprint=tls_data.get("certificate_fingerprint", ""),
                    certificate_issuer=tls_data.get("certificate_issuer", ""),
                    certificate_subject=tls_data.get("certificate_subject", ""),
                    certificate_valid_from=tls_data.get("certificate_valid_from", ""),
                    certificate_valid_to=tls_data.get("certificate_valid_to", ""),
                    certificate_status=tls_data.get("certificate_status", ""),
                    tls_version=tls_data.get("version", ""),
                    cipher_suite=tls_data.get("cipher_suite", ""),
                    inspection_result=log_entry.get("action", "")
                )
                inspection_events.append(event)
                
            except Exception as e:
                self.logger.warning(f"Failed to parse inspection event: {e}")
                continue
                
        return inspection_events
        
    def integrate_with_cert_monitor(self, violations: List[TLSPolicyViolation]):
        """Integrate TLS violations with existing certificate monitoring"""
        for violation in violations:
            if violation.certificate_subject and violation.blocked:
                # Create a certificate event for the monitoring system
                cert_event = {
                    "timestamp": violation.timestamp,
                    "event_type": "tls_policy_violation",
                    "host": violation.destination,
                    "certificate_subject": violation.certificate_subject,
                    "certificate_issuer": violation.certificate_issuer,
                    "violation_type": violation.violation_type,
                    "policy_name": violation.policy_name,
                    "action": violation.action,
                    "source_ip": violation.source_ip
                }
                
                # Add to existing monitoring data
                self._store_violation_event(cert_event)
                
    def _store_violation_event(self, event: Dict):
        """Store violation event in monitoring system"""
        # Create violations directory if it doesn't exist
        violations_dir = "data/tls_violations"
        os.makedirs(violations_dir, exist_ok=True)
        
        # Store as JSONL for easy processing
        violations_file = f"{violations_dir}/violations_{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        
        with open(violations_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
            
    def generate_violation_report(self, start_time: datetime = None) -> Dict[str, Any]:
        """Generate a comprehensive violation report"""
        if not start_time:
            start_time = datetime.now() - timedelta(days=1)
            
        violations = self.parse_tls_events(self.get_gateway_logs(start_time))
        inspection_events = self.get_certificate_inspection_events(start_time)
        
        # Analyze violations
        violation_stats = {
            "total_violations": len(violations),
            "blocked_connections": len([v for v in violations if v.blocked]),
            "violation_types": {},
            "top_destinations": {},
            "policy_triggers": {}
        }
        
        for violation in violations:
            # Count by violation type
            vtype = violation.violation_type
            violation_stats["violation_types"][vtype] = violation_stats["violation_types"].get(vtype, 0) + 1
            
            # Count by destination
            dest = violation.destination
            violation_stats["top_destinations"][dest] = violation_stats["top_destinations"].get(dest, 0) + 1
            
            # Count by policy
            policy = violation.policy_name
            violation_stats["policy_triggers"][policy] = violation_stats["policy_triggers"].get(policy, 0) + 1
            
        # Certificate inspection stats
        inspection_stats = {
            "total_inspections": len(inspection_events),
            "unique_certificates": len(set(e.certificate_fingerprint for e in inspection_events if e.certificate_fingerprint)),
            "certificate_authorities": list(set(e.certificate_issuer for e in inspection_events if e.certificate_issuer)),
            "tls_versions": {},
            "cipher_suites": set()
        }
        
        for event in inspection_events:
            if event.tls_version:
                inspection_stats["tls_versions"][event.tls_version] = inspection_stats["tls_versions"].get(event.tls_version, 0) + 1
            if event.cipher_suite:
                inspection_stats["cipher_suites"].add(event.cipher_suite)
                
        # Convert set to list for JSON serialization
        inspection_stats["cipher_suites"] = list(inspection_stats["cipher_suites"])
        
        report = {
            "report_generated": datetime.now().isoformat(),
            "time_period": {
                "start": start_time.isoformat(),
                "end": datetime.now().isoformat()
            },
            "violation_summary": violation_stats,
            "inspection_summary": inspection_stats,
            "recommendations": self._generate_recommendations(violation_stats, inspection_stats)
        }
        
        # Save report
        report_file = f"reports/tls_violation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs("reports", exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        self.logger.info(f"TLS violation report saved to {report_file}")
        return report
        
    def _generate_recommendations(self, violation_stats: Dict, inspection_stats: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if violation_stats["total_violations"] > 100:
            recommendations.append("High number of TLS violations detected. Consider reviewing and tightening policies.")
            
        # Check for expired certificates
        if "Expired Certificate" in violation_stats["violation_types"]:
            recommendations.append("Expired certificates detected. Implement automated certificate renewal.")
            
        # Check for weak encryption
        if "Weak Encryption" in violation_stats["violation_types"]:
            recommendations.append("Weak encryption detected. Block legacy TLS versions and cipher suites.")
            
        # Check for self-signed certificates
        if "Self-Signed Certificate" in violation_stats["violation_types"]:
            recommendations.append("Self-signed certificates in use. Consider implementing proper CA infrastructure.")
            
        # Check TLS versions
        weak_tls = [v for v in inspection_stats.get("tls_versions", {}).keys() 
                   if v in ["TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]]
        if weak_tls:
            recommendations.append(f"Legacy TLS versions detected: {', '.join(weak_tls)}. Upgrade to TLS 1.2 or higher.")
            
        # Check for too many CAs
        if len(inspection_stats.get("certificate_authorities", [])) > 50:
            recommendations.append("Large number of certificate authorities detected. Consider restricting to trusted CAs only.")
            
        return recommendations
        
    def monitor_continuous(self, interval_minutes: int = 15):
        """Run continuous monitoring of TLS inspection"""
        self.logger.info(f"Starting continuous TLS monitoring (interval: {interval_minutes} minutes)")
        
        try:
            while True:
                start_time = datetime.now() - timedelta(minutes=interval_minutes + 5)  # Slight overlap
                
                # Fetch and process violations
                violations = self.parse_tls_events(self.get_gateway_logs(start_time))
                
                if violations:
                    self.logger.info(f"Found {len(violations)} TLS violations in last {interval_minutes} minutes")
                    
                    # Integrate with existing monitoring
                    self.integrate_with_cert_monitor(violations)
                    
                    # Log critical violations
                    critical_violations = [v for v in violations if v.blocked and v.violation_type in [
                        "Invalid Certificate", "Expired Certificate", "Revoked Certificate"
                    ]]
                    
                    for violation in critical_violations:
                        self.logger.warning(f"CRITICAL TLS VIOLATION: {violation.violation_type} - {violation.destination}")
                        
                # Generate periodic reports
                if datetime.now().minute == 0:  # Hourly reports
                    report = self.generate_violation_report()
                    self.logger.info(f"Generated hourly report: {report['violation_summary']['total_violations']} violations")
                    
                time.sleep(interval_minutes * 60)
                
        except KeyboardInterrupt:
            self.logger.info("TLS monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Error in continuous monitoring: {e}")
            
    def test_with_mock_data(self):
        """Test monitoring with mock data when API is not available"""
        self.logger.info("Testing TLS monitoring with mock data...")
        
        mock_violations = [
            TLSPolicyViolation(
                timestamp=datetime.now().isoformat(),
                policy_name="Block Invalid SSL Certificates",
                action="block",
                source_ip="192.168.22.100",
                destination="expired.badssl.com",
                certificate_issuer="BadSSL Fake CA",
                certificate_subject="*.badssl.com",
                violation_type="Expired Certificate",
                blocked=True
            ),
            TLSPolicyViolation(
                timestamp=datetime.now().isoformat(),
                policy_name="Warn on Weak SSL/TLS",
                action="allow",
                source_ip="192.168.22.101", 
                destination="rc4.badssl.com",
                certificate_issuer="BadSSL Fake CA",
                certificate_subject="*.badssl.com",
                violation_type="Weak Encryption",
                blocked=False
            )
        ]
        
        # Process mock violations
        self.integrate_with_cert_monitor(mock_violations)
        
        # Generate test report
        violation_stats = {
            "total_violations": 2,
            "blocked_connections": 1,
            "violation_types": {"Expired Certificate": 1, "Weak Encryption": 1},
            "top_destinations": {"expired.badssl.com": 1, "rc4.badssl.com": 1},
            "policy_triggers": {"Block Invalid SSL Certificates": 1, "Warn on Weak SSL/TLS": 1}
        }
        
        inspection_stats = {
            "total_inspections": 2,
            "unique_certificates": 1,
            "certificate_authorities": ["BadSSL Fake CA"],
            "tls_versions": {"TLSv1.2": 1, "TLSv1.0": 1},
            "cipher_suites": ["ECDHE-RSA-AES256-GCM-SHA384", "RC4-SHA"]
        }
        
        test_report = {
            "report_generated": datetime.now().isoformat(),
            "test_mode": True,
            "violation_summary": violation_stats,
            "inspection_summary": inspection_stats,
            "recommendations": self._generate_recommendations(violation_stats, inspection_stats)
        }
        
        print(json.dumps(test_report, indent=2))
        return test_report

def main():
    """Main function for testing and demonstration"""
    monitor = CloudflareTLSMonitor()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        # Test with mock data
        monitor.test_with_mock_data()
        return
        
    if len(sys.argv) > 1 and sys.argv[1] == "--continuous":
        # Run continuous monitoring
        interval = int(sys.argv[2]) if len(sys.argv) > 2 else 15
        monitor.monitor_continuous(interval)
        return
        
    # Generate a one-time report
    print("Generating TLS violation report...")
    report = monitor.generate_violation_report()
    
    print(f"\n📊 TLS Monitoring Report")
    print(f"Time Period: {report['time_period']['start']} to {report['time_period']['end']}")
    print(f"Total Violations: {report['violation_summary']['total_violations']}")
    print(f"Blocked Connections: {report['violation_summary']['blocked_connections']}")
    
    if report['violation_summary']['violation_types']:
        print(f"\n🚨 Violation Types:")
        for vtype, count in report['violation_summary']['violation_types'].items():
            print(f"  - {vtype}: {count}")
            
    if report['recommendations']:
        print(f"\n💡 Recommendations:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")

if __name__ == "__main__":
    main()
