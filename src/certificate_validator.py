#!/usr/bin/env python3
"""
UCG Certificate Monitor - Certificate Validation Engine
Validates certificates against baselines and detects anomalies
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import structlog

logger = structlog.get_logger(__name__)


class AlertType(Enum):
    """Types of certificate alerts"""
    ISSUER_MISMATCH = "issuer_mismatch"
    FINGERPRINT_CHANGE = "fingerprint_change" 
    EXPIRY_SOON = "expiry_soon"
    EXPIRED = "expired"
    UNKNOWN_CERTIFICATE = "unknown_certificate"
    WEAK_SIGNATURE = "weak_signature"
    REVOKED = "revoked"
    SUBJECT_MISMATCH = "subject_mismatch"
    INVALID_CHAIN = "invalid_chain"


@dataclass
class CertificateAlert:
    """Certificate alert information"""
    alert_type: AlertType
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    message: str
    certificate_info: Dict
    baseline_info: Optional[Dict] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class CertificateValidator:
    """Validates certificates against baselines and security policies"""
    
    def __init__(self, config: Dict, db_path: str = None):
        self.config = config
        self.db_path = db_path or config.get('database', {}).get('path', 'data/cert_monitor.db')
        self.validation_rules = config.get('certificates', {}).get('validation_rules', {})
        self.alert_rules = config.get('certificates', {}).get('alert_on', [])
        self.expiry_warning_days = config.get('certificates', {}).get('expiry_warning_days', 30)
        
        # Weak signature algorithms to flag
        self.weak_signatures = {
            'md5WithRSAEncryption',
            'sha1WithRSAEncryption', 
            'md2WithRSAEncryption',
            'md4WithRSAEncryption'
        }
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize certificate database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create baseline certificates table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS baseline_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    serial_number TEXT NOT NULL,
                    signature_algorithm TEXT NOT NULL,
                    certificate_der BLOB NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    UNIQUE(host, port, fingerprint_sha256)
                )
            ''')
            
            # Create certificate history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS certificate_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    captured_timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    validation_status TEXT,
                    alerts TEXT
                )
            ''')
            
            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS certificate_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    certificate_fingerprint TEXT NOT NULL,
                    host TEXT,
                    port INTEGER,
                    timestamp TEXT NOT NULL,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    certificate_data TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info("Certificate database initialized", path=self.db_path)
            
        except Exception as e:
            logger.error("Failed to initialize database", error=str(e))
            raise
    
    def add_baseline_certificate(self, cert_info: Dict) -> bool:
        """Add or update baseline certificate"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if certificate already exists
            cursor.execute('''
                SELECT id FROM baseline_certificates 
                WHERE host = ? AND port = ? AND fingerprint_sha256 = ?
            ''', (cert_info.get('host', ''), cert_info.get('port', 0), 
                  cert_info['fingerprint_sha256']))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update last_seen timestamp
                cursor.execute('''
                    UPDATE baseline_certificates 
                    SET last_seen = ? 
                    WHERE id = ?
                ''', (datetime.now().isoformat(), existing[0]))
            else:
                # Insert new baseline certificate
                cursor.execute('''
                    INSERT INTO baseline_certificates 
                    (host, port, fingerprint_sha256, subject, issuer, not_before, 
                     not_after, serial_number, signature_algorithm, certificate_der, 
                     first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cert_info.get('host', ''),
                    cert_info.get('port', 0),
                    cert_info['fingerprint_sha256'],
                    cert_info['subject'],
                    cert_info['issuer'],
                    cert_info['not_before'].isoformat(),
                    cert_info['not_after'].isoformat(),
                    cert_info['serial_number'],
                    cert_info['signature_algorithm'],
                    cert_info.get('raw_certificate', b''),
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))
            
            conn.commit()
            conn.close()
            
            logger.info("Baseline certificate updated",
                       fingerprint=cert_info['fingerprint_sha256'][:16])
            return True
            
        except Exception as e:
            logger.error("Failed to add baseline certificate", error=str(e))
            return False
    
    def validate_certificate(self, cert_info: Dict) -> Tuple[bool, List[CertificateAlert]]:
        """Validate certificate against baselines and policies"""
        alerts = []
        is_valid = True
        
        try:
            # Get baseline certificate for comparison
            baseline = self._get_baseline_certificate(
                cert_info.get('host', ''), 
                cert_info.get('port', 0)
            )
            
            # Check expiry
            expiry_alerts = self._check_certificate_expiry(cert_info)
            alerts.extend(expiry_alerts)
            
            # Check signature algorithm
            if self._check_weak_signature(cert_info):
                alerts.append(CertificateAlert(
                    AlertType.WEAK_SIGNATURE,
                    "MEDIUM",
                    f"Certificate uses weak signature algorithm: {cert_info.get('signature_algorithm', 'unknown')}",
                    cert_info
                ))
            
            if baseline:
                # Compare against baseline
                comparison_alerts = self._compare_with_baseline(cert_info, baseline)
                alerts.extend(comparison_alerts)
            else:
                # Unknown certificate
                if "unknown_certificate" in self.alert_rules:
                    alerts.append(CertificateAlert(
                        AlertType.UNKNOWN_CERTIFICATE,
                        "HIGH",
                        f"Unknown certificate detected for {cert_info.get('host', 'unknown host')}",
                        cert_info
                    ))
            
            # Record certificate in history
            self._record_certificate_history(cert_info, alerts)
            
            # Store alerts
            for alert in alerts:
                self._store_alert(alert)
            
            is_valid = len([a for a in alerts if a.severity in ['HIGH', 'CRITICAL']]) == 0
            
        except Exception as e:
            logger.error("Error validating certificate", error=str(e))
            is_valid = False
            
        return is_valid, alerts
    
    def _get_baseline_certificate(self, host: str, port: int) -> Optional[Dict]:
        """Get baseline certificate for host:port"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM baseline_certificates 
                WHERE host = ? AND port = ? AND status = 'active'
                ORDER BY last_seen DESC LIMIT 1
            ''', (host, port))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            
            return None
            
        except Exception as e:
            logger.error("Error getting baseline certificate", error=str(e))
            return None
    
    def _check_certificate_expiry(self, cert_info: Dict) -> List[CertificateAlert]:
        """Check certificate expiry and upcoming expiration"""
        alerts = []
        
        try:
            not_after = cert_info['not_after']
            now = datetime.now()
            
            # Check if expired
            if not_after < now:
                alerts.append(CertificateAlert(
                    AlertType.EXPIRED,
                    "CRITICAL",
                    f"Certificate has expired on {not_after}",
                    cert_info
                ))
            else:
                # Check if expiring soon
                days_until_expiry = (not_after - now).days
                if days_until_expiry <= self.expiry_warning_days:
                    severity = "HIGH" if days_until_expiry <= 7 else "MEDIUM"
                    alerts.append(CertificateAlert(
                        AlertType.EXPIRY_SOON,
                        severity,
                        f"Certificate expires in {days_until_expiry} days ({not_after})",
                        cert_info
                    ))
                    
        except Exception as e:
            logger.error("Error checking certificate expiry", error=str(e))
            
        return alerts
    
    def _check_weak_signature(self, cert_info: Dict) -> bool:
        """Check if certificate uses weak signature algorithm"""
        signature_alg = cert_info.get('signature_algorithm', '').lower()
        return any(weak in signature_alg for weak in self.weak_signatures)
    
    def _compare_with_baseline(self, cert_info: Dict, baseline: Dict) -> List[CertificateAlert]:
        """Compare certificate with baseline"""
        alerts = []
        
        try:
            # Check fingerprint change
            if "fingerprint_change" in self.alert_rules:
                if cert_info['fingerprint_sha256'] != baseline['fingerprint_sha256']:
                    alerts.append(CertificateAlert(
                        AlertType.FINGERPRINT_CHANGE,
                        "HIGH",
                        f"Certificate fingerprint changed from {baseline['fingerprint_sha256'][:16]} to {cert_info['fingerprint_sha256'][:16]}",
                        cert_info,
                        baseline
                    ))
            
            # Check issuer change
            if "issuer_mismatch" in self.alert_rules:
                if cert_info['issuer'] != baseline['issuer']:
                    alerts.append(CertificateAlert(
                        AlertType.ISSUER_MISMATCH,
                        "HIGH",
                        f"Certificate issuer changed from '{baseline['issuer']}' to '{cert_info['issuer']}'",
                        cert_info,
                        baseline
                    ))
            
            # Check subject change
            if cert_info['subject'] != baseline['subject']:
                alerts.append(CertificateAlert(
                    AlertType.SUBJECT_MISMATCH,
                    "MEDIUM",
                    f"Certificate subject changed from '{baseline['subject']}' to '{cert_info['subject']}'",
                    cert_info,
                    baseline
                ))
                
        except Exception as e:
            logger.error("Error comparing with baseline", error=str(e))
            
        return alerts
    
    def _record_certificate_history(self, cert_info: Dict, alerts: List[CertificateAlert]):
        """Record certificate in history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            alerts_json = json.dumps([{
                'type': alert.alert_type.value,
                'severity': alert.severity,
                'message': alert.message
            } for alert in alerts])
            
            cursor.execute('''
                INSERT INTO certificate_history 
                (host, port, fingerprint_sha256, subject, issuer, captured_timestamp,
                 source_ip, destination_ip, validation_status, alerts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cert_info.get('host', ''),
                cert_info.get('port', 0),
                cert_info['fingerprint_sha256'],
                cert_info['subject'],
                cert_info['issuer'],
                cert_info['timestamp'].isoformat(),
                cert_info.get('source_ip', ''),
                cert_info.get('destination_ip', ''),
                'valid' if len(alerts) == 0 else 'alerts',
                alerts_json
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error("Error recording certificate history", error=str(e))
    
    def _store_alert(self, alert: CertificateAlert):
        """Store alert in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO certificate_alerts 
                (alert_type, severity, message, certificate_fingerprint, 
                 host, port, timestamp, certificate_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.alert_type.value,
                alert.severity,
                alert.message,
                alert.certificate_info['fingerprint_sha256'],
                alert.certificate_info.get('host', ''),
                alert.certificate_info.get('port', 0),
                alert.timestamp.isoformat(),
                json.dumps(alert.certificate_info, default=str)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error("Error storing alert", error=str(e))
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent alerts"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since = (datetime.now() - timedelta(hours=hours)).isoformat()
            
            cursor.execute('''
                SELECT * FROM certificate_alerts 
                WHERE timestamp >= ? 
                ORDER BY timestamp DESC
            ''', (since,))
            
            columns = [desc[0] for desc in cursor.description]
            alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return alerts
            
        except Exception as e:
            logger.error("Error getting recent alerts", error=str(e))
            return []
    
    def get_certificate_statistics(self) -> Dict:
        """Get certificate monitoring statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            stats = {}
            
            # Total baseline certificates
            cursor.execute('SELECT COUNT(*) FROM baseline_certificates WHERE status = "active"')
            stats['baseline_certificates'] = cursor.fetchone()[0]
            
            # Total certificates seen in last 24 hours
            since = (datetime.now() - timedelta(hours=24)).isoformat()
            cursor.execute('SELECT COUNT(*) FROM certificate_history WHERE captured_timestamp >= ?', (since,))
            stats['certificates_24h'] = cursor.fetchone()[0]
            
            # Active alerts
            cursor.execute('SELECT COUNT(*) FROM certificate_alerts WHERE acknowledged = FALSE')
            stats['active_alerts'] = cursor.fetchone()[0]
            
            # Alert breakdown by severity
            cursor.execute('''
                SELECT severity, COUNT(*) FROM certificate_alerts 
                WHERE acknowledged = FALSE 
                GROUP BY severity
            ''')
            stats['alerts_by_severity'] = dict(cursor.fetchall())
            
            # Alert breakdown by type
            cursor.execute('''
                SELECT alert_type, COUNT(*) FROM certificate_alerts 
                WHERE acknowledged = FALSE 
                GROUP BY alert_type
            ''')
            stats['alerts_by_type'] = dict(cursor.fetchall())
            
            conn.close()
            return stats
            
        except Exception as e:
            logger.error("Error getting statistics", error=str(e))
            return {}
    
    def acknowledge_alert(self, alert_id: int) -> bool:
        """Acknowledge an alert"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE certificate_alerts 
                SET acknowledged = TRUE 
                WHERE id = ?
            ''', (alert_id,))
            
            conn.commit()
            conn.close()
            
            logger.info("Alert acknowledged", alert_id=alert_id)
            return True
            
        except Exception as e:
            logger.error("Error acknowledging alert", alert_id=alert_id, error=str(e))
            return False
    
    def import_baseline_certificates(self, certificates: List[Dict]) -> int:
        """Import multiple baseline certificates"""
        imported = 0
        for cert_info in certificates:
            if self.add_baseline_certificate(cert_info):
                imported += 1
        
        logger.info("Baseline certificates imported", count=imported)
        return imported
    
    def export_baseline_certificates(self) -> List[Dict]:
        """Export all baseline certificates"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM baseline_certificates WHERE status = "active"')
            columns = [desc[0] for desc in cursor.description]
            certificates = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            
            logger.info("Baseline certificates exported", count=len(certificates))
            return certificates
            
        except Exception as e:
            logger.error("Error exporting baseline certificates", error=str(e))
            return []


class CertificatePolicy:
    """Certificate security policy enforcement"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.minimum_key_size = config.get('security', {}).get('minimum_key_size', 2048)
        self.allowed_signature_algorithms = config.get('security', {}).get('allowed_signature_algorithms', [])
        self.trusted_cas = config.get('security', {}).get('trusted_cas', [])
        self.required_extensions = config.get('security', {}).get('required_extensions', [])
    
    def validate_certificate_policy(self, cert_info: Dict) -> List[CertificateAlert]:
        """Validate certificate against security policy"""
        alerts = []
        
        # Add policy validation logic here
        # This would include checks for:
        # - Key size requirements
        # - Allowed signature algorithms
        # - Required extensions
        # - CA trust validation
        
        return alerts


if __name__ == "__main__":
    # Example usage
    import yaml
    
    # Load configuration
    with open('../config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Create validator
    validator = CertificateValidator(config)
    
    # Example certificate info
    cert_info = {
        'host': 'example.com',
        'port': 443,
        'subject': 'CN=example.com,O=Example Corp',
        'issuer': 'CN=Example CA,O=Example CA Inc',
        'fingerprint_sha256': '1234567890abcdef' * 4,
        'signature_algorithm': 'sha256WithRSAEncryption',
        'not_before': datetime.now(),
        'not_after': datetime.now() + timedelta(days=90),
        'serial_number': '12345',
        'timestamp': datetime.now()
    }
    
    # Add as baseline
    validator.add_baseline_certificate(cert_info)
    
    # Validate certificate
    is_valid, alerts = validator.validate_certificate(cert_info)
    print(f"Certificate valid: {is_valid}")
    print(f"Alerts: {len(alerts)}")
    for alert in alerts:
        print(f"- {alert.alert_type.value}: {alert.message}")
    
    # Get statistics
    stats = validator.get_certificate_statistics()
    print(f"Statistics: {stats}")
