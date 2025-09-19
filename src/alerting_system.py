#!/usr/bin/env python3
"""
UCG Certificate Monitor - Alerting System
Real-time notifications via email, Slack, SMS, and other channels
"""

import asyncio
import json
import smtplib
import ssl
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
import queue
import threading

import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from twilio.rest import Client as TwilioClient
import structlog

from certificate_validator import CertificateAlert, AlertType

logger = structlog.get_logger(__name__)


class NotificationChannel(Enum):
    """Types of notification channels"""
    EMAIL = "email"
    SLACK = "slack"
    SMS = "sms"
    WEBHOOK = "webhook"
    TEAMS = "teams"


@dataclass
class AlertNotification:
    """Alert notification to be sent"""
    alert: CertificateAlert
    channels: List[NotificationChannel]
    priority: str = "normal"  # low, normal, high, critical
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


class AlertingSystem:
    """Central alerting system for certificate monitoring"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.alerting_config = config.get('alerting', {})
        self.enabled = self.alerting_config.get('enabled', True)
        
        # Notification queue
        self.notification_queue = queue.Queue()
        self.processing_thread = None
        self.running = False
        
        # Alert deduplication
        self.recent_alerts: Set[str] = set()
        self.dedup_window = 300  # 5 minutes
        self._last_cleanup = datetime.now()
        
        # Initialize notification channels
        self._init_channels()
    
    def _init_channels(self):
        """Initialize notification channels"""
        self.channels = {}
        
        # Email channel
        if self.alerting_config.get('channels', {}).get('email', {}).get('enabled', False):
            self.channels[NotificationChannel.EMAIL] = EmailNotifier(self.alerting_config['channels']['email'])
        
        # Slack channel
        if self.alerting_config.get('channels', {}).get('slack', {}).get('enabled', False):
            self.channels[NotificationChannel.SLACK] = SlackNotifier(self.alerting_config['channels']['slack'])
        
        # SMS channel
        if self.alerting_config.get('channels', {}).get('sms', {}).get('enabled', False):
            self.channels[NotificationChannel.SMS] = SMSNotifier(self.alerting_config['channels']['sms'])
        
        # Webhook channel
        if self.alerting_config.get('channels', {}).get('webhook', {}).get('enabled', False):
            self.channels[NotificationChannel.WEBHOOK] = WebhookNotifier(self.alerting_config['channels']['webhook'])
    
    def start(self):
        """Start the alerting system"""
        if not self.enabled:
            logger.info("Alerting system is disabled")
            return
        
        if self.running:
            logger.warning("Alerting system is already running")
            return
        
        self.running = True
        self.processing_thread = threading.Thread(target=self._process_notifications)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
        logger.info("Alerting system started")
    
    def stop(self):
        """Stop the alerting system"""
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        logger.info("Alerting system stopped")
    
    def send_alert(self, alert: CertificateAlert, channels: Optional[List[NotificationChannel]] = None):
        """Send certificate alert"""
        if not self.enabled:
            return
        
        # Determine channels based on alert severity
        if channels is None:
            channels = self._get_channels_for_alert(alert)
        
        # Check for duplicate alerts
        alert_key = self._get_alert_key(alert)
        if alert_key in self.recent_alerts:
            logger.debug("Suppressing duplicate alert", alert_key=alert_key)
            return
        
        # Add to recent alerts for deduplication
        self.recent_alerts.add(alert_key)
        
        # Create notification
        notification = AlertNotification(
            alert=alert,
            channels=channels,
            priority=self._get_priority_from_severity(alert.severity)
        )
        
        # Queue notification
        self.notification_queue.put(notification)
        
        logger.info("Alert queued for notification",
                   alert_type=alert.alert_type.value,
                   severity=alert.severity,
                   channels=[c.value for c in channels])
    
    def _process_notifications(self):
        """Process notification queue in background thread"""
        while self.running:
            try:
                # Clean up old alerts periodically
                if (datetime.now() - self._last_cleanup).seconds > self.dedup_window:
                    self._cleanup_old_alerts()
                
                # Get notification from queue
                try:
                    notification = self.notification_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Send notification
                self._send_notification(notification)
                
            except Exception as e:
                logger.error("Error processing notifications", error=str(e))
    
    def _send_notification(self, notification: AlertNotification):
        """Send individual notification"""
        success = False
        
        for channel in notification.channels:
            if channel in self.channels:
                try:
                    self.channels[channel].send_notification(notification.alert)
                    success = True
                    logger.info("Alert sent successfully",
                               channel=channel.value,
                               alert_type=notification.alert.alert_type.value)
                except Exception as e:
                    logger.error("Failed to send alert",
                               channel=channel.value,
                               error=str(e))
        
        # Retry if all channels failed
        if not success and notification.retry_count < notification.max_retries:
            notification.retry_count += 1
            # Exponential backoff
            delay = 2 ** notification.retry_count
            threading.Timer(delay, lambda: self.notification_queue.put(notification)).start()
            logger.warning("Retrying alert notification",
                          retry_count=notification.retry_count,
                          delay=delay)
    
    def _get_channels_for_alert(self, alert: CertificateAlert) -> List[NotificationChannel]:
        """Determine appropriate channels based on alert severity"""
        channels = []
        
        severity_mapping = {
            'LOW': [NotificationChannel.EMAIL],
            'MEDIUM': [NotificationChannel.EMAIL, NotificationChannel.SLACK],
            'HIGH': [NotificationChannel.EMAIL, NotificationChannel.SLACK],
            'CRITICAL': [NotificationChannel.EMAIL, NotificationChannel.SLACK, NotificationChannel.SMS]
        }
        
        for channel in severity_mapping.get(alert.severity, []):
            if channel in self.channels:
                channels.append(channel)
        
        return channels
    
    def _get_priority_from_severity(self, severity: str) -> str:
        """Convert severity to priority"""
        priority_map = {
            'LOW': 'low',
            'MEDIUM': 'normal',
            'HIGH': 'high',
            'CRITICAL': 'critical'
        }
        return priority_map.get(severity, 'normal')
    
    def _get_alert_key(self, alert: CertificateAlert) -> str:
        """Generate unique key for alert deduplication"""
        return f"{alert.alert_type.value}:{alert.certificate_info.get('fingerprint_sha256', '')[:16]}"
    
    def _cleanup_old_alerts(self):
        """Remove old alerts from deduplication set"""
        # This is a simple implementation - in production you might want
        # to track timestamps for more precise cleanup
        if len(self.recent_alerts) > 1000:
            # Clear half of the alerts when getting too many
            alerts_list = list(self.recent_alerts)
            self.recent_alerts = set(alerts_list[len(alerts_list)//2:])
        
        self._last_cleanup = datetime.now()
    
    def get_statistics(self) -> Dict:
        """Get alerting statistics"""
        return {
            'enabled': self.enabled,
            'running': self.running,
            'queued_notifications': self.notification_queue.qsize(),
            'recent_alerts': len(self.recent_alerts),
            'active_channels': len(self.channels)
        }


class EmailNotifier:
    """Email notification handler"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.smtp_server = config.get('smtp_server')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('username')
        self.password = config.get('password')
        self.from_address = config.get('from_address')
        self.to_addresses = config.get('to_addresses', [])
    
    def send_notification(self, alert: CertificateAlert):
        """Send email notification"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = self._create_subject(alert)
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.to_addresses)
            
            # Create HTML and text versions
            text_content = self._create_text_content(alert)
            html_content = self._create_html_content(alert)
            
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.username, self.password)
                server.sendmail(self.from_address, self.to_addresses, msg.as_string())
            
            logger.info("Email alert sent successfully")
            
        except Exception as e:
            logger.error("Failed to send email alert", error=str(e))
            raise
    
    def _create_subject(self, alert: CertificateAlert) -> str:
        """Create email subject"""
        host = alert.certificate_info.get('host', 'unknown')
        return f"[UCG-CERT-{alert.severity}] {alert.alert_type.value.replace('_', ' ').title()} - {host}"
    
    def _create_text_content(self, alert: CertificateAlert) -> str:
        """Create plain text email content"""
        content = f"""
UCG Certificate Monitor Alert

Alert Type: {alert.alert_type.value.replace('_', ' ').title()}
Severity: {alert.severity}
Timestamp: {alert.timestamp}

{alert.message}

Certificate Details:
- Host: {alert.certificate_info.get('host', 'unknown')}
- Port: {alert.certificate_info.get('port', 'unknown')}
- Subject: {alert.certificate_info.get('subject', 'unknown')}
- Issuer: {alert.certificate_info.get('issuer', 'unknown')}
- Fingerprint: {alert.certificate_info.get('fingerprint_sha256', 'unknown')[:32]}...
- Expires: {alert.certificate_info.get('not_after', 'unknown')}

Source: {alert.certificate_info.get('source', 'unknown')}
"""
        
        if alert.baseline_info:
            content += f"\n\nBaseline Certificate:\n"
            content += f"- Subject: {alert.baseline_info.get('subject', 'unknown')}\n"
            content += f"- Issuer: {alert.baseline_info.get('issuer', 'unknown')}\n"
            content += f"- Fingerprint: {alert.baseline_info.get('fingerprint_sha256', 'unknown')[:32]}...\n"
        
        return content.strip()
    
    def _create_html_content(self, alert: CertificateAlert) -> str:
        """Create HTML email content"""
        severity_colors = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107',
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545'
        }
        
        color = severity_colors.get(alert.severity, '#6c757d')
        
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; margin: 20px;">
            <div style="border-left: 4px solid {color}; padding-left: 20px;">
                <h2 style="color: {color};">UCG Certificate Monitor Alert</h2>
                <p><strong>Alert Type:</strong> {alert.alert_type.value.replace('_', ' ').title()}</p>
                <p><strong>Severity:</strong> <span style="color: {color};">{alert.severity}</span></p>
                <p><strong>Timestamp:</strong> {alert.timestamp}</p>
                <p><strong>Message:</strong> {alert.message}</p>
            </div>
            
            <h3>Certificate Details</h3>
            <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
                <tr><td><strong>Host</strong></td><td>{alert.certificate_info.get('host', 'unknown')}</td></tr>
                <tr><td><strong>Port</strong></td><td>{alert.certificate_info.get('port', 'unknown')}</td></tr>
                <tr><td><strong>Subject</strong></td><td>{alert.certificate_info.get('subject', 'unknown')}</td></tr>
                <tr><td><strong>Issuer</strong></td><td>{alert.certificate_info.get('issuer', 'unknown')}</td></tr>
                <tr><td><strong>Fingerprint</strong></td><td><code>{alert.certificate_info.get('fingerprint_sha256', 'unknown')[:32]}...</code></td></tr>
                <tr><td><strong>Expires</strong></td><td>{alert.certificate_info.get('not_after', 'unknown')}</td></tr>
                <tr><td><strong>Source</strong></td><td>{alert.certificate_info.get('source', 'unknown')}</td></tr>
            </table>
        """
        
        if alert.baseline_info:
            html += f"""
            <h3>Baseline Certificate</h3>
            <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
                <tr><td><strong>Subject</strong></td><td>{alert.baseline_info.get('subject', 'unknown')}</td></tr>
                <tr><td><strong>Issuer</strong></td><td>{alert.baseline_info.get('issuer', 'unknown')}</td></tr>
                <tr><td><strong>Fingerprint</strong></td><td><code>{alert.baseline_info.get('fingerprint_sha256', 'unknown')[:32]}...</code></td></tr>
            </table>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html


class SlackNotifier:
    """Slack notification handler"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.webhook_url = config.get('webhook_url')
        self.channel = config.get('channel', '#security-alerts')
        self.username = config.get('username', 'UCG-CertMonitor')
        
        # Initialize Slack client if token provided
        self.client = None
        if config.get('token'):
            self.client = WebClient(token=config.get('token'))
    
    def send_notification(self, alert: CertificateAlert):
        """Send Slack notification"""
        try:
            message = self._create_slack_message(alert)
            
            if self.client:
                # Use Slack API client
                self.client.chat_postMessage(**message)
            elif self.webhook_url:
                # Use webhook
                response = requests.post(self.webhook_url, json=message)
                response.raise_for_status()
            else:
                raise ValueError("No Slack client or webhook URL configured")
            
            logger.info("Slack alert sent successfully")
            
        except Exception as e:
            logger.error("Failed to send Slack alert", error=str(e))
            raise
    
    def _create_slack_message(self, alert: CertificateAlert) -> Dict:
        """Create Slack message payload"""
        severity_colors = {
            'LOW': 'good',
            'MEDIUM': 'warning',
            'HIGH': 'warning',
            'CRITICAL': 'danger'
        }
        
        color = severity_colors.get(alert.severity, 'warning')
        
        # Create attachment
        attachment = {
            'color': color,
            'title': f"{alert.alert_type.value.replace('_', ' ').title()}",
            'title_link': f"http://localhost:8080/alerts/{alert.certificate_info.get('fingerprint_sha256', '')[:16]}",
            'text': alert.message,
            'fields': [
                {
                    'title': 'Host',
                    'value': alert.certificate_info.get('host', 'unknown'),
                    'short': True
                },
                {
                    'title': 'Severity',
                    'value': alert.severity,
                    'short': True
                },
                {
                    'title': 'Subject',
                    'value': alert.certificate_info.get('subject', 'unknown'),
                    'short': False
                },
                {
                    'title': 'Issuer',
                    'value': alert.certificate_info.get('issuer', 'unknown'),
                    'short': False
                },
                {
                    'title': 'Fingerprint',
                    'value': f"```{alert.certificate_info.get('fingerprint_sha256', 'unknown')[:32]}...```",
                    'short': False
                }
            ],
            'footer': 'UCG Certificate Monitor',
            'ts': int(alert.timestamp.timestamp())
        }
        
        message = {
            'channel': self.channel,
            'username': self.username,
            'attachments': [attachment]
        }
        
        return message


class SMSNotifier:
    """SMS notification handler using Twilio"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.client = TwilioClient(
            config.get('twilio_sid'),
            config.get('twilio_token')
        )
        self.from_number = config.get('from_number')
        self.to_numbers = config.get('to_numbers', [])
    
    def send_notification(self, alert: CertificateAlert):
        """Send SMS notification"""
        try:
            message_body = self._create_sms_message(alert)
            
            for to_number in self.to_numbers:
                self.client.messages.create(
                    body=message_body,
                    from_=self.from_number,
                    to=to_number
                )
            
            logger.info("SMS alert sent successfully")
            
        except Exception as e:
            logger.error("Failed to send SMS alert", error=str(e))
            raise
    
    def _create_sms_message(self, alert: CertificateAlert) -> str:
        """Create SMS message content"""
        host = alert.certificate_info.get('host', 'unknown')
        return f"UCG-CERT [{alert.severity}]: {alert.alert_type.value.replace('_', ' ').title()} on {host}. {alert.message[:100]}..."


class WebhookNotifier:
    """Generic webhook notification handler"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.url = config.get('url')
        self.headers = config.get('headers', {})
        self.auth = config.get('auth')
    
    def send_notification(self, alert: CertificateAlert):
        """Send webhook notification"""
        try:
            payload = {
                'alert_type': alert.alert_type.value,
                'severity': alert.severity,
                'message': alert.message,
                'timestamp': alert.timestamp.isoformat(),
                'certificate_info': {
                    k: str(v) for k, v in alert.certificate_info.items()
                },
                'baseline_info': {
                    k: str(v) for k, v in alert.baseline_info.items()
                } if alert.baseline_info else None
            }
            
            # Prepare authentication
            auth = None
            if self.auth:
                if self.auth.get('type') == 'basic':
                    auth = (self.auth.get('username'), self.auth.get('password'))
            
            response = requests.post(
                self.url,
                json=payload,
                headers=self.headers,
                auth=auth,
                timeout=30
            )
            response.raise_for_status()
            
            logger.info("Webhook alert sent successfully")
            
        except Exception as e:
            logger.error("Failed to send webhook alert", error=str(e))
            raise


if __name__ == "__main__":
    # Example usage
    import yaml
    from certificate_validator import CertificateAlert, AlertType
    
    # Load configuration
    with open('../config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Create alerting system
    alerting = AlertingSystem(config)
    alerting.start()
    
    # Example alert
    cert_info = {
        'host': 'example.com',
        'port': 443,
        'subject': 'CN=example.com',
        'issuer': 'CN=Let\'s Encrypt',
        'fingerprint_sha256': '1234567890abcdef' * 4,
        'not_after': datetime.now() + timedelta(days=7)
    }
    
    alert = CertificateAlert(
        AlertType.EXPIRY_SOON,
        "HIGH",
        "Certificate expires in 7 days",
        cert_info
    )
    
    # Send alert
    alerting.send_alert(alert)
    
    # Wait a bit then stop
    import time
    time.sleep(2)
    alerting.stop()
