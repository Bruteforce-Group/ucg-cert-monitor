#!/usr/bin/env python3
"""
Cloudflare Gateway Log Monitor Agent
Real-time monitoring of Gateway logs with intelligent rule analysis and notifications

Author: AI Assistant
Date: September 6, 2025
Version: 1.0.0
"""

import json
import requests
import time
import logging
import sqlite3
import hashlib
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
from collections import defaultdict, Counter
import os
import subprocess
import threading
import queue
import sys
from urllib.parse import urlparse

@dataclass
class LogEvent:
    """Represents a Gateway log event"""
    timestamp: str
    client_ip: str
    host: str
    uri: str
    method: str
    status: int
    user_agent: str
    ray_id: str = ""
    
    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class RuleRecommendation:
    """Represents a rule recommendation"""
    priority: str  # HIGH, MEDIUM, LOW
    action: str   # ALLOW, BLOCK, MODIFY
    rule_type: str  # HTTP, DNS
    target: str   # domain, path, etc.
    reason: str
    evidence: List[str]
    suggested_rule: dict
    confidence: float  # 0.0 to 1.0
    
    def to_dict(self) -> dict:
        return asdict(self)

class GatewayLogAnalyzer:
    """Intelligent log analyzer for detecting rule patterns"""
    
    def __init__(self):
        self.blocked_patterns = defaultdict(int)
        self.allowed_patterns = defaultdict(int)
        self.time_window = timedelta(hours=1)
        self.confidence_threshold = 0.7
        
    def analyze_events(self, events: List[LogEvent]) -> List[RuleRecommendation]:
        """Analyze log events and generate rule recommendations"""
        recommendations = []
        
        # Group events by status code
        blocked_events = [e for e in events if e.status in [403, 451, 502, 504]]
        successful_events = [e for e in events if e.status in [200, 201, 202]]
        
        # Analyze blocked legitimate traffic
        recommendations.extend(self._analyze_blocked_legitimate(blocked_events))
        
        # Analyze potential security threats
        recommendations.extend(self._analyze_security_threats(successful_events))
        
        # Analyze patterns and anomalies
        recommendations.extend(self._analyze_patterns(events))
        
        return recommendations
    
    def _analyze_blocked_legitimate(self, blocked_events: List[LogEvent]) -> List[RuleRecommendation]:
        """Detect legitimate services being blocked"""
        recommendations = []
        
        # Group by host
        host_blocks = Counter(e.host for e in blocked_events)
        
        for host, count in host_blocks.items():
            if count >= 5:  # Threshold for investigation
                # Check if it's a known legitimate service
                if self._is_likely_legitimate(host, blocked_events):
                    confidence = min(0.9, count / 20.0)  # Higher count = higher confidence
                    
                    recommendations.append(RuleRecommendation(
                        priority="HIGH" if count > 20 else "MEDIUM",
                        action="ALLOW",
                        rule_type="HTTP",
                        target=host,
                        reason=f"Legitimate service {host} blocked {count} times",
                        evidence=[f"Status 403/451 count: {count}", f"Host: {host}"],
                        suggested_rule={
                            "name": f"HTTP Allow: {host} (Auto-detected)",
                            "action": "allow",
                            "traffic": f'http.request.host == "{host}"',
                            "precedence": 45
                        },
                        confidence=confidence
                    ))
        
        return recommendations
    
    def _analyze_security_threats(self, successful_events: List[LogEvent]) -> List[RuleRecommendation]:
        """Detect potential security threats that should be blocked"""
        recommendations = []
        
        # Look for suspicious patterns
        for event in successful_events:
            # SQL injection patterns
            if any(pattern in event.uri.lower() for pattern in ['select ', 'union ', 'drop ', 'insert ']):
                recommendations.append(RuleRecommendation(
                    priority="HIGH",
                    action="BLOCK",
                    rule_type="HTTP",
                    target=event.host,
                    reason=f"Potential SQL injection detected on {event.host}",
                    evidence=[f"URI: {event.uri}", f"User-Agent: {event.user_agent}"],
                    suggested_rule={
                        "name": f"HTTP Block: SQL Injection on {event.host}",
                        "action": "block",
                        "traffic": f'http.request.host == "{event.host}" and http.request.uri.query matches ".*(SELECT|UNION|DROP|INSERT).*"',
                        "precedence": 100
                    },
                    confidence=0.8
                ))
            
            # Suspicious file downloads
            if event.uri.endswith(('.exe', '.scr', '.bat', '.cmd')) and event.status == 200:
                recommendations.append(RuleRecommendation(
                    priority="MEDIUM",
                    action="BLOCK", 
                    rule_type="HTTP",
                    target=event.host,
                    reason=f"Executable file download from {event.host}",
                    evidence=[f"URI: {event.uri}", f"Status: {event.status}"],
                    suggested_rule={
                        "name": f"HTTP Block: Executable Downloads from {event.host}",
                        "action": "block", 
                        "traffic": f'http.request.host == "{event.host}" and http.request.uri.path matches ".*\\\\.(exe|scr|bat|cmd)$"',
                        "precedence": 200
                    },
                    confidence=0.6
                ))
        
        return recommendations
    
    def _analyze_patterns(self, events: List[LogEvent]) -> List[RuleRecommendation]:
        """Analyze traffic patterns for optimization opportunities"""
        recommendations = []
        
        # Group by user agent for bot detection
        user_agents = Counter(e.user_agent for e in events)
        
        for ua, count in user_agents.items():
            if count > 50 and any(bot in ua.lower() for bot in ['bot', 'crawler', 'spider']):
                recommendations.append(RuleRecommendation(
                    priority="LOW",
                    action="MODIFY",
                    rule_type="HTTP", 
                    target=ua,
                    reason=f"High volume bot traffic detected: {ua}",
                    evidence=[f"Request count: {count}", f"User-Agent: {ua}"],
                    suggested_rule={
                        "name": f"HTTP Rate-limit: {ua[:30]}...",
                        "action": "allow",
                        "traffic": f'http.request.user_agent == "{ua}"',
                        "rule_settings": {"rate_limit": {"requests_per_minute": 10}}
                    },
                    confidence=0.5
                ))
        
        return recommendations
    
    def _is_likely_legitimate(self, host: str, events: List[LogEvent]) -> bool:
        """Determine if a blocked host is likely legitimate"""
        # Check against known legitimate patterns
        legitimate_indicators = [
            'apple.com', 'google.com', 'microsoft.com', 'amazon.com',
            'cloudflare.com', 'github.com', 'stackoverflow.com',
            'api.', 'cdn.', 'static.', 'assets.', '.edu', '.gov'
        ]
        
        if any(indicator in host.lower() for indicator in legitimate_indicators):
            return True
            
        # Check user agents for legitimate patterns
        host_events = [e for e in events if e.host == host]
        user_agents = set(e.user_agent for e in host_events)
        
        legitimate_ua_patterns = ['safari/', 'chrome/', 'firefox/', 'edge/', 'cfnetwork/']
        if any(any(pattern in ua.lower() for pattern in legitimate_ua_patterns) for ua in user_agents):
            return True
            
        return False

class NotificationManager:
    """Handles notifications for rule recommendations"""
    
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def send_notification(self, recommendations: List[RuleRecommendation]) -> bool:
        """Send notifications about rule recommendations"""
        if not recommendations:
            return True
            
        try:
            # Filter by priority
            high_priority = [r for r in recommendations if r.priority == "HIGH"]
            medium_priority = [r for r in recommendations if r.priority == "MEDIUM"]
            
            # Send different notification types based on configuration
            success = True
            
            if self.config.get('notifications', {}).get('desktop', False):
                success &= self._send_desktop_notification(recommendations)
                
            if self.config.get('notifications', {}).get('email', {}).get('enabled', False):
                success &= self._send_email_notification(recommendations)
                
            if self.config.get('notifications', {}).get('webhook', {}).get('enabled', False):
                success &= self._send_webhook_notification(recommendations)
                
            return success
        except Exception as e:
            self.logger.error(f"Failed to send notifications: {e}")
            return False
    
    def _send_desktop_notification(self, recommendations: List[RuleRecommendation]) -> bool:
        """Send macOS desktop notification"""
        try:
            high_priority = [r for r in recommendations if r.priority == "HIGH"]
            if high_priority:
                title = "Gateway Rule Alert"
                message = f"Found {len(high_priority)} high-priority rule recommendations"
                subprocess.run([
                    'osascript', '-e', 
                    f'display notification "{message}" with title "{title}"'
                ], check=True)
            return True
        except Exception as e:
            self.logger.error(f"Desktop notification failed: {e}")
            return False
    
    def _send_email_notification(self, recommendations: List[RuleRecommendation]) -> bool:
        """Send email notification with detailed recommendations"""
        try:
            email_config = self.config.get('notifications', {}).get('email', {})
            
            msg = MIMEMultipart()
            msg['From'] = email_config.get('from_address')
            msg['To'] = email_config.get('to_address')
            msg['Subject'] = f"Gateway Monitor: {len(recommendations)} Rule Recommendations"
            
            # Create email body
            body = self._generate_email_body(recommendations)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP(email_config.get('smtp_server'), email_config.get('smtp_port', 587))
            server.starttls()
            server.login(email_config.get('username'), email_config.get('password'))
            server.sendmail(email_config.get('from_address'), email_config.get('to_address'), msg.as_string())
            server.quit()
            
            return True
        except Exception as e:
            self.logger.error(f"Email notification failed: {e}")
            return False
    
    def _send_webhook_notification(self, recommendations: List[RuleRecommendation]) -> bool:
        """Send webhook notification (e.g., Slack, Teams)"""
        try:
            webhook_config = self.config.get('notifications', {}).get('webhook', {})
            webhook_url = webhook_config.get('url')
            
            payload = {
                "text": f"Gateway Monitor Alert: {len(recommendations)} rule recommendations",
                "attachments": [
                    {
                        "color": "warning" if any(r.priority == "HIGH" for r in recommendations) else "good",
                        "fields": [
                            {
                                "title": f"{r.priority} Priority - {r.action} {r.target}",
                                "value": r.reason,
                                "short": False
                            } for r in recommendations[:5]  # Limit to first 5
                        ]
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Webhook notification failed: {e}")
            return False
    
    def _generate_email_body(self, recommendations: List[RuleRecommendation]) -> str:
        """Generate HTML email body with recommendations"""
        html = f"""
        <html>
        <head><title>Gateway Rule Recommendations</title></head>
        <body>
        <h2>Gateway Monitor Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>
        <p>Found <strong>{len(recommendations)}</strong> rule recommendations:</p>
        
        <table border="1" style="border-collapse: collapse; width: 100%;">
        <tr style="background-color: #f0f0f0;">
            <th>Priority</th>
            <th>Action</th>
            <th>Target</th>
            <th>Reason</th>
            <th>Confidence</th>
        </tr>
        """
        
        for rec in recommendations:
            color = {"HIGH": "#ffebee", "MEDIUM": "#fff3e0", "LOW": "#e8f5e8"}.get(rec.priority, "#ffffff")
            html += f"""
            <tr style="background-color: {color};">
                <td><strong>{rec.priority}</strong></td>
                <td>{rec.action}</td>
                <td>{rec.target}</td>
                <td>{rec.reason}</td>
                <td>{rec.confidence:.1%}</td>
            </tr>
            """
        
        html += """
        </table>
        <p><em>This is an automated message from the Gateway Monitor Agent.</em></p>
        </body>
        </html>
        """
        
        return html

class GatewayMonitor:
    """Main monitoring agent class"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        self.analyzer = GatewayLogAnalyzer()
        self.notifier = NotificationManager(self.config)
        self.db_path = "gateway_monitor.db"
        self._setup_database()
        self.running = False
        self.last_check = datetime.utcnow() - timedelta(minutes=5)
        
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default configuration
            return {
                "cloudflare": {
                    "api_email": os.getenv("CF_API_EMAIL"),
                    "api_key": os.getenv("CF_API_KEY"),
                    "account_id": "0b0ee2b5eaf1fb8a2612e40ab6488052",
                    "zone_id": "7249ad638510c628a7861d93535acbca"
                },
                "monitoring": {
                    "interval_minutes": 5,
                    "lookback_minutes": 10,
                    "min_events_for_analysis": 5
                },
                "notifications": {
                    "desktop": True,
                    "email": {
                        "enabled": False
                    },
                    "webhook": {
                        "enabled": False
                    }
                }
            }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        # File handler
        handler = logging.FileHandler("gateway_monitor.log")
        handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _setup_database(self):
        """Setup SQLite database for storing recommendations and events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS recommendations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                priority TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                target TEXT NOT NULL,
                reason TEXT NOT NULL,
                confidence REAL NOT NULL,
                suggested_rule TEXT NOT NULL,
                status TEXT DEFAULT 'PENDING'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT,
                host TEXT,
                uri TEXT,
                method TEXT,
                status INTEGER,
                user_agent TEXT,
                ray_id TEXT,
                processed BOOLEAN DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def fetch_logs(self) -> List[LogEvent]:
        """Fetch recent logs from Cloudflare API"""
        try:
            # Calculate time window
            now = datetime.utcnow()
            since = self.last_check
            
            # Build SQL query for Log Explorer
            query = f"""
                SELECT ClientIP, ClientRequestHost, ClientRequestURI, 
                       ClientRequestMethod, EdgeResponseStatus, ClientRequestUserAgent,
                       RayID
                FROM http_requests 
                WHERE ClientIP = '104.28.250.151'
                ORDER BY EdgeTimeStamp DESC 
                LIMIT 1000
            """
            
            # Make API request
            url = f"https://api.cloudflare.com/client/v4/zones/{self.config['cloudflare']['zone_id']}/logs/explorer/query/sql"
            headers = {
                "X-Auth-Email": self.config['cloudflare']['api_email'],
                "X-Auth-Key": self.config['cloudflare']['api_key'],
                "Content-Type": "application/json"
            }
            
            response = requests.get(url, headers=headers, params={"query": query}, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            events = []
            
            for record in data.get('result', []):
                event = LogEvent(
                    timestamp=now.isoformat(),
                    client_ip=record.get('clientip', ''),
                    host=record.get('clientrequesthost', ''),
                    uri=record.get('clientrequesturi', ''),
                    method=record.get('clientrequestmethod', ''),
                    status=record.get('edgeresponsestatus', 0),
                    user_agent=record.get('clientrequestuseragent', ''),
                    ray_id=record.get('rayid', '')
                )
                events.append(event)
            
            self.logger.info(f"Fetched {len(events)} log events")
            return events
            
        except Exception as e:
            self.logger.error(f"Failed to fetch logs: {e}")
            return []
    
    def store_recommendation(self, recommendation: RuleRecommendation):
        """Store recommendation in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO recommendations 
            (timestamp, priority, action, rule_type, target, reason, confidence, suggested_rule)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.utcnow().isoformat(),
            recommendation.priority,
            recommendation.action,
            recommendation.rule_type, 
            recommendation.target,
            recommendation.reason,
            recommendation.confidence,
            json.dumps(recommendation.suggested_rule)
        ))
        
        conn.commit()
        conn.close()
    
    def run_analysis_cycle(self):
        """Run a single analysis cycle"""
        self.logger.info("Starting analysis cycle...")
        
        # Fetch logs
        events = self.fetch_logs()
        
        if len(events) < self.config.get('monitoring', {}).get('min_events_for_analysis', 5):
            self.logger.info(f"Not enough events ({len(events)}) for analysis")
            return
        
        # Analyze events
        recommendations = self.analyzer.analyze_events(events)
        
        if recommendations:
            self.logger.info(f"Generated {len(recommendations)} recommendations")
            
            # Store recommendations
            for rec in recommendations:
                self.store_recommendation(rec)
            
            # Send notifications
            self.notifier.send_notification(recommendations)
        else:
            self.logger.info("No recommendations generated")
        
        # Update last check time
        self.last_check = datetime.utcnow()
    
    def start(self):
        """Start the monitoring agent"""
        self.logger.info("Starting Gateway Monitor Agent...")
        self.running = True
        
        interval = self.config.get('monitoring', {}).get('interval_minutes', 5) * 60
        
        while self.running:
            try:
                self.run_analysis_cycle()
                time.sleep(interval)
            except KeyboardInterrupt:
                self.logger.info("Received interrupt signal")
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring cycle: {e}")
                time.sleep(30)  # Brief pause before retrying
        
        self.logger.info("Gateway Monitor Agent stopped")
    
    def stop(self):
        """Stop the monitoring agent"""
        self.running = False

def main():
    """Main entry point"""
    monitor = GatewayMonitor()
    
    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.stop()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
