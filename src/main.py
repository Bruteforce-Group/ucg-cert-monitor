#!/usr/bin/env python3
"""
UCG Certificate Monitor - Main Application
Integrates network monitoring, certificate validation, UCG APIs, and alerting
"""

import asyncio
import signal
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import yaml
from dotenv import load_dotenv
import structlog
import click

try:
    from network_monitor import NetworkTrafficMonitor, PassiveCertificateCollector
except ImportError:
    from network_monitor_simple import NetworkTrafficMonitor, PassiveCertificateCollector
from certificate_validator import CertificateValidator
from ucg_api_client import UCGAPIClient, UCGCertificatePoller, UCGDiscovery
from alerting_system import AlertingSystem

# Setup logging
logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "processors": [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    "handlers": {
        "default": {
            "level": "INFO",
            "class": "logging.StreamHandler",
        },
        "file": {
            "level": "DEBUG",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "logs/cert_monitor.log",
            "maxBytes": 100 * 1024 * 1024,  # 100MB
            "backupCount": 5,
        },
    },
    "loggers": {
        "": {
            "handlers": ["default", "file"],
            "level": "INFO",
            "propagate": False,
        }
    }
}

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


class UCGCertificateMonitor:
    """Main UCG Certificate Monitor application"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_configuration()
        self.running = False
        
        # Initialize components
        self.certificate_validator = CertificateValidator(self.config)
        self.alerting_system = AlertingSystem(self.config)
        self.network_monitor = None
        self.ucg_poller = None
        self.passive_collector = None
        
        # Statistics
        self.stats = {
            'start_time': None,
            'certificates_processed': 0,
            'alerts_generated': 0,
            'network_packets_processed': 0,
            'ucg_polls_completed': 0
        }
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_configuration(self) -> Dict:
        """Load configuration from file"""
        try:
            # Load environment variables from multiple locations
            env_paths = [
                Path(self.config_path).parent / '.env',  # config/.env
                Path('.env'),  # .env in current directory
                Path.home() / '.env'  # ~/.env
            ]
            
            for env_path in env_paths:
                if env_path.exists():
                    load_dotenv(env_path)
                    logger.debug("Loaded environment variables", env_path=str(env_path))
                    break
            
            # Load YAML configuration
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Substitute environment variables
            config = self._substitute_env_vars(config)
            
            logger.info("Configuration loaded successfully", config_path=self.config_path)
            return config
            
        except Exception as e:
            logger.error("Failed to load configuration", config_path=self.config_path, error=str(e))
            raise
    
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
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info("Received shutdown signal", signal=signum)
        self.stop()
    
    async def start(self):
        """Start the certificate monitor"""
        if self.running:
            logger.warning("Monitor is already running")
            return
        
        logger.info("Starting UCG Certificate Monitor")
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        try:
            # Start alerting system
            self.alerting_system.start()
            
            # Initialize and start network monitoring if enabled
            if self.config.get('network', {}).get('enabled', True):
                await self._start_network_monitoring()
            
            # Initialize and start UCG API polling if enabled
            if self.config.get('ucg', {}).get('enabled', True):
                await self._start_ucg_polling()
            
            # Start passive certificate collection
            await self._start_passive_collection()
            
            logger.info("UCG Certificate Monitor started successfully")
            
            # Main monitoring loop
            await self._monitoring_loop()
            
        except Exception as e:
            logger.error("Error starting certificate monitor", error=str(e))
            await self.stop()
            raise
    
    async def _start_network_monitoring(self):
        """Start network traffic monitoring"""
        try:
            self.network_monitor = NetworkTrafficMonitor(
                self.config,
                certificate_callback=self._handle_certificate
            )
            self.network_monitor.start_monitoring()
            logger.info("Network monitoring started")
        except Exception as e:
            logger.error("Failed to start network monitoring", error=str(e))
            # Don't fail completely if network monitoring can't start
    
    async def _start_ucg_polling(self):
        """Start UCG API polling"""
        try:
            self.ucg_poller = UCGCertificatePoller(
                self.config,
                certificate_callback=self._handle_certificate
            )
            await self.ucg_poller.start_polling()
            logger.info("UCG API polling started")
        except Exception as e:
            logger.error("Failed to start UCG polling", error=str(e))
            # Don't fail completely if UCG polling can't start
    
    async def _start_passive_collection(self):
        """Start passive certificate collection from known endpoints"""
        try:
            self.passive_collector = PassiveCertificateCollector(self.config)
            
            # Add common endpoints
            endpoints = [
                ('google.com', 443),
                ('github.com', 443),
                ('stackoverflow.com', 443)
            ]
            
            for host, port in endpoints:
                self.passive_collector.add_endpoint(host, port)
            
            logger.info("Passive certificate collection configured")
        except Exception as e:
            logger.error("Failed to configure passive collection", error=str(e))
    
    def _handle_certificate(self, cert_info: Dict):
        """Handle discovered certificate"""
        try:
            self.stats['certificates_processed'] += 1
            
            logger.info("Processing certificate",
                       host=cert_info.get('host', 'unknown'),
                       fingerprint=cert_info.get('fingerprint_sha256', 'unknown')[:16])
            
            # Validate certificate
            is_valid, alerts = self.certificate_validator.validate_certificate(cert_info)
            
            # Send alerts
            for alert in alerts:
                self.alerting_system.send_alert(alert)
                self.stats['alerts_generated'] += 1
            
            # Add to baseline if valid and no alerts
            if is_valid and len(alerts) == 0:
                self.certificate_validator.add_baseline_certificate(cert_info)
            
        except Exception as e:
            logger.error("Error handling certificate", error=str(e))
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        last_stats_log = datetime.now()
        
        while self.running:
            try:
                # Log statistics periodically
                if (datetime.now() - last_stats_log).seconds >= 300:  # Every 5 minutes
                    await self._log_statistics()
                    last_stats_log = datetime.now()
                
                # Collect passive certificates periodically
                if self.passive_collector:
                    try:
                        certificates = await self.passive_collector.collect_certificates()
                        for cert_info in certificates:
                            if cert_info:
                                self._handle_certificate(cert_info)
                    except Exception as e:
                        logger.error("Error in passive collection", error=str(e))
                
                # Sleep before next iteration
                await asyncio.sleep(60)  # Check every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in monitoring loop", error=str(e))
                await asyncio.sleep(10)
    
    async def _log_statistics(self):
        """Log monitoring statistics"""
        runtime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        stats = {
            **self.stats,
            'runtime_seconds': runtime,
            'certificates_per_minute': self.stats['certificates_processed'] / (runtime / 60) if runtime > 0 else 0
        }
        
        # Add component statistics
        if self.network_monitor:
            net_stats = self.network_monitor.get_statistics()
            stats.update({f'network_{k}': v for k, v in net_stats.items()})
        
        cert_stats = self.certificate_validator.get_certificate_statistics()
        stats.update({f'validator_{k}': v for k, v in cert_stats.items()})
        
        alert_stats = self.alerting_system.get_statistics()
        stats.update({f'alerting_{k}': v for k, v in alert_stats.items()})
        
        logger.info("Monitoring statistics", **stats)
    
    async def stop(self):
        """Stop the certificate monitor"""
        if not self.running:
            return
        
        logger.info("Stopping UCG Certificate Monitor")
        self.running = False
        
        # Stop components
        if self.network_monitor:
            self.network_monitor.stop_monitoring()
        
        if self.ucg_poller:
            await self.ucg_poller.stop_polling()
        
        self.alerting_system.stop()
        
        logger.info("UCG Certificate Monitor stopped")
    
    async def discover_ucg_devices(self) -> List[Dict]:
        """Discover UCG devices on the network"""
        try:
            discovery = UCGDiscovery(self.config)
            devices = await discovery.discover_ucg_devices()
            
            logger.info("UCG device discovery completed", discovered=len(devices))
            
            for device in devices:
                logger.info("Discovered UCG device",
                           host=device['host'],
                           port=device['port'],
                           type=device['device_type'])
            
            return devices
            
        except Exception as e:
            logger.error("Error discovering UCG devices", error=str(e))
            return []


@click.group()
def cli():
    """UCG Certificate Monitor CLI"""
    pass


@cli.command()
@click.option('--config', '-c', default='config/config.yaml', help='Configuration file path')
@click.option('--daemon', '-d', is_flag=True, help='Run as daemon')
def monitor(config, daemon):
    """Start certificate monitoring"""
    async def run_monitor():
        monitor = UCGCertificateMonitor(config)
        try:
            await monitor.start()
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        finally:
            await monitor.stop()
    
    if daemon:
        # TODO: Implement proper daemon mode
        logger.info("Daemon mode not yet implemented, running in foreground")
    
    asyncio.run(run_monitor())


@cli.command()
@click.option('--config', '-c', default='config/config.yaml', help='Configuration file path')
def discover(config):
    """Discover UCG devices on the network"""
    async def run_discovery():
        monitor = UCGCertificateMonitor(config)
        devices = await monitor.discover_ucg_devices()
        
        if devices:
            click.echo(f"\\nDiscovered {len(devices)} UCG devices:")
            for device in devices:
                click.echo(f"- {device['host']}:{device['port']} ({device['device_type']})")
        else:
            click.echo("No UCG devices discovered")
    
    asyncio.run(run_discovery())


@cli.command()
@click.option('--config', '-c', default='config/config.yaml', help='Configuration file path')
@click.option('--host', '-h', required=True, help='Host to collect certificate from')
@click.option('--port', '-p', default=443, help='Port to collect certificate from')
def collect(config, host, port):
    """Collect certificate from specific host"""
    async def run_collection():
        monitor = UCGCertificateMonitor(config)
        collector = PassiveCertificateCollector(monitor.config)
        collector.add_endpoint(host, port)
        
        certificates = await collector.collect_certificates()
        
        for cert_info in certificates:
            if cert_info:
                click.echo(f"\\nCertificate for {host}:{port}:")
                click.echo(f"Subject: {cert_info['subject']}")
                click.echo(f"Issuer: {cert_info['issuer']}")
                click.echo(f"Expires: {cert_info['not_after']}")
                click.echo(f"Fingerprint: {cert_info['fingerprint_sha256']}")
                
                # Validate certificate
                is_valid, alerts = monitor.certificate_validator.validate_certificate(cert_info)
                click.echo(f"Valid: {is_valid}")
                
                if alerts:
                    click.echo("Alerts:")
                    for alert in alerts:
                        click.echo(f"- {alert.alert_type.value}: {alert.message}")
            else:
                click.echo(f"Failed to collect certificate from {host}:{port}")
    
    asyncio.run(run_collection())


@cli.command()
@click.option('--config', '-c', default='config/config.yaml', help='Configuration file path')
def flowlogs(config):
    """Analyze network flow logs and correlate with certificates"""
    async def run_flow_analysis():
        try:
            from flow_cert_integration import FlowCertificateCorrelator
            
            monitor = UCGCertificateMonitor(config)
            correlator = FlowCertificateCorrelator(monitor.config)
            
            await correlator.initialize()
            
            click.echo("🔄 Analyzing network flows and certificates...")
            results = await correlator.discover_and_monitor_certificates()
            
            # Display results
            flow_analysis = results['flow_analysis']
            click.echo(f"\n📊 Flow Analysis:")
            click.echo(f"   Total candidates: {flow_analysis.get('total_candidates', 0)}")
            click.echo(f"   High confidence: {flow_analysis.get('high_confidence', 0)}")
            
            cert_discoveries = results['certificate_discoveries']
            click.echo(f"\n🔐 Certificate Discoveries: {len(cert_discoveries)}")
            for discovery in cert_discoveries[:5]:
                candidate = discovery['candidate']
                cert_info = discovery['certificate']
                score = discovery['correlation_score']
                click.echo(f"   - {candidate['hostname']} ({candidate['ip_address']}) - {score}% confidence")
            
            high_value = results['high_value_targets']
            click.echo(f"\n🎯 High-Value Targets: {len(high_value)}")
            for target in high_value[:3]:
                click.echo(f"   - {target['hostname']} ({target['monitoring_priority']} priority)")
            
            recommendations = results['monitoring_recommendations']
            click.echo(f"\n💡 Recommendations: {len(recommendations)}")
            for rec in recommendations:
                click.echo(f"   [{rec['priority']}] {rec['description']}")
            
            await correlator.close()
            
        except ImportError:
            click.echo("❌ Flow log analysis not available (missing dependencies)")
        except Exception as e:
            click.echo(f"❌ Error in flow analysis: {e}")
    
    asyncio.run(run_flow_analysis())


@cli.command()
@click.option('--config', '-c', default='config/config.yaml', help='Configuration file path')
def stats(config):
    """Show monitoring statistics"""
    monitor = UCGCertificateMonitor(config)
    
    # Get certificate statistics
    cert_stats = monitor.certificate_validator.get_certificate_statistics()
    
    click.echo("\\nCertificate Statistics:")
    click.echo(f"Baseline certificates: {cert_stats.get('baseline_certificates', 0)}")
    click.echo(f"Certificates seen (24h): {cert_stats.get('certificates_24h', 0)}")
    click.echo(f"Active alerts: {cert_stats.get('active_alerts', 0)}")
    
    if cert_stats.get('alerts_by_severity'):
        click.echo("\\nAlerts by severity:")
        for severity, count in cert_stats['alerts_by_severity'].items():
            click.echo(f"- {severity}: {count}")


if __name__ == '__main__':
    cli()
