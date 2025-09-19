#!/usr/bin/env python3
"""
Flow Logs Demo Script
Demonstrates the complete flow log and certificate monitoring integration
"""

import asyncio
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

async def main():
    print("🚀 UCG Certificate Monitor - Flow Log Integration Demo")
    print("=" * 70)
    print()
    
    try:
        from dotenv import load_dotenv
        import yaml
        
        # Load configuration
        load_dotenv('.env')
        
        with open('config/config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        
        print("📋 What this demo shows:")
        print("   1. Network flow analysis from UniFi controller")
        print("   2. Device discovery and traffic pattern analysis")
        print("   3. Certificate collection from high-traffic devices")
        print("   4. Correlation between network flows and TLS usage")
        print("   5. Security monitoring recommendations")
        print()
        
        # Demo 1: Basic Flow Analysis
        print("🔍 Demo 1: Basic Flow Log Analysis")
        print("-" * 40)
        
        from unifi_flow_logs import UniFiFlowLogClient
        
        flow_client = UniFiFlowLogClient(config)
        await flow_client.initialize()
        
        candidates = await flow_client.get_tls_certificate_candidates()
        
        print(f"✅ Discovered {len(candidates)} devices with TLS traffic indicators")
        print("📊 Top certificate candidates:")
        
        for i, candidate in enumerate(candidates[:5], 1):
            traffic_mb = candidate['traffic_volume'] / (1024 * 1024)
            print(f"   {i}. {candidate['hostname']} ({candidate['ip_address']})")
            print(f"      Device: {candidate['device_type']}")
            print(f"      Traffic: {traffic_mb:.1f} MB")
            print(f"      Confidence: {candidate['confidence_score']}%")
            print()
        
        await flow_client.close()
        
        # Demo 2: Flow-Certificate Integration
        print("🔄 Demo 2: Flow-Certificate Correlation")
        print("-" * 40)
        
        from flow_cert_integration import FlowCertificateCorrelator
        
        correlator = FlowCertificateCorrelator(config)
        await correlator.initialize()
        
        results = await correlator.discover_and_monitor_certificates()
        
        # Show results
        flow_analysis = results['flow_analysis']
        cert_discoveries = results['certificate_discoveries']
        high_value_targets = results['high_value_targets']
        recommendations = results['monitoring_recommendations']
        
        print(f"✅ Flow analysis complete:")
        print(f"   - Total devices analyzed: {flow_analysis.get('total_candidates', 0)}")
        print(f"   - High-confidence TLS users: {flow_analysis.get('high_confidence', 0)}")
        print(f"   - Certificates discovered: {len(cert_discoveries)}")
        print(f"   - High-value targets identified: {len(high_value_targets)}")
        print()
        
        if cert_discoveries:
            print("🔐 Certificate Discovery Results:")
            for discovery in cert_discoveries:
                candidate = discovery['candidate']
                cert_info = discovery['certificate']
                score = discovery['correlation_score']
                
                print(f"   📜 {candidate['hostname']} ({candidate['ip_address']})")
                print(f"      Certificate Subject: {cert_info.get('subject', 'Unknown')}")
                print(f"      Issuer: {cert_info.get('issuer', 'Unknown')}")
                print(f"      Correlation Score: {score}%")
                
                if cert_info.get('flow_correlation'):
                    flow_meta = cert_info['flow_correlation']
                    print(f"      Device Type: {flow_meta['device_type']}")
                    traffic_mb = flow_meta['traffic_volume'] / (1024 * 1024)
                    print(f"      Traffic Volume: {traffic_mb:.1f} MB")
                print()
        
        if high_value_targets:
            print("🎯 High-Value Security Targets:")
            for target in high_value_targets:
                print(f"   ⚠️  {target['hostname']} ({target['monitoring_priority']} Priority)")
                print(f"      Reasons: {', '.join(target['reasons'])}")
                print(f"      Certificate: {target['certificate_subject']}")
                print()
        
        if recommendations:
            print("💡 Security Monitoring Recommendations:")
            for rec in recommendations:
                print(f"   [{rec['priority']}] {rec['description']}")
                print(f"       Action: {rec['action']}")
                if rec['type'] == 'monitor_unverified_devices':
                    print(f"       Devices: {len(rec.get('devices', []))}")
                elif rec['type'] == 'certificate_expiry_monitoring':
                    print(f"       Certificates: {len(rec.get('certificates', []))}")
                print()
        
        await correlator.close()
        
        # Demo 3: Practical Usage Examples
        print("🛠️  Demo 3: Practical Usage Examples")
        print("-" * 40)
        
        print("Command Line Usage:")
        print("   python3 src/main.py flowlogs         # Run flow analysis")
        print("   python3 src/main.py monitor          # Continuous monitoring")
        print("   python3 src/main.py discover         # Device discovery")
        print()
        
        print("Integration Benefits:")
        print("   ✅ Automated discovery of certificate-using devices")
        print("   ✅ Traffic pattern analysis for security insights")
        print("   ✅ Proactive certificate monitoring")
        print("   ✅ High-value target identification")
        print("   ✅ Real-time network security monitoring")
        print()
        
        print("🎉 Demo Complete!")
        print("The UCG Certificate Monitor now provides comprehensive")
        print("network flow analysis and certificate correlation capabilities!")
        
    except Exception as e:
        print(f"❌ Demo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
