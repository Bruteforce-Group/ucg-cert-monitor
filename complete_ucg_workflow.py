#!/usr/bin/env python3
"""
Complete UCG Workflow Demonstration
Shows the full workflow: Discovery → Authentication → Details Request
"""

import asyncio
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from main import UCGCertificateMonitor

async def demonstrate_complete_ucg_workflow():
    """Demonstrate complete UCG workflow"""
    
    print("🔄 Complete UCG Workflow Demonstration")
    print("=" * 60)
    
    # Initialize the monitor (this handles env var substitution)
    monitor = UCGCertificateMonitor('config/config.yaml')
    
    print(f"📋 Configuration Summary:")
    print(f"   UCG Enabled: {monitor.config['ucg']['enabled']}")
    print(f"   API Endpoints: {len(monitor.config['ucg']['api_endpoints'])}")
    print(f"   Discovery Ranges: {monitor.config['ucg']['discovery_ranges']}")
    print(f"   API Key: {'✅ Configured' if monitor.config['ucg']['auth']['api_key'] != 'NO_DATA' else '❌ Not configured'}")
    
    # Step 1: Network Discovery
    print(f"\n🔍 Step 1: UCG Network Discovery")
    discovered_devices = await monitor.discover_ucg_devices()
    
    # Step 2: Manual API Test (since we know the endpoint)
    print(f"\n🔧 Step 2: Testing Known UCG Endpoint")
    
    # Test certificate collection from the known UCG device
    print(f"   → Testing certificate collection from mars.int.bozza.au...")
    
    try:
        # Create a temporary passive collector to test certificate collection
        from network_monitor import PassiveCertificateCollector
        collector = PassiveCertificateCollector(monitor.config)
        collector.add_endpoint('mars.int.bozza.au', 443)
        
        certificates = await collector.collect_certificates()
        
        if certificates:
            for cert_info in certificates:
                if cert_info:
                    print(f"   ✅ Certificate collected successfully!")
                    print(f"      Subject: {cert_info.get('subject', 'Unknown')}")
                    print(f"      Issuer: {cert_info.get('issuer', 'Unknown')}")
                    print(f"      Expires: {cert_info.get('not_after', 'Unknown')}")
                    print(f"      Fingerprint: {cert_info.get('fingerprint_sha256', 'Unknown')[:16]}...")
                    
                    # Test certificate validation
                    is_valid, alerts = monitor.certificate_validator.validate_certificate(cert_info)
                    print(f"      Valid: {is_valid}")
                    if alerts:
                        print(f"      Alerts: {len(alerts)} generated")
        else:
            print(f"   ⚠️  No certificates collected")
            
    except Exception as e:
        print(f"   ❌ Error collecting certificates: {e}")
    
    # Step 3: Show API capabilities
    print(f"\n📡 Step 3: UCG API Integration Summary")
    print(f"   The application now supports:")
    print(f"   ✅ UniFi controller discovery")
    print(f"   ✅ X-API-KEY authentication")
    print(f"   ✅ UniFi-specific API endpoints:")
    print(f"      - /proxy/network/integration/v1/sites")
    print(f"      - /proxy/network/integration/v1/settings/certificates") 
    print(f"      - /proxy/network/api/s/default/rest/setting/super_identity")
    print(f"   ✅ Certificate collection and validation")
    print(f"   ✅ Network discovery and monitoring")
    
    # Step 4: Next steps
    print(f"\n🚀 Step 4: Next Steps for Full Integration")
    print(f"   To enable continuous UCG monitoring:")
    print(f"   1. Run: python3 src/main.py monitor")
    print(f"   2. The system will automatically:")
    print(f"      → Discover UCG devices on your network")
    print(f"      → Authenticate with configured endpoints")
    print(f"      → Collect certificates every 5 minutes")
    print(f"      → Validate certificates against baseline")
    print(f"      → Generate alerts for certificate changes")
    
    print(f"\n✨ UCG Workflow demonstration completed!")
    
    # Test that the API endpoint is reachable
    import aiohttp
    print(f"\n🔌 Bonus: Direct API Connectivity Test")
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(verify_ssl=False),
            timeout=aiohttp.ClientTimeout(total=5)
        ) as session:
            headers = {
                'X-API-KEY': monitor.config['ucg']['auth']['api_key'],
                'Accept': 'application/json'
            }
            
            async with session.get(
                'https://mars.int.bozza.au/proxy/network/integration/v1/sites',
                headers=headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"   ✅ Direct API test successful!")
                    print(f"      Status: {resp.status}")
                    if 'data' in data:
                        print(f"      Sites found: {len(data['data'])}")
                        for site in data['data']:
                            print(f"         - {site.get('name', 'Unknown')} (ID: {site.get('id', 'Unknown')[:8]}...)")
                else:
                    print(f"   ⚠️  API returned status: {resp.status}")
                    
    except Exception as e:
        print(f"   ❌ Direct API test failed: {e}")

if __name__ == "__main__":
    asyncio.run(demonstrate_complete_ucg_workflow())
