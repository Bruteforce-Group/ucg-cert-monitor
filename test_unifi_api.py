#!/usr/bin/env python3
"""
UniFi API Integration Test
Test the UniFi controller API integration directly
"""

import asyncio
import sys
import yaml
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from ucg_api_client import UCGAPIClient
import structlog

# Setup simple logging
structlog.configure(
    processors=[structlog.processors.JSONRenderer()],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

async def test_unifi_api():
    """Test UniFi API integration"""
    
    print("🚀 UniFi API Integration Test")
    print("=" * 50)
    
    # Load configuration
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    print(f"📍 Testing endpoints: {config['ucg']['api_endpoints']}")
    print(f"🔐 Using API key: {config['ucg']['auth']['api_key'][:8]}...")
    
    # Test API client
    api_client = UCGAPIClient(config)
    
    try:
        print("\n🔧 Initializing API client...")
        await api_client.initialize()
        print("✅ API client initialized successfully")
        
        # Test each configured endpoint
        for endpoint in config['ucg']['api_endpoints']:
            print(f"\n📡 Testing endpoint: {endpoint}")
            
            # Test authentication status
            if endpoint in api_client._authenticated_endpoints:
                auth_info = api_client._authenticated_endpoints[endpoint]
                print(f"   ✅ Authenticated with method: {auth_info['type']}")
                
                # Test sites endpoint
                try:
                    print("   → Testing sites endpoint...")
                    status = await api_client.get_system_status(endpoint)
                    if status:
                        print(f"   ✅ Sites data retrieved: {len(status)} fields")
                        if 'data' in status and isinstance(status['data'], list):
                            for site in status['data']:
                                print(f"      - Site: {site.get('name', 'Unknown')} (ID: {site.get('id', 'Unknown')[:8]}...)")
                    else:
                        print("   ⚠️  No sites data returned")
                except Exception as e:
                    print(f"   ❌ Error getting sites: {e}")
                
                # Test certificates
                try:
                    print("   → Testing certificate endpoints...")
                    certificates = await api_client.get_device_certificates(endpoint)
                    if certificates:
                        print(f"   ✅ Found {len(certificates)} certificate(s)")
                        for cert in certificates:
                            print(f"      - Subject: {cert.get('subject', 'Unknown')}")
                            print(f"        Expires: {cert.get('not_after', 'Unknown')}")
                    else:
                        print("   ⚠️  No certificates found")
                except Exception as e:
                    print(f"   ❌ Error getting certificates: {e}")
                
                # Test configuration
                try:
                    print("   → Testing configuration endpoints...")
                    config_info = await api_client.get_ucg_configuration(endpoint)
                    if config_info:
                        print(f"   ✅ Configuration retrieved: {len(config_info)} fields")
                        # Show some key fields
                        for key in ['data', 'settings', 'version']:
                            if key in config_info:
                                print(f"      {key}: {type(config_info[key])} ({len(str(config_info[key]))} chars)")
                    else:
                        print("   ⚠️  No configuration data returned")
                except Exception as e:
                    print(f"   ❌ Error getting configuration: {e}")
                    
            else:
                print(f"   ❌ Authentication failed for {endpoint}")
        
        # Test bulk polling
        print(f"\n🔄 Testing bulk polling of all endpoints...")
        try:
            results = await api_client.poll_all_endpoints()
            print("✅ Bulk polling successful:")
            print(f"   - Certificates: {len(results['certificates'])}")
            print(f"   - Configurations: {len(results['configurations'])}")
            print(f"   - Statuses: {len(results['statuses'])}")
            print(f"   - Errors: {len(results['errors'])}")
            
            if results['errors']:
                print("   Errors encountered:")
                for error in results['errors']:
                    print(f"      - {error['endpoint']}: {error['error']}")
                    
        except Exception as e:
            print(f"❌ Bulk polling failed: {e}")
    
    finally:
        await api_client.close()
    
    print(f"\n✨ UniFi API test completed!")

if __name__ == "__main__":
    asyncio.run(test_unifi_api())
