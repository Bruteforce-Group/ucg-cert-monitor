#!/usr/bin/env python3
"""
UCG Discovery and Detail Request Demo
This script demonstrates how to:
1. Discover UCG devices on the network
2. Request certificate details from discovered devices
3. Attempt to get configuration and status information
"""

import asyncio
import sys
import yaml
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from ucg_api_client import UCGDiscovery, UCGAPIClient
import structlog

# Setup simple logging
structlog.configure(
    processors=[structlog.processors.JSONRenderer()],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

async def demonstrate_ucg_discovery():
    """Demonstrate full UCG discovery and detail request workflow"""
    
    print("🔍 UCG Network Discovery and Detail Request Demo")
    print("=" * 60)
    
    # Load configuration
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Phase 1: Network Discovery
    print("\n📡 Phase 1: Discovering UCG devices on network...")
    discovery = UCGDiscovery(config)
    discovered_devices = await discovery.discover_ucg_devices()
    
    if not discovered_devices:
        print("❌ No UCG devices found on the network")
        print("\nTip: Check your network configuration and discovery_ranges in config.yaml")
        return
    
    print(f"✅ Found {len(discovered_devices)} UCG device(s):")
    for i, device in enumerate(discovered_devices, 1):
        print(f"   {i}. {device['host']}:{device['port']} ({device['device_type']})")
        print(f"      Base URL: {device['base_url']}")
        print(f"      Discovered: {device['discovered_at']}")
    
    # Phase 2: Request Details from Discovered Devices
    print(f"\n🔧 Phase 2: Requesting details from discovered devices...")
    
    # Create API client with discovered endpoints
    ucg_endpoints = []
    for device in discovered_devices:
        ucg_endpoints.append(device['base_url'])
    
    # Update config with discovered endpoints
    config['ucg']['api_endpoints'] = ucg_endpoints
    api_client = UCGAPIClient(config)
    
    try:
        await api_client.initialize()
        print("✅ API client initialized")
        
        # Try to get details from each endpoint
        for endpoint in ucg_endpoints:
            print(f"\n📋 Requesting details from {endpoint}:")
            
            try:
                # Get system status
                print("   → Requesting system status...")
                status = await api_client.get_system_status(endpoint)
                if status:
                    print(f"   ✅ Status retrieved: {len(status)} fields")
                    # Show some key fields if they exist
                    for key in ['version', 'model', 'uptime', 'status']:
                        if key in status:
                            print(f"      {key}: {status[key]}")
                else:
                    print("   ❌ No status information available")
                
                # Get configuration
                print("   → Requesting configuration...")
                config_info = await api_client.get_ucg_configuration(endpoint)
                if config_info:
                    print(f"   ✅ Configuration retrieved: {len(config_info)} fields")
                    # Show some key fields if they exist
                    for key in ['hostname', 'model', 'firmware_version']:
                        if key in config_info:
                            print(f"      {key}: {config_info[key]}")
                else:
                    print("   ❌ No configuration information available")
                
                # Get certificates
                print("   → Requesting certificates...")
                certificates = await api_client.get_device_certificates(endpoint)
                if certificates:
                    print(f"   ✅ Found {len(certificates)} certificate(s)")
                    for cert in certificates:
                        print(f"      - {cert.get('subject', 'Unknown subject')}")
                        print(f"        Expires: {cert.get('not_after', 'Unknown')}")
                        print(f"        Fingerprint: {cert.get('fingerprint_sha256', 'Unknown')[:16]}...")
                else:
                    print("   ❌ No certificates found")
                    
            except Exception as e:
                print(f"   ❌ Error requesting details: {e}")
        
        # Phase 3: Poll all endpoints at once
        print(f"\n🔄 Phase 3: Polling all endpoints simultaneously...")
        try:
            results = await api_client.poll_all_endpoints()
            print(f"✅ Polling completed:")
            print(f"   - Certificates found: {len(results['certificates'])}")
            print(f"   - Endpoints polled: {len(results['configurations'])}")
            print(f"   - Errors encountered: {len(results['errors'])}")
            
            if results['errors']:
                print("   Errors:")
                for error in results['errors']:
                    print(f"      - {error['endpoint']}: {error['error']}")
                    
        except Exception as e:
            print(f"   ❌ Polling failed: {e}")
    
    finally:
        await api_client.close()
    
    print(f"\n✨ Demo completed!")
    print("\nNext steps:")
    print("- Update config.yaml with discovered endpoints")
    print("- Configure proper authentication credentials in .env")
    print("- Run 'python3 src/main.py monitor' to start continuous monitoring")

if __name__ == "__main__":
    asyncio.run(demonstrate_ucg_discovery())
