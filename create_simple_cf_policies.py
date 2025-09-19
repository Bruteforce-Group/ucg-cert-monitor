#!/usr/bin/env python3
"""
Create Simple Cloudflare Gateway Policies
Basic policies with simple expressions that should work reliably
"""

import os
import sys
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional

class SimpleCloudflareGatewayPolicyManager:
    def __init__(self, api_key: str, email: str, account_id: str):
        self.api_key = api_key
        self.email = email
        self.account_id = account_id
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self.headers = {
            "X-Auth-Email": email,
            "X-Auth-Key": api_key,
            "Content-Type": "application/json"
        }
        
    def create_policy(self, policy_data: Dict) -> Optional[Dict]:
        """Create a Gateway policy"""
        url = f"{self.base_url}/rules"
        
        try:
            print(f"  Creating: {policy_data['name']}")
            response = requests.post(url, headers=self.headers, json=policy_data, timeout=30)
            
            if response.status_code == 400:
                try:
                    error_detail = response.json()
                    errors = error_detail.get('errors', [])
                    if errors:
                        print(f"    ❌ Failed: {errors[0].get('message', 'Unknown error')}")
                    else:
                        print(f"    ❌ Failed: Bad request")
                except:
                    print(f"    ❌ Failed: {response.text}")
                return None
                
            response.raise_for_status()
            print(f"    ✅ Created successfully")
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"    ❌ Network error: {e}")
            return None

    def get_basic_dns_policies(self) -> List[Dict]:
        """Get basic DNS policies that should work"""
        return [
            {
                "name": "DNS: Block Malware (Basic)",
                "description": "Block domains in Cloudflare malware category",
                "precedence": 1000,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "any(dns.content_category[*] in {68})",  # Malware category
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked: Malware domain"
                }
            },
            {
                "name": "DNS: Block Adult Content",
                "description": "Block adult content domains",
                "precedence": 1001,
                "enabled": False,  # Disabled by default
                "action": "block", 
                "filters": ["dns"],
                "traffic": "any(dns.content_category[*] in {4})",  # Adult category
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked: Adult content"
                }
            },
            {
                "name": "DNS: Allow All Other DNS",
                "description": "Log and allow all other DNS queries",
                "precedence": 9998,
                "enabled": True,
                "action": "allow",
                "filters": ["dns"],
                "traffic": "true",
                "rule_settings": {}
            }
        ]

    def get_basic_network_policies(self) -> List[Dict]:
        """Get basic Network policies that should work"""
        return [
            {
                "name": "Network: Block Bitcoin Mining Ports",
                "description": "Block common Bitcoin mining ports",
                "precedence": 2000,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "net.dst.port == 8333 or net.dst.port == 8334",
                "rule_settings": {}
            },
            {
                "name": "Network: Block P2P Ports",
                "description": "Block BitTorrent and P2P ports",
                "precedence": 2001,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "net.dst.port == 6881 or net.dst.port == 6999",
                "rule_settings": {}
            },
            {
                "name": "Network: Allow All Other Traffic",
                "description": "Log and allow all other network traffic",
                "precedence": 9997,
                "enabled": True,
                "action": "allow",
                "filters": ["l4"], 
                "traffic": "true",
                "rule_settings": {}
            }
        ]

    def get_basic_http_policies(self) -> List[Dict]:
        """Get basic HTTP policies that should work"""
        return [
            {
                "name": "HTTP: Block .exe Downloads",
                "description": "Block .exe file downloads",
                "precedence": 3000,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.uri.path matches \".*\\.exe$\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked: Executable download"
                }
            },
            {
                "name": "HTTP: Block Social Media (Optional)",
                "description": "Block major social media sites",
                "precedence": 3001,
                "enabled": False,  # Disabled by default
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.host == \"facebook.com\" or http.request.host == \"twitter.com\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked: Social media restricted"
                }
            },
            {
                "name": "HTTP: Allow All Other HTTP",
                "description": "Log and allow all other HTTP traffic",
                "precedence": 9996,
                "enabled": True,
                "action": "allow",
                "filters": ["http"],
                "traffic": "true",
                "rule_settings": {}
            }
        ]

    def create_all_policies(self):
        """Create all basic policies"""
        print("🚀 Creating Basic Cloudflare Gateway Policies")
        print("=" * 60)
        
        policies_created = 0
        policies_failed = 0
        
        all_policies = []
        all_policies.extend(self.get_basic_dns_policies())
        all_policies.extend(self.get_basic_network_policies())
        all_policies.extend(self.get_basic_http_policies())
        
        for policy in all_policies:
            result = self.create_policy(policy)
            if result and result.get('success'):
                policies_created += 1
            else:
                policies_failed += 1
                
        print(f"\n📊 Summary:")
        print(f"  ✅ Policies Created: {policies_created}")
        print(f"  ❌ Policies Failed: {policies_failed}")
        total = policies_created + policies_failed
        if total > 0:
            print(f"  📈 Success Rate: {(policies_created/total*100):.1f}%")

def main():
    """Main function"""
    # Get credentials from environment
    api_key = os.getenv('CF_API_KEY')
    email = os.getenv('CF_API_EMAIL') 
    account_id = "0b0ee2b5eaf1fb8a2612e40ab6488052"  # Your account ID
    
    if not api_key or not email:
        print("❌ Error: CF_API_KEY and CF_API_EMAIL environment variables are required")
        sys.exit(1)
        
    print("🔐 Simple Cloudflare Gateway Policies Creator")
    print("=" * 60)
    print(f"Account ID: {account_id}")
    print(f"API Email: {email}")
    
    # Create policy manager
    manager = SimpleCloudflareGatewayPolicyManager(api_key, email, account_id)
    
    # Create all policies
    manager.create_all_policies()
    
    print("\n🎉 Policy creation completed!")

if __name__ == "__main__":
    main()
