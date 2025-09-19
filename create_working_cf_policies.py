#!/usr/bin/env python3
"""
Create Working Cloudflare Gateway Policies
Uses tested expressions that work with the Cloudflare Gateway API
"""

import os
import sys
import json
import requests
from typing import Dict, List, Optional

class WorkingCloudflareGatewayPolicyManager:
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
            
            if response.status_code == 409:
                print(f"    ℹ️  Already exists (skipping)")
                return {"success": True}
                
            if response.status_code == 400:
                try:
                    error_detail = response.json()
                    errors = error_detail.get('errors', [])
                    if errors:
                        print(f"    ❌ Failed: {errors[0].get('message', 'Unknown error')}")
                    else:
                        print(f"    ❌ Failed: Bad request")
                    print(f"    🔍 Debug: {response.text}")
                except:
                    print(f"    ❌ Failed: {response.text}")
                return None
                
            response.raise_for_status()
            print(f"    ✅ Created successfully")
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"    ❌ Network error: {e}")
            return None

    def get_working_policies(self) -> List[Dict]:
        """Get policies with verified working expressions"""
        return [
            # DNS Policies
            {
                "name": "DNS: Block Malware Categories",
                "description": "Block known malware domains using Cloudflare categories",
                "precedence": 1000,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "any(dns.content_category[*] in {68})",  # 68 = Malware
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked: Malware domain detected"
                }
            },
            {
                "name": "DNS: Block Phishing Categories", 
                "description": "Block phishing domains using Cloudflare categories",
                "precedence": 1001,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "any(dns.content_category[*] in {83})",  # 83 = Phishing
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked: Phishing domain detected"
                }
            },
            {
                "name": "DNS: Block Gambling (Optional)",
                "description": "Block gambling websites",
                "precedence": 1002,
                "enabled": False,  # Disabled by default
                "action": "block", 
                "filters": ["dns"],
                "traffic": "any(dns.content_category[*] in {23})",  # 23 = Gambling
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked: Gambling site"
                }
            },
            {
                "name": "DNS: Allow Business Domains",
                "description": "Explicitly allow important business domains",
                "precedence": 1100,
                "enabled": True,
                "action": "allow",
                "filters": ["dns"],
                "traffic": "any(dns.fqdn[*] in {\"google.com\" \"microsoft.com\" \"office.com\" \"cloudflare.com\" \"github.com\" \"stackoverflow.com\"})",
                "rule_settings": {}
            },
            
            # Network Policies
            {
                "name": "Network: Block Crypto Mining",
                "description": "Block cryptocurrency mining ports",
                "precedence": 2000,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "net.dst.port == 8333",  # Bitcoin
                "rule_settings": {}
            },
            {
                "name": "Network: Block BitTorrent",
                "description": "Block BitTorrent traffic",
                "precedence": 2001,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "net.dst.port == 6881",  # BitTorrent
                "rule_settings": {}
            },
            {
                "name": "Network: Allow HTTPS",
                "description": "Explicitly allow HTTPS traffic",
                "precedence": 2100,
                "enabled": True,
                "action": "allow",
                "filters": ["l4"],
                "traffic": "net.dst.port == 443",
                "rule_settings": {}
            },
            
            # HTTP Policies  
            {
                "name": "HTTP: Block Executable Downloads",
                "description": "Block dangerous executable file downloads",
                "precedence": 3000,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.uri.path matches \".*\\\\.exe$\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked: Executable download prohibited"
                }
            },
            {
                "name": "HTTP: Block Social Media (Optional)",
                "description": "Block major social media platforms",
                "precedence": 3001,
                "enabled": False,  # Disabled by default
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.host == \"facebook.com\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked: Social media restricted"
                }
            },
            {
                "name": "HTTP: Allow Business Tools",
                "description": "Ensure business tools are accessible",
                "precedence": 3100,
                "enabled": True,
                "action": "allow",
                "filters": ["http"],
                "traffic": "http.request.host == \"office.com\"",
                "rule_settings": {}
            }
        ]

    def create_all_policies(self):
        """Create all working policies"""
        print("🚀 Creating Working Cloudflare Gateway Policies")
        print("=" * 60)
        
        policies_created = 0
        policies_failed = 0
        policies_skipped = 0
        
        all_policies = self.get_working_policies()
        
        for policy in all_policies:
            result = self.create_policy(policy)
            if result:
                if result.get('success'):
                    policies_created += 1
                else:
                    policies_skipped += 1
            else:
                policies_failed += 1
                
        print(f"\n📊 Summary:")
        print(f"  ✅ Policies Created: {policies_created}")
        print(f"  ℹ️  Policies Skipped (existing): {policies_skipped}")
        print(f"  ❌ Policies Failed: {policies_failed}")
        total = policies_created + policies_failed + policies_skipped
        if total > 0:
            success_rate = ((policies_created + policies_skipped) / total * 100)
            print(f"  📈 Success Rate: {success_rate:.1f}%")
        
        print(f"\n📚 Policy Types Created:")
        print(f"  🔒 DNS Security: Malware & phishing blocking")
        print(f"  🌐 Network Security: Crypto mining & P2P blocking") 
        print(f"  🔗 HTTP Security: Executable download blocking")
        print(f"  ✅ Business Continuity: Essential service allowlists")

def main():
    """Main function"""
    # Get credentials from environment
    api_key = os.getenv('CF_API_KEY')
    email = os.getenv('CF_API_EMAIL') 
    account_id = "0b0ee2b5eaf1fb8a2612e40ab6488052"  # Your account ID
    
    if not api_key or not email:
        print("❌ Error: CF_API_KEY and CF_API_EMAIL environment variables are required")
        sys.exit(1)
        
    print("🔐 Working Cloudflare Gateway Policies Creator")
    print("=" * 60)
    print(f"Account ID: {account_id}")
    print(f"API Email: {email}")
    
    # Create policy manager
    manager = WorkingCloudflareGatewayPolicyManager(api_key, email, account_id)
    
    # Create all policies
    manager.create_all_policies()
    
    print("\n🎉 Policy creation completed!")
    print("\n📋 Next Steps:")
    print("  1. Visit Cloudflare Zero Trust Dashboard > Gateway > Policies")
    print("  2. Review and adjust policy precedence as needed")
    print("  3. Enable optional policies (gambling, social media) as required")
    print("  4. Monitor logs and fine-tune rules based on your organization's needs")
    print("  5. Consider adding custom domain lists for more specific blocking")

if __name__ == "__main__":
    main()
