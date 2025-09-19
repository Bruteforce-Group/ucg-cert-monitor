#!/usr/bin/env python3
"""
Create Common Cloudflare Gateway Policies
Based on Cloudflare Zero Trust best practices for DNS, Network, and HTTP filtering
"""

import os
import sys
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional

class CloudflareGatewayPolicyManager:
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
        
    def create_policy(self, policy_type: str, policy_data: Dict) -> Optional[Dict]:
        """Create a Gateway policy"""
        url = f"{self.base_url}/rules"
        
        try:
            response = requests.post(url, headers=self.headers, json=policy_data, timeout=10)
            if response.status_code == 400:
                error_detail = response.json()
                print(f"  ❌ Failed: {error_detail.get('errors', [{}])[0].get('message', 'Unknown error')}")
                return None
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"  ❌ Network error: {e}")
            return None

    def get_common_dns_policies(self) -> List[Dict]:
        """Get recommended common DNS policies"""
        return [
            {
                "name": "DNS: Block Malware Domains",
                "description": "Block known malware domains to protect against malicious software",
                "precedence": 1000,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "dns.security_category.malware",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked by DNS policy: Malware domain detected"
                }
            },
            {
                "name": "DNS: Block Phishing Domains",
                "description": "Block phishing domains to prevent credential theft",
                "precedence": 1001,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "dns.security_category.phishing",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked by DNS policy: Phishing domain detected"
                }
            },
            {
                "name": "DNS: Block Newly Registered Domains",
                "description": "Block domains registered within the last 30 days (high risk)",
                "precedence": 1002,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "dns.domain_age < 30",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked by DNS policy: Newly registered domain (high risk)"
                }
            },
            {
                "name": "DNS: Block Command & Control",
                "description": "Block known command and control servers",
                "precedence": 1003,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "dns.security_category.command_and_control",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked by DNS policy: Command & Control server detected"
                }
            },
            {
                "name": "DNS: Block Adult Content",
                "description": "Block adult content domains",
                "precedence": 1004,
                "enabled": False,  # Disabled by default
                "action": "block",
                "filters": ["dns"],
                "traffic": "dns.content_category.adult_themes",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked by DNS policy: Adult content blocked"
                }
            },
            {
                "name": "DNS: Log All DNS Queries",
                "description": "Log all DNS queries for monitoring and analysis",
                "precedence": 9999,
                "enabled": True,
                "action": "allow",
                "filters": ["dns"],
                "traffic": "true",
                "rule_settings": {}
            }
        ]

    def get_common_network_policies(self) -> List[Dict]:
        """Get recommended common Network policies"""
        return [
            {
                "name": "Network: Block Cryptocurrency Mining Ports",
                "description": "Block common cryptocurrency mining ports",
                "precedence": 2000,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "net.dst.port in {3333 4444 8333 8334 9332 9333 14433 14444}",
                "rule_settings": {
                    "block_page_enabled": False
                }
            },
            {
                "name": "Network: Block P2P File Sharing Ports",
                "description": "Block common P2P file sharing ports",
                "precedence": 2001,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "net.dst.port in {1214 4662 4672 6346 6347 6881 6999}",
                "rule_settings": {
                    "block_page_enabled": False
                }
            },
            {
                "name": "Network: Log High-Risk Ports",
                "description": "Log connections to commonly exploited ports for monitoring",
                "precedence": 2100,
                "enabled": True,
                "action": "allow",
                "filters": ["l4"],
                "traffic": "net.dst.port in {21 22 23 135 139 445 1433 1521 3389 5432 5900}",
                "rule_settings": {}
            },
            {
                "name": "Network: Allow Essential Services",
                "description": "Explicitly allow essential network services",
                "precedence": 2200,
                "enabled": True,
                "action": "allow",
                "filters": ["l4"],
                "traffic": "net.dst.port in {53 80 443 123 67 68}",
                "rule_settings": {}
            },
            {
                "name": "Network: Log All Traffic",
                "description": "Log all network traffic for monitoring",
                "precedence": 2999,
                "enabled": True,
                "action": "allow",
                "filters": ["l4"],
                "traffic": "true",
                "rule_settings": {}
            }
        ]

    def get_common_http_policies(self) -> List[Dict]:
        """Get recommended common HTTP policies"""
        return [
            {
                "name": "HTTP: Block Executable Downloads",
                "description": "Block potentially dangerous executable file downloads",
                "precedence": 3000,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.uri.path matches r\".*\\.(exe|scr|bat|cmd|pif|com)$\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked by HTTP policy: Executable file download blocked"
                }
            },
            {
                "name": "HTTP: Block Malware Domains",
                "description": "Block HTTP traffic to known malware domains",
                "precedence": 3001,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.host in $cf.threat_intelligence.malware",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked by HTTP policy: Known malware domain"
                }
            },
            {
                "name": "HTTP: Block Social Media (Optional)",
                "description": "Block social media sites (can be customized with time-based rules)",
                "precedence": 3100,
                "enabled": False,  # Disabled by default
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.host matches r\".*(facebook|twitter|instagram|tiktok|snapchat)\\.(com|net|org).*\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Blocked by HTTP policy: Social media access restricted"
                }
            },
            {
                "name": "HTTP: Allow Business Domains",
                "description": "Explicitly allow essential business domains",
                "precedence": 3200,
                "enabled": True,
                "action": "allow",
                "filters": ["http"],
                "traffic": "http.request.host in {\"office.com\" \"microsoft.com\" \"google.com\" \"zoom.us\" \"slack.com\" \"github.com\" \"cloudflare.com\"}",
                "rule_settings": {}
            },
            {
                "name": "HTTP: Enable Browser Isolation for Untrusted Sites",
                "description": "Use browser isolation for potentially risky websites",
                "precedence": 3300,
                "enabled": False,  # Requires Browser Isolation subscription
                "action": "isolate",
                "filters": ["http"],
                "traffic": "not http.request.host in $cf.resolved.domain.whitelist",
                "rule_settings": {
                    "biso_admin_controls": {
                        "dcp": false,
                        "dd": false,
                        "dk": false,
                        "dp": false,
                        "du": false
                    }
                }
            },
            {
                "name": "HTTP: Log All HTTP Traffic",
                "description": "Log all HTTP traffic for monitoring and compliance",
                "precedence": 3999,
                "enabled": True,
                "action": "allow",
                "filters": ["http"],
                "traffic": "true",
                "rule_settings": {}
            }
        ]

    def create_all_policies(self):
        """Create all recommended common policies"""
        print("🚀 Creating Common Cloudflare Gateway Policies")
        print("=" * 60)
        
        policies_created = 0
        policies_failed = 0
        
        # DNS Policies
        print("\n📋 Creating DNS Policies...")
        dns_policies = self.get_common_dns_policies()
        for policy in dns_policies:
            print(f"  Creating: {policy['name']}")
            result = self.create_policy("DNS", policy)
            if result and result.get('success'):
                policies_created += 1
                print(f"    ✅ Created successfully")
            else:
                policies_failed += 1
                print(f"    ❌ Failed to create")
                
        # Network Policies
        print("\n🌐 Creating Network Policies...")
        network_policies = self.get_common_network_policies()
        for policy in network_policies:
            print(f"  Creating: {policy['name']}")
            result = self.create_policy("Network", policy)
            if result and result.get('success'):
                policies_created += 1
                print(f"    ✅ Created successfully")
            else:
                policies_failed += 1
                print(f"    ❌ Failed to create")
                
        # HTTP Policies
        print("\n🔒 Creating HTTP Policies...")
        http_policies = self.get_common_http_policies()
        for policy in http_policies:
            print(f"  Creating: {policy['name']}")
            result = self.create_policy("HTTP", policy)
            if result and result.get('success'):
                policies_created += 1
                print(f"    ✅ Created successfully")
            else:
                policies_failed += 1
                print(f"    ❌ Failed to create")
                
        print(f"\n📊 Summary:")
        print(f"  ✅ Policies Created: {policies_created}")
        print(f"  ❌ Policies Failed: {policies_failed}")
        print(f"  📈 Success Rate: {(policies_created/(policies_created+policies_failed)*100):.1f}%")
        
        if policies_failed > 0:
            print(f"\n💡 Note: Some policies may have failed due to:")
            print(f"  - Syntax issues with traffic expressions")
            print(f"  - Missing threat intelligence lists")
            print(f"  - Account permission limitations")
            print(f"  - Policy conflicts with existing rules")

def main():
    """Main function"""
    # Get credentials from environment
    api_key = os.getenv('CF_API_KEY')
    email = os.getenv('CF_API_EMAIL')
    account_id = "0b0ee2b5eaf1fb8a2612e40ab6488052"  # Your account ID
    
    if not api_key or not email:
        print("❌ Error: CF_API_KEY and CF_API_EMAIL environment variables are required")
        sys.exit(1)
        
    print("🔐 Cloudflare Gateway Common Policies Creator")
    print("=" * 60)
    print(f"Account ID: {account_id}")
    print(f"API Email: {email}")
    
    # Create policy manager
    manager = CloudflareGatewayPolicyManager(api_key, email, account_id)
    
    # Create all policies
    manager.create_all_policies()
    
    print("\n🎉 Policy creation process completed!")
    print("\n📚 Next Steps:")
    print("  1. Review created policies in the Cloudflare Zero Trust dashboard")
    print("  2. Adjust policy precedence as needed")
    print("  3. Enable/disable policies based on your organization's needs")
    print("  4. Monitor policy logs and adjust rules as necessary")

if __name__ == "__main__":
    main()
