#!/usr/bin/env python3
"""
Fix the two failed rules from the simple improvement script
Uses alternative operators that are supported by the Gateway API
"""

import os
import sys
import json
import requests
from datetime import datetime

class FixedRuleCreator:
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
        
    def create_rule(self, rule_data: dict) -> bool:
        """Create a Gateway rule"""
        url = f"{self.base_url}/rules"
        
        try:
            response = requests.post(url, headers=self.headers, json=rule_data, timeout=30)
            
            if response.status_code == 200:
                print(f"    ✅ Created successfully")
                return True
            else:
                print(f"    ❌ Failed: {response.status_code}")
                try:
                    error_detail = response.json()
                    print(f"    Error: {error_detail.get('errors', [{}])[0].get('message', 'Unknown')}")
                except:
                    print(f"    Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"    ❌ Network error: {e}")
            return False

    def get_fixed_rules(self) -> list:
        """Get the fixed rules using alternative operators"""
        return [
            # Fixed script injection rule using "matches" instead of "contains"
            {
                "name": "HTTP: Block Script Injections (Fixed)",
                "description": "Block basic script injection attempts using regex matching",
                "precedence": 503,
                "enabled": True,
                "action": "block", 
                "filters": ["http"],
                "traffic": "http.request.uri matches \".*(\\\\<script|javascript\\\\:|onerror\\\\=).*\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Script injection attempt blocked"
                }
            },
            # Fixed file upload monitoring using "matches" instead of "contains"
            {
                "name": "HTTP: Monitor File Upload Activity (Fixed)",
                "description": "Monitor file upload activity for security using regex matching",
                "precedence": 801,
                "enabled": True,
                "action": "allow",
                "filters": ["http"],
                "traffic": "http.request.method == \"POST\" and http.request.uri.path matches \".*upload.*\"",
                "rule_settings": {}
            }
        ]

    def create_fixed_rules(self):
        """Create the fixed rules"""
        print("🔧 Creating fixed rules with alternative operators...")
        
        rules = self.get_fixed_rules()
        created = 0
        
        for rule in rules:
            print(f"  🔄 Creating: {rule['name']}")
            if self.create_rule(rule):
                created += 1
                
        return created

def main():
    """Main function"""
    # Get credentials from environment
    api_key = os.getenv('CF_API_KEY')
    email = os.getenv('CF_API_EMAIL') 
    account_id = "0b0ee2b5eaf1fb8a2612e40ab6488052"
    
    if not api_key or not email:
        print("❌ Error: CF_API_KEY and CF_API_EMAIL environment variables are required")
        sys.exit(1)
        
    print("🔧 Fixing Failed Gateway Rules")
    print("=" * 50)
    
    # Create fixed rule creator
    fixer = FixedRuleCreator(api_key, email, account_id)
    
    # Create fixed rules
    created = fixer.create_fixed_rules()
    
    print(f"\n📊 Results: {created}/2 fixed rules created successfully")
    
    if created == 2:
        print("🎉 All fixed rules created! Gateway improvements are complete.")
        sys.exit(0)
    else:
        print("⚠️  Some rules still need fixing")
        sys.exit(1)

if __name__ == "__main__":
    main()
