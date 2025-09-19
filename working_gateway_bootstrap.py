#!/usr/bin/env python3
"""
Working Cloudflare Gateway Bootstrap Script
===========================================

Creates baseline security policies using field names and syntax that actually work.
Based on analysis of existing working rules.

Environment variables required:
  * CF_API_KEY    – Legacy API key
  * CF_API_EMAIL  – Email address for API key
"""

import json
import os
import sys
import requests
from typing import Dict, List

# Configuration
API_BASE_URL = "https://api.cloudflare.com/client/v4"
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "0b0ee2b5eaf1fb8a2612e40ab6488052")
API_KEY = os.environ.get("CF_API_KEY")
EMAIL = os.environ.get("CF_API_EMAIL")

if not API_KEY or not EMAIL:
    print("❌ Error: CF_API_KEY and CF_API_EMAIL environment variables are required")
    sys.exit(1)

# Initialize session with API Key authentication
session = requests.Session()
session.headers.update({
    "X-Auth-Email": EMAIL,
    "X-Auth-Key": API_KEY,
    "Content-Type": "application/json",
})

def api_post(path: str, payload: Dict) -> Dict:
    """Perform POST request to Cloudflare API"""
    url = f"{API_BASE_URL}{path}"
    response = session.post(url, data=json.dumps(payload))
    if not response.ok:
        raise RuntimeError(f"POST {path} failed: {response.status_code} - {response.text}")
    data = response.json()
    if not data.get("success", True):
        raise RuntimeError(f"API error: {data}")
    return data["result"]

def api_get(path: str) -> List[Dict]:
    """Get all Gateway rules"""
    url = f"{API_BASE_URL}{path}"
    response = session.get(url)
    if not response.ok:
        raise RuntimeError(f"GET {path} failed: {response.status_code} - {response.text}")
    data = response.json()
    return data["result"]

def find_available_precedence(start: int, existing_rules: List[Dict]) -> int:
    """Find an available precedence value"""
    used_precedences = {rule.get("precedence", 0) for rule in existing_rules}
    precedence = start
    while precedence in used_precedences:
        precedence += 1
    return precedence

def create_working_bootstrap_policies():
    """Create bootstrap policies with working syntax and field names"""
    
    print("🚀 Working Cloudflare Gateway Bootstrap")
    print("=" * 50)
    
    # Get existing rules to avoid precedence conflicts  
    existing_rules = api_get(f"/accounts/{ACCOUNT_ID}/gateway/rules")
    existing_names = {rule.get("name") for rule in existing_rules}
    
    # Category IDs from existing working rules
    security_ids = "68 178 80 187 83 176 175 117 131 188 134 191 151 153"
    
    policies = []
    
    # 1. DNS Security Policy (using working syntax)
    if "DNS: Bootstrap Security Categories" not in existing_names:
        precedence = find_available_precedence(3000, existing_rules)
        policies.append({
            "name": "DNS: Bootstrap Security Categories", 
            "description": "Bootstrap: Block domains in security threat categories",
            "filters": ["dns"],
            "traffic": f"any(dns.security_category[*] in {{{security_ids}}})",
            "action": "block",
            "enabled": True,
            "precedence": precedence,
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Security threat category blocked"
            }
        })
    
    # 2. HTTP Security Policy (using http.request.uri.* instead of http.content_category)
    if "HTTP: Bootstrap Security Categories" not in existing_names:
        precedence = find_available_precedence(3100, existing_rules)
        policies.append({
            "name": "HTTP: Bootstrap Security Categories",
            "description": "Bootstrap: Block HTTP requests to security threat domains",
            "filters": ["http"],
            "traffic": f"any(http.request.uri.security_category[*] in {{{security_ids}}})",
            "action": "block",
            "enabled": True, 
            "precedence": precedence,
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Security threat category blocked"
            }
        })
    
    # 3. File Download Security (using path matching instead of filetype field)
    if "HTTP: Bootstrap File Download Security" not in existing_names:
        precedence = find_available_precedence(3150, existing_rules)  
        policies.append({
            "name": "HTTP: Bootstrap File Download Security",
            "description": "Bootstrap: Block dangerous executable downloads",
            "filters": ["http"],
            "traffic": 'http.request.uri.path matches ".*\\\\.(exe|msi|dll|bat|cmd|scr|ps1|jar|apk|ipa)$"',
            "action": "block",
            "enabled": True,
            "precedence": precedence,
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Dangerous file download blocked"
            }
        })
    
    # 4. Network Security - High-Risk Countries (using single country syntax)
    if "L4: Bootstrap Block High-Risk Countries" not in existing_names:
        precedence = find_available_precedence(3200, existing_rules)
        policies.append({
            "name": "L4: Bootstrap Block High-Risk Countries",
            "description": "Bootstrap: Block traffic to high-risk countries", 
            "filters": ["l4"],
            "traffic": 'net.dst.geo.country == "RU" or net.dst.geo.country == "KP" or net.dst.geo.country == "IR" or net.dst.geo.country == "SY"',
            "action": "block",
            "enabled": True,
            "precedence": precedence,
            "rule_settings": {}
        })
    
    # 5. Network Security - Block Suspicious Ports
    if "L4: Bootstrap Block Suspicious Ports" not in existing_names:
        precedence = find_available_precedence(3250, existing_rules)
        policies.append({
            "name": "L4: Bootstrap Block Suspicious Ports",
            "description": "Bootstrap: Block commonly abused ports",
            "filters": ["l4"],
            "traffic": "net.dst.port in {1433 3389 5432 1521 3306 5900 6379 27017 9200 11211}",
            "action": "block", 
            "enabled": True,
            "precedence": precedence,
            "rule_settings": {}
        })
    
    if not policies:
        print("ℹ️  All bootstrap policies already exist")
        return 0
        
    print(f"\n📋 Creating {len(policies)} bootstrap policies...")
    
    success_count = 0
    for policy in policies:
        try:
            print(f"  🔄 Creating: {policy['name']}")
            result = api_post(f"/accounts/{ACCOUNT_ID}/gateway/rules", policy)
            print(f"    ✅ Created successfully (precedence: {policy['precedence']})")
            success_count += 1
        except Exception as e:
            print(f"    ❌ Failed: {e}")
            
    print(f"\n📊 Bootstrap Results:")
    print(f"   • Policies Created: {success_count}/{len(policies)}")
    print(f"   • Success Rate: {success_count/len(policies)*100:.1f}%")
    
    if success_count > 0:
        print(f"\n✅ Bootstrap completed successfully!")
        print(f"\n📚 Bootstrap Policies Created:")
        for policy in policies[:success_count]:
            print(f"   • {policy['name']} (precedence: {policy['precedence']})")
        
        print(f"\n📝 Next Steps:")
        print(f"  1. Check Zero Trust dashboard for new rules")
        print(f"  2. Monitor Gateway logs for policy hits")
        print(f"  3. Run test suite: python3 test_all_gateway_rules_dynamic.py")
        print(f"  4. Adjust policies based on business needs")
    else:
        print(f"\n❌ Bootstrap failed - no policies created")
        
    return success_count

def main():
    """Main function"""
    created = create_working_bootstrap_policies()
    sys.exit(0 if created > 0 else 1)

if __name__ == "__main__":
    main()
