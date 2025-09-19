#!/usr/bin/env python3
"""
Examine Existing Cloudflare Gateway Rules
Learn the correct filter format from existing rules
"""

import os
import json
import requests

# Load environment variables
def load_env_file():
    env_file = ".env.cloudflare"
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value

load_env_file()

def get_rule_details():
    """Get detailed information about existing rules"""
    account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID")
    email = os.getenv("CLOUDFLARE_EMAIL")
    api_key = os.getenv("CLOUDFLARE_API_KEY")
    
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/rules"
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        if data.get("success"):
            rules = data["result"]
            print(f"📝 Found {len(rules)} total rules")
            
            # Find HTTP rules to examine their structure
            http_rules = [r for r in rules if r.get("traffic") == "http"][:5]
            
            print(f"\n🔍 Examining {len(http_rules)} HTTP rules:")
            
            for i, rule in enumerate(http_rules):
                print(f"\n--- Rule {i+1}: {rule['name']} ---")
                print(f"Action: {rule['action']}")
                print(f"Traffic: {rule.get('traffic')}")
                print(f"Enabled: {rule.get('enabled')}")
                
                # Show filters
                filters = rule.get("filters", [])
                if filters:
                    print(f"Filters ({len(filters)}):")
                    for j, f in enumerate(filters):
                        print(f"  {j+1}. {f}")
                else:
                    print("No filters")
                
                # Show rule settings
                settings = rule.get("rule_settings", {})
                if settings:
                    print(f"Settings: {json.dumps(settings, indent=2)}")
                
                print(f"Full rule structure:")
                print(json.dumps(rule, indent=2)[:500] + "..." if len(json.dumps(rule, indent=2)) > 500 else json.dumps(rule, indent=2))
                
            # Look for TLS/certificate related rules specifically
            print(f"\n🔒 TLS/Certificate Rules:")
            cert_rules = [r for r in rules if any(word in r['name'].lower() 
                                                for word in ['tls', 'ssl', 'cert', 'https'])]
            
            for rule in cert_rules[:3]:
                print(f"\n--- {rule['name']} ---")
                print(f"Filters: {rule.get('filters', [])}")
                if rule.get('rule_settings'):
                    print(f"Settings: {rule['rule_settings']}")
                    
            return rules
        else:
            print(f"❌ Failed to get rules: {data.get('errors')}")
            return []
            
    except requests.RequestException as e:
        print(f"❌ Request failed: {e}")
        return []

def main():
    """Main examination function"""
    print("🔍 Examining Existing Cloudflare Gateway Rules")
    print("=" * 60)
    
    rules = get_rule_details()
    
    if rules:
        print(f"\n💡 Key Findings:")
        
        # Analyze filter patterns
        all_filters = []
        for rule in rules:
            all_filters.extend(rule.get("filters", []))
        
        if all_filters:
            print(f"📊 Filter examples ({len(all_filters)} total):")
            unique_patterns = set()
            
            for f in all_filters[:20]:  # Show first 20 filters
                # Extract the field being used
                if " in " in f:
                    field = f.split(" in ")[0]
                elif " == " in f:
                    field = f.split(" == ")[0]  
                elif " contains " in f:
                    field = f.split(" contains ")[0]
                else:
                    field = f.split()[0] if f.split() else "unknown"
                    
                unique_patterns.add(field.strip())
                
            print("   Common fields used:")
            for pattern in sorted(unique_patterns):
                print(f"     - {pattern}")
                
            print(f"\n   Example filters:")
            for f in all_filters[:5]:
                print(f"     {f}")
                
        else:
            print("No filters found in existing rules")
            
        # Show traffic types
        traffic_types = set(rule.get("traffic", "unknown") for rule in rules)
        print(f"\n🚦 Traffic types: {', '.join(sorted(traffic_types))}")
        
        # Show actions
        actions = set(rule.get("action", "unknown") for rule in rules)
        print(f"⚡ Actions used: {', '.join(sorted(actions))}")

if __name__ == "__main__":
    main()
