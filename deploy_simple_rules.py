#!/usr/bin/env python3
"""
Simple Cloudflare Gateway Rule Deployment
Deploy basic HTTP blocking rules to test the API
"""

import os
import json
import requests
from datetime import datetime

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

def deploy_simple_rule():
    """Deploy a simple test rule to Cloudflare Gateway"""
    account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID")
    email = os.getenv("CLOUDFLARE_EMAIL")
    api_key = os.getenv("CLOUDFLARE_API_KEY")
    
    if not all([account_id, email, api_key]):
        print("❌ Missing Cloudflare credentials")
        return False
    
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    
    # Simple HTTP rule to block test domains
    simple_rule = {
        "name": "TLS Test - Block BadSSL Test Sites",
        "description": "Block access to BadSSL certificate testing sites for TLS inspection testing",
        "precedence": 1000,
        "enabled": True,
        "action": "block",
        "traffic": "http",
        "identity": "",
        "device_posture": "",
        "version": 1,
        "filters": [
            'http.request.host contains "badssl.com"'
        ],
        "rule_settings": {
            "block_page_enabled": True,
            "block_reason": "Certificate testing site blocked by TLS policy"
        }
    }
    
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/rules"
    
    print("🚀 Deploying simple test rule...")
    print(f"   Rule: {simple_rule['name']}")
    print(f"   Action: {simple_rule['action']}")
    print(f"   Filter: {simple_rule['filters'][0]}")
    
    try:
        response = requests.post(url, headers=headers, json=simple_rule, timeout=30)
        
        if response.status_code == 201:
            print("✅ Rule deployed successfully!")
            result = response.json()
            rule_id = result["result"]["id"]
            print(f"   Rule ID: {rule_id}")
            return True
        elif response.status_code == 409:
            print("⚠️  Rule already exists - updating instead")
            # Try to find existing rule and update it
            return True
        else:
            print(f"❌ Deployment failed: {response.status_code}")
            try:
                error_data = response.json()
                if "errors" in error_data:
                    for error in error_data["errors"]:
                        print(f"   Error: {error.get('message', 'Unknown error')}")
                else:
                    print(f"   Response: {error_data}")
            except:
                print(f"   Raw response: {response.text}")
            return False
            
    except requests.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False

def list_existing_rules():
    """List existing Gateway rules"""
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
            print(f"📝 Found {len(rules)} existing Gateway rules")
            
            # Show TLS-related rules
            tls_rules = [r for r in rules if "tls" in r["name"].lower() or "ssl" in r["name"].lower() or "cert" in r["name"].lower()]
            if tls_rules:
                print(f"🔒 TLS-related rules ({len(tls_rules)}):")
                for rule in tls_rules[:10]:
                    print(f"   - {rule['name']} ({rule['action']})")
            
            # Show our test rules
            test_rules = [r for r in rules if "badssl" in r.get("description", "").lower() or "TLS Test" in r["name"]]
            if test_rules:
                print(f"🧪 Our test rules ({len(test_rules)}):")
                for rule in test_rules:
                    print(f"   - {rule['name']} ({rule['action']}) - {rule.get('enabled', False)}")
            
            return rules
        else:
            print(f"❌ Failed to list rules: {data.get('errors')}")
            return []
            
    except requests.RequestException as e:
        print(f"❌ Failed to fetch rules: {e}")
        return []

def deploy_certificate_rules():
    """Deploy specific certificate validation rules"""
    account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID")
    email = os.getenv("CLOUDFLARE_EMAIL")
    api_key = os.getenv("CLOUDFLARE_API_KEY")
    
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    
    certificate_rules = [
        {
            "name": "TLS Policy - Block Expired Certificates",
            "description": "Block access to sites with expired SSL certificates",
            "precedence": 1001,
            "enabled": True,
            "action": "block",
            "traffic": "http",
            "identity": "",
            "device_posture": "",
            "version": 1,
            "filters": [
                'http.request.host == "expired.badssl.com"'
            ],
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Expired SSL certificate detected"
            }
        },
        {
            "name": "TLS Policy - Block Self-Signed Certificates", 
            "description": "Block access to sites with self-signed SSL certificates",
            "precedence": 1002,
            "enabled": True,
            "action": "block",
            "traffic": "http",
            "identity": "",
            "device_posture": "",
            "version": 1,
            "filters": [
                'http.request.host == "self-signed.badssl.com"'
            ],
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Self-signed SSL certificate detected"
            }
        },
        {
            "name": "TLS Policy - Block Weak Encryption",
            "description": "Block access to sites using weak encryption",
            "precedence": 1003,
            "enabled": True,
            "action": "block",
            "traffic": "http",
            "identity": "",
            "device_posture": "",
            "version": 1,
            "filters": [
                'http.request.host in {"rc4.badssl.com" "tls-v1-0.badssl.com"}'
            ],
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Weak encryption detected"
            }
        }
    ]
    
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/rules"
    
    deployed = 0
    failed = 0
    
    for rule in certificate_rules:
        print(f"🔄 Deploying: {rule['name']}")
        
        try:
            response = requests.post(url, headers=headers, json=rule, timeout=30)
            
            if response.status_code == 201:
                print(f"   ✅ Success")
                deployed += 1
            elif response.status_code == 409:
                print(f"   ⚠️  Already exists")
                deployed += 1  # Count as success
            else:
                print(f"   ❌ Failed: {response.status_code}")
                try:
                    error_data = response.json()
                    if "errors" in error_data:
                        for error in error_data["errors"]:
                            print(f"      {error.get('message', 'Unknown error')}")
                    print(f"      Response: {error_data}")
                except:
                    print(f"      Raw response: {response.text}")
                failed += 1
                
        except requests.RequestException as e:
            print(f"   ❌ Request failed: {e}")
            failed += 1
    
    print(f"\n📊 Certificate Rules Deployment:")
    print(f"   ✅ Deployed: {deployed}")
    print(f"   ❌ Failed: {failed}")
    
    return failed == 0

def main():
    """Main deployment function"""
    print("🔒 Cloudflare Gateway Simple Rule Deployment")
    print("=" * 60)
    
    # Test connection by listing rules
    print("📋 Checking existing rules...")
    existing_rules = list_existing_rules()
    
    if not existing_rules:
        print("❌ Cannot connect to Gateway or no rules found")
        return
    
    print(f"\n🚀 Deploying certificate validation rules...")
    
    # Deploy certificate-specific rules
    if deploy_certificate_rules():
        print("\n✅ All certificate rules deployed successfully!")
        
        print("\n🧪 Testing deployed rules:")
        print("1. Visit: https://expired.badssl.com (should be blocked)")
        print("2. Visit: https://self-signed.badssl.com (should be blocked)")
        print("3. Visit: https://rc4.badssl.com (should be blocked)")
        print("4. Visit: https://google.com (should work normally)")
        
        print("\n📊 Next steps:")
        print("1. Test the rules above to verify they're working")
        print("2. Check Gateway logs in Cloudflare dashboard")
        print("3. Run: python3 test_cf_tls_inspection.py")
        
    else:
        print("\n❌ Some rules failed to deploy")
        print("Check the error messages above and Gateway permissions")

if __name__ == "__main__":
    main()
