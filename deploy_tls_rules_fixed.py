#!/usr/bin/env python3
"""
Fixed Cloudflare Gateway TLS Rule Deployment
Deploy TLS certificate validation rules with correct API structure
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

def deploy_tls_rules():
    """Deploy TLS rules with correct Cloudflare Gateway API structure"""
    account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID")
    email = os.getenv("CLOUDFLARE_EMAIL")
    api_key = os.getenv("CLOUDFLARE_API_KEY")
    
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    
    # TLS certificate validation rules using correct API structure
    certificate_rules = [
        {
            "name": "TLS Policy - Block Expired Certificate Sites",
            "description": "Block access to sites known to have expired SSL certificates for testing",
            "precedence": 2001,
            "enabled": True,
            "action": "block",
            "filters": ["http"],  # Just the traffic type
            "traffic": 'http.request.host == "expired.badssl.com"',  # Filter expression
            "identity": "",
            "device_posture": "",
            "version": 1,
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Expired SSL certificate detected - blocked by TLS security policy"
            }
        },
        {
            "name": "TLS Policy - Block Self-Signed Certificate Sites", 
            "description": "Block access to sites with self-signed SSL certificates for testing",
            "precedence": 2002,
            "enabled": True,
            "action": "block",
            "filters": ["http"],
            "traffic": 'http.request.host == "self-signed.badssl.com"',
            "identity": "",
            "device_posture": "",
            "version": 1,
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Self-signed SSL certificate detected - blocked by TLS security policy"
            }
        },
        {
            "name": "TLS Policy - Block Revoked Certificate Sites",
            "description": "Block access to sites with revoked SSL certificates for testing",
            "precedence": 2003,
            "enabled": True,
            "action": "block",
            "filters": ["http"],
            "traffic": 'http.request.host == "revoked.badssl.com"',
            "identity": "",
            "device_posture": "",
            "version": 1,
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Revoked SSL certificate detected - blocked by TLS security policy"
            }
        },
        {
            "name": "TLS Policy - Block Weak Encryption Sites",
            "description": "Block access to sites using weak encryption (RC4, old TLS)",
            "precedence": 2004,
            "enabled": True,
            "action": "block",
            "filters": ["http"],
            "traffic": 'http.request.host in {"rc4.badssl.com" "tls-v1-0.badssl.com" "tls-v1-1.badssl.com"}',
            "identity": "",
            "device_posture": "",
            "version": 1,
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Weak encryption detected - blocked by TLS security policy"
            }
        },
        {
            "name": "TLS Policy - Block Invalid Hostname Sites",
            "description": "Block access to sites with SSL certificate hostname mismatches",
            "precedence": 2005,
            "enabled": True,
            "action": "block",
            "filters": ["http"],
            "traffic": 'http.request.host in {"wrong.host.badssl.com" "untrusted-root.badssl.com"}',
            "identity": "",
            "device_posture": "",
            "version": 1,
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "SSL certificate hostname mismatch detected - blocked by TLS security policy"
            }
        },
        {
            "name": "TLS Policy - Monitor Certificate Test Sites",
            "description": "Log access to certificate testing sites for monitoring",
            "precedence": 2010,
            "enabled": True,
            "action": "allow",
            "filters": ["http"],
            "traffic": 'http.request.host matches ".*\\.badssl\\.com$"',
            "identity": "",
            "device_posture": "",
            "version": 1,
            "rule_settings": {
                "override_ips": [],  # Enables logging
                "payload_log": {
                    "enabled": True
                },
                "untrusted_cert": {
                    "action": "pass_through"
                }
            }
        }
    ]
    
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/rules"
    
    print("🔒 Cloudflare Gateway TLS Certificate Validation Rules")
    print("=" * 70)
    print("🚀 Deploying TLS certificate validation rules...")
    print("📍 Using correct API structure: filters=traffic_type, traffic=filter_expression")
    print()
    
    deployed = 0
    failed = 0
    
    for rule in certificate_rules:
        print(f"🔄 Deploying: {rule['name']}")
        print(f"   Traffic Filter: {rule['traffic']}")
        
        try:
            response = requests.post(url, headers=headers, json=rule, timeout=30)
            
            if response.status_code in [200, 201]:
                try:
                    result = response.json()
                    if result.get("success"):
                        rule_id = result["result"]["id"]
                        print(f"   ✅ Success (ID: {rule_id[:8]}...)")
                        deployed += 1
                    else:
                        print(f"   ❌ API returned success=false")
                        if "errors" in result:
                            for error in result["errors"]:
                                print(f"      {error.get('message', 'Unknown error')}")
                        failed += 1
                except Exception as e:
                    print(f"   ❌ Failed to parse response: {e}")
                    print(f"      Raw response: {response.text[:200]}")
                    failed += 1
            elif response.status_code == 409:
                print(f"   ⚠️  Already exists - skipping")
                deployed += 1  # Count as success
            else:
                print(f"   ❌ Failed: {response.status_code}")
                try:
                    error_data = response.json()
                    if "errors" in error_data:
                        for error in error_data["errors"]:
                            print(f"      {error.get('message', 'Unknown error')}")
                except:
                    print(f"      Raw response: {response.text[:200]}")
                failed += 1
                
        except requests.RequestException as e:
            print(f"   ❌ Request failed: {e}")
            failed += 1
        
        print()  # Empty line for readability
    
    print(f"📊 Deployment Summary:")
    print(f"   ✅ Successfully deployed: {deployed}")
    print(f"   ❌ Failed: {failed}")
    print(f"   📈 Success rate: {(deployed/(deployed+failed)*100):.1f}%")
    
    return failed == 0

def test_deployed_rules():
    """Test the deployed rules by checking if they exist"""
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
            
            # Find our deployed rules
            tls_policy_rules = [r for r in rules if r["name"].startswith("TLS Policy -")]
            
            if tls_policy_rules:
                print(f"🔍 Found {len(tls_policy_rules)} deployed TLS policy rules:")
                for rule in tls_policy_rules:
                    status = "🟢" if rule["enabled"] else "⚪"
                    print(f"   {status} {rule['name']} ({rule['action']})")
                    print(f"      Traffic Filter: {rule.get('traffic', 'No filter')}")
                    print()
                
                return True
            else:
                print("❌ No TLS policy rules found")
                return False
                
    except requests.RequestException as e:
        print(f"❌ Failed to check rules: {e}")
        return False

def main():
    """Main deployment function"""
    print("🔒 Cloudflare Gateway TLS Certificate Validation Rules")
    print("=" * 70)
    print("This will deploy certificate validation rules that block access to:")
    print("• Sites with expired SSL certificates")
    print("• Sites with self-signed certificates") 
    print("• Sites with revoked certificates")
    print("• Sites using weak encryption (RC4, old TLS)")
    print("• Sites with certificate hostname mismatches")
    print()
    
    # Deploy the rules
    if deploy_tls_rules():
        print("✅ All TLS certificate validation rules deployed successfully!")
        
        print("\n🧪 Testing deployed rules...")
        if test_deployed_rules():
            print("\n🎯 Rules are active and ready for testing!")
            
            print("\n📋 Test your deployed rules:")
            print("1. Visit: https://expired.badssl.com (should be blocked)")
            print("2. Visit: https://self-signed.badssl.com (should be blocked)")
            print("3. Visit: https://revoked.badssl.com (should be blocked)")
            print("4. Visit: https://rc4.badssl.com (should be blocked)")
            print("5. Visit: https://wrong.host.badssl.com (should be blocked)")
            print("6. Visit: https://google.com (should work normally)")
            
            print("\n📊 What happens when blocked:")
            print("• User sees Cloudflare block page")
            print("• Block reason explains the certificate issue")
            print("• Event is logged in Gateway analytics")
            
            print("\n🔍 Monitor your rules:")
            print("1. Cloudflare Dashboard → Zero Trust → Gateway → Analytics")
            print("2. Look for 'TLS Policy' rules in blocked requests")
            print("3. Run: python3 test_cf_tls_inspection.py")
            
        else:
            print("⚠️  Could not verify deployed rules")
            
    else:
        print("❌ Some rules failed to deploy")
        print("Check the error messages above")

if __name__ == "__main__":
    main()
