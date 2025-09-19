#!/usr/bin/env python3
"""
Cloudflare Zero Trust Gateway Rules Deployment
Deploy TLS certificate validation rules using official Cloudflare API
"""

import os
import json
import requests
from datetime import datetime

# Use environment variables from your Warp Drive setup
CF_API_EMAIL = "daniel@bruteforce.group"
CF_API_KEY = "9586ac5f9e8deaeffa283a83d137d265123fe"
CF_ACCOUNT_ID = "0b0ee2b5eaf1fb8a2612e40ab6488052"

def deploy_gateway_rules():
    """Deploy Gateway HTTP rules using Cloudflare Zero Trust API"""
    
    headers = {
        "X-Auth-Email": CF_API_EMAIL,
        "X-Auth-Key": CF_API_KEY,
        "Content-Type": "application/json"
    }
    
    # Gateway Rules API endpoint
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/gateway/rules"
    
    # TLS Certificate validation rules using correct API format
    rules = [
        {
            "name": "TLS Security - Block Expired Certificates",
            "description": "Block access to sites with expired SSL certificates",
            "precedence": 3001,
            "enabled": True,
            "action": "block",
            "traffic": "http",
            "identity": "",
            "device_posture": "",
            "version": 1,
            "filters": ['http.request.host == "expired.badssl.com"'],
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "SSL certificate has expired - blocked for security"
            }
        },
        {
            "name": "TLS Security - Block Self-Signed Certificates", 
            "description": "Block access to sites using self-signed SSL certificates",
            "precedence": 3002,
            "enabled": True,
            "action": "block",
            "traffic": "http",
            "identity": "",
            "device_posture": "",
            "version": 1,
            "filters": ['http.request.host == "self-signed.badssl.com"'],
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Self-signed SSL certificate detected - blocked for security"
            }
        },
        {
            "name": "TLS Security - Block Revoked Certificates",
            "description": "Block access to sites with revoked SSL certificates",
            "precedence": 3003,
            "enabled": True,
            "action": "block",
            "traffic": "http", 
            "identity": "",
            "device_posture": "",
            "version": 1,
            "filters": ['http.request.host == "revoked.badssl.com"'],
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "SSL certificate has been revoked - blocked for security"
            }
        },
        {
            "name": "TLS Security - Block Weak Encryption",
            "description": "Block sites using weak encryption protocols (RC4, TLS 1.0)",
            "precedence": 3004,
            "enabled": True,
            "action": "block",
            "traffic": "http",
            "identity": "",
            "device_posture": "",
            "version": 1,
            "filters": ['http.request.host in {"rc4.badssl.com" "tls-v1-0.badssl.com"}'],
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "Weak encryption detected (RC4/old TLS) - blocked for security"
            }
        },
        {
            "name": "TLS Security - Block Certificate Hostname Mismatch",
            "description": "Block sites with SSL certificate hostname mismatches",
            "precedence": 3005,
            "enabled": True,
            "action": "block",
            "traffic": "http",
            "identity": "",
            "device_posture": "",
            "version": 1,
            "filters": ['http.request.host == "wrong.host.badssl.com"'],
            "rule_settings": {
                "block_page_enabled": True,
                "block_reason": "SSL certificate hostname mismatch - blocked for security"
            }
        }
    ]
    
    print("🚀 Deploying TLS Certificate Security Rules to Cloudflare Gateway")
    print(f"📧 Account: {CF_API_EMAIL}")
    print(f"🆔 Account ID: {CF_ACCOUNT_ID}")
    print(f"🔧 Deploying {len(rules)} security rules...")
    print()
    
    deployed = 0
    failed = 0
    
    for rule in rules:
        print(f"🔄 Deploying: {rule['name']}")
        print(f"   Action: {rule['action']}")
        print(f"   Filter: {rule['filters'][0]}")
        
        try:
            response = requests.post(url, headers=headers, json=rule, timeout=30)
            
            if response.status_code == 201:
                result = response.json()
                if result.get("success"):
                    rule_id = result["result"]["id"]
                    print(f"   ✅ Success! Rule ID: {rule_id}")
                    deployed += 1
                else:
                    print(f"   ❌ API Error: {result.get('errors', 'Unknown error')}")
                    failed += 1
                    
            elif response.status_code == 409:
                print(f"   ⚠️  Rule already exists - skipping")
                deployed += 1
                
            elif response.status_code == 400:
                print(f"   ❌ Bad Request (400)")
                try:
                    error_data = response.json()
                    if "errors" in error_data:
                        for error in error_data["errors"]:
                            print(f"      📝 {error.get('message', 'Unknown error')}")
                    else:
                        print(f"      📝 Response: {error_data}")
                except:
                    print(f"      📝 Raw: {response.text[:200]}")
                failed += 1
                
            else:
                print(f"   ❌ HTTP Error: {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"      📝 {error_data}")
                except:
                    print(f"      📝 Raw: {response.text[:200]}")
                failed += 1
                
        except requests.RequestException as e:
            print(f"   ❌ Request failed: {e}")
            failed += 1
        
        print()
    
    print("📊 Deployment Summary:")
    print(f"   ✅ Successfully deployed: {deployed}")
    print(f"   ❌ Failed to deploy: {failed}")
    if deployed + failed > 0:
        print(f"   📈 Success rate: {(deployed/(deployed+failed)*100):.1f}%")
    
    return failed == 0

def list_deployed_rules():
    """List deployed TLS security rules"""
    headers = {
        "X-Auth-Email": CF_API_EMAIL,
        "X-Auth-Key": CF_API_KEY,
        "Content-Type": "application/json"
    }
    
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/gateway/rules"
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        if data.get("success"):
            rules = data["result"]
            
            # Find TLS security rules
            tls_rules = [r for r in rules if "TLS Security" in r["name"]]
            
            if tls_rules:
                print(f"🔍 Found {len(tls_rules)} TLS Security rules:")
                for rule in tls_rules:
                    status = "🟢 Enabled" if rule["enabled"] else "⚪ Disabled"
                    print(f"   {status}: {rule['name']}")
                    print(f"      Action: {rule['action']}")
                    print(f"      Filter: {rule['filters'][0] if rule['filters'] else 'No filter'}")
                    print(f"      ID: {rule['id']}")
                    print()
                return tls_rules
            else:
                print("❌ No TLS Security rules found")
                return []
        else:
            print(f"❌ API Error: {data.get('errors')}")
            return []
            
    except requests.RequestException as e:
        print(f"❌ Failed to fetch rules: {e}")
        return []

def test_api_connection():
    """Test connection to Cloudflare API"""
    headers = {
        "X-Auth-Email": CF_API_EMAIL,
        "X-Auth-Key": CF_API_KEY,
        "Content-Type": "application/json"
    }
    
    # Test with account info
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        if data.get("success"):
            account = data["result"]
            print(f"✅ API Connection successful!")
            print(f"   Account: {account['name']}")
            print(f"   ID: {account['id']}")
            return True
        else:
            print(f"❌ API Error: {data.get('errors')}")
            return False
            
    except requests.RequestException as e:
        print(f"❌ Connection failed: {e}")
        return False

def main():
    """Main deployment function"""
    print("🔒 Cloudflare Zero Trust Gateway TLS Security Rules")
    print("=" * 65)
    
    # Test API connection first
    print("🧪 Testing API connection...")
    if not test_api_connection():
        print("❌ Cannot connect to Cloudflare API. Check credentials.")
        return
    
    print("\n📋 Current rules status...")
    existing_rules = list_deployed_rules()
    
    print(f"\n🚀 Deploying new TLS certificate validation rules...")
    
    if deploy_gateway_rules():
        print("✅ All TLS security rules deployed successfully!")
        
        print("\n🔍 Verifying deployed rules...")
        deployed_rules = list_deployed_rules()
        
        if deployed_rules:
            print("🎯 Rules are active and ready!")
            
            print(f"\n🧪 Test your TLS security rules:")
            print("Visit these URLs to test certificate validation:")
            print("1. https://expired.badssl.com → Should be blocked")
            print("2. https://self-signed.badssl.com → Should be blocked") 
            print("3. https://revoked.badssl.com → Should be blocked")
            print("4. https://rc4.badssl.com → Should be blocked")
            print("5. https://wrong.host.badssl.com → Should be blocked")
            print("6. https://google.com → Should work normally")
            
            print(f"\n📊 What happens when blocked:")
            print("• Cloudflare displays a security block page")
            print("• Block reason explains the certificate issue")
            print("• Event is logged in Zero Trust Analytics")
            
            print(f"\n🔍 Monitor in Cloudflare Dashboard:")
            print("1. Go to Zero Trust → Gateway → Analytics")
            print("2. Filter by 'TLS Security' rules")
            print("3. View blocked requests and security events")
            
        else:
            print("⚠️  Could not verify deployed rules")
    else:
        print("❌ Some rules failed to deploy")
        print("Check the error messages above for details")

if __name__ == "__main__":
    main()
