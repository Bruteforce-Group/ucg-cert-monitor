#!/usr/bin/env python3
"""
Quick Cloudflare Authentication Test
Test Global API Key or API Token authentication
"""

import os
import requests
import sys

def test_global_api_key(email, api_key, account_id=None):
    """Test Global API Key authentication"""
    print("🔑 Testing Global API Key authentication...")
    
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    
    # Test basic authentication
    url = "https://api.cloudflare.com/client/v4/user"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        if data.get("success"):
            user_email = data["result"]["email"]
            print(f"✅ Authentication successful for: {user_email}")
            
            # Get account information if account_id provided
            if account_id:
                account_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}"
                account_response = requests.get(account_url, headers=headers)
                
                if account_response.status_code == 200:
                    account_data = account_response.json()
                    if account_data.get("success"):
                        account_name = account_data["result"]["name"]
                        print(f"✅ Account access confirmed: {account_name}")
                        return True
                else:
                    print(f"⚠️  Cannot access account {account_id}")
                    print("   Check that the account ID is correct")
            else:
                return True
                
        else:
            print(f"❌ Authentication failed: {data.get('errors')}")
            return False
            
    except requests.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False

def test_api_token(api_token, account_id=None):
    """Test API Token authentication"""
    print("🔑 Testing API Token authentication...")
    
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    # Test token verification
    url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        if data.get("success"):
            token_status = data["result"]["status"]
            print(f"✅ Token verification successful: {token_status}")
            
            # Test account access if account_id provided
            if account_id:
                account_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}"
                account_response = requests.get(account_url, headers=headers)
                
                if account_response.status_code == 200:
                    account_data = account_response.json()
                    if account_data.get("success"):
                        account_name = account_data["result"]["name"]
                        print(f"✅ Account access confirmed: {account_name}")
                        return True
                else:
                    print(f"⚠️  Cannot access account {account_id}")
                    print("   Check token permissions and account ID")
            else:
                return True
                
        else:
            print(f"❌ Token verification failed: {data.get('errors')}")
            return False
            
    except requests.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False

def main():
    """Main testing function"""
    print("🧪 Cloudflare API Authentication Test")
    print("=" * 50)
    
    # Check for environment variables first
    email = os.getenv("CLOUDFLARE_EMAIL")
    api_key = os.getenv("CLOUDFLARE_API_KEY")
    api_token = os.getenv("CLOUDFLARE_API_TOKEN")
    account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID")
    
    # Load from .env.cloudflare if it exists
    env_file = ".env.cloudflare"
    if os.path.exists(env_file):
        print(f"📄 Loading credentials from {env_file}")
        with open(env_file, 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    if key == "CLOUDFLARE_EMAIL":
                        email = value
                    elif key == "CLOUDFLARE_API_KEY":
                        api_key = value
                    elif key == "CLOUDFLARE_API_TOKEN":
                        api_token = value
                    elif key == "CLOUDFLARE_ACCOUNT_ID":
                        account_id = value
    
    print("\n🔍 Found credentials:")
    print(f"   Email: {'✅' if email else '❌'}")
    print(f"   Global API Key: {'✅' if api_key else '❌'}")
    print(f"   API Token: {'✅' if api_token else '❌'}")
    print(f"   Account ID: {'✅' if account_id else '❌'}")
    
    success = False
    
    # Test Global API Key first if available
    if email and api_key:
        print(f"\n{'='*30}")
        if test_global_api_key(email, api_key, account_id):
            success = True
            print("🎉 Global API Key authentication works!")
        else:
            print("❌ Global API Key authentication failed")
    
    # Test API Token if available
    if api_token:
        print(f"\n{'='*30}")
        if test_api_token(api_token, account_id):
            success = True
            print("🎉 API Token authentication works!")
        else:
            print("❌ API Token authentication failed")
    
    if not success:
        print("\n❌ No working authentication method found")
        print("\n💡 To set up credentials:")
        print("1. Go to https://dash.cloudflare.com/profile/api-tokens")
        print("2. For Global API Key: scroll down and click 'View' next to Global API Key")
        print("3. For API Token: click 'Create Token' and set up custom permissions")
        print("4. Run this test again to verify")
        sys.exit(1)
    else:
        print(f"\n✅ Authentication test passed!")
        print("You can now run: python3 deploy_to_cf_gateway.py")

if __name__ == "__main__":
    main()
