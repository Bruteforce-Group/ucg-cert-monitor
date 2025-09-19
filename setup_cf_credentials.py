#!/usr/bin/env python3
"""
Interactive Cloudflare Credentials Setup
Help set up Global API Key authentication for Cloudflare Gateway
"""

import os
import requests

def setup_credentials():
    """Interactive setup of Cloudflare credentials"""
    print("🔧 Cloudflare Zero Trust Credentials Setup")
    print("=" * 50)
    print()
    print("We'll set up Global API Key authentication (recommended for full access)")
    print()
    
    print("📋 How to get your credentials:")
    print("1. 🌐 Go to: https://dash.cloudflare.com/profile/api-tokens")
    print("2. 📜 Scroll down to 'Global API Key' section")
    print("3. 🔍 Click 'View' next to Global API Key")
    print("4. 🔐 Enter your Cloudflare password")
    print("5. 📋 Copy the Global API Key that appears")
    print("6. 🏷️  Get your Account ID from any zone's right sidebar")
    print()
    
    # Get credentials from user
    email = input("Enter your Cloudflare email address: ").strip()
    if not email:
        print("❌ Email is required")
        return False
        
    print()
    api_key = input("Enter your Cloudflare Global API Key: ").strip()
    if not api_key:
        print("❌ Global API Key is required")
        return False
        
    print()
    account_id = input("Enter your Cloudflare Account ID: ").strip()
    if not account_id:
        print("❌ Account ID is required")
        return False
    
    print()
    print("🧪 Testing credentials...")
    
    # Test the credentials
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    
    # Test basic authentication
    try:
        response = requests.get("https://api.cloudflare.com/client/v4/user", headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        if data.get("success"):
            user_email = data["result"]["email"]
            print(f"✅ Authentication successful for: {user_email}")
            
            # Test account access
            account_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}"
            account_response = requests.get(account_url, headers=headers)
            
            if account_response.status_code == 200:
                account_data = account_response.json()
                if account_data.get("success"):
                    account_name = account_data["result"]["name"]
                    print(f"✅ Account access confirmed: {account_name}")
                    
                    # Save credentials
                    env_file = ".env.cloudflare"
                    with open(env_file, 'w') as f:
                        f.write(f"CLOUDFLARE_EMAIL={email}\n")
                        f.write(f"CLOUDFLARE_API_KEY={api_key}\n")
                        f.write(f"CLOUDFLARE_ACCOUNT_ID={account_id}\n")
                    
                    print(f"✅ Credentials saved to {env_file}")
                    print()
                    print("🎉 Setup complete! You can now run:")
                    print("   python3 deploy_to_cf_gateway.py")
                    return True
                else:
                    print(f"❌ Cannot access account: {account_data.get('errors')}")
                    return False
            else:
                print(f"❌ Cannot access account {account_id}")
                print("   Please verify your Account ID is correct")
                return False
        else:
            print(f"❌ Authentication failed: {data.get('errors')}")
            return False
            
    except requests.RequestException as e:
        print(f"❌ Connection failed: {e}")
        return False

def main():
    """Main setup function"""
    success = setup_credentials()
    
    if success:
        print("\n✅ Credentials setup completed successfully!")
        
        # Run the deployment script next
        run_deployment = input("\nWould you like to deploy TLS policies now? (y/n): ").strip().lower()
        if run_deployment in ['y', 'yes']:
            print("\n🚀 Starting deployment...")
            os.system("python3 deploy_to_cf_gateway.py")
    else:
        print("\n❌ Credential setup failed")
        print("Please check your credentials and try again")

if __name__ == "__main__":
    main()
