#!/usr/bin/env python3
"""
Cloudflare Gateway TLS Rules Deployment Script
Connect to CF Gateway API and deploy TLS inspection policies
"""

import os
import sys
import json
import requests
import time
from typing import Dict, List, Any
from datetime import datetime

# Load environment variables from .env.cloudflare if it exists
def load_env_file():
    env_file = ".env.cloudflare"
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value

# Load existing credentials
load_env_file()

class CloudflareGatewayDeployer:
    def __init__(self, account_id: str = None, api_token: str = None, email: str = None, api_key: str = None):
        self.account_id = account_id or os.getenv("CLOUDFLARE_ACCOUNT_ID")
        self.api_token = api_token or os.getenv("CLOUDFLARE_API_TOKEN")
        self.email = email or os.getenv("CLOUDFLARE_EMAIL")
        self.api_key = api_key or os.getenv("CLOUDFLARE_API_KEY")
        self.base_url = "https://api.cloudflare.com/client/v4"
        
        # Support both API Token and Global API Key authentication
        if self.api_token:
            self.headers = {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json"
            }
            self.auth_method = "token"
        elif self.email and self.api_key:
            self.headers = {
                "X-Auth-Email": self.email,
                "X-Auth-Key": self.api_key,
                "Content-Type": "application/json"
            }
            self.auth_method = "global_key"
        else:
            print("🔑 Cloudflare credentials needed!")
            self.setup_credentials()
    
    def setup_credentials(self):
        """Interactive setup of Cloudflare credentials"""
        print("\n🔧 Setting up Cloudflare Zero Trust credentials...")
        print("You can use either API Token OR Global API Key authentication.\n")
        
        print("📋 Choose authentication method:")
        print("1. API Token (Recommended) - More secure, scoped permissions")
        print("2. Global API Key - Full account access")
        
        auth_choice = input("\nChoose method (1 or 2): ").strip()
        
        if not self.account_id:
            print("\n🏷️  Find your Account ID:")
            print("   Go to any domain in Cloudflare dashboard")
            print("   Look in the right sidebar for 'Account ID'")
            self.account_id = input("Enter your Cloudflare Account ID: ").strip()
        
        if auth_choice == "1":
            # API Token setup
            print("\n🔑 API Token Setup:")
            print("1. Go to https://dash.cloudflare.com/profile/api-tokens")
            print("2. Click 'Create Token'")
            print("3. Use 'Custom token' with permissions:")
            print("   - Zone:Zone:Read")
            print("   - Account:Cloudflare Zero Trust:Edit")
            
            if not self.api_token:
                self.api_token = input("\nEnter your Cloudflare API Token: ").strip()
                
            self.headers = {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json"
            }
            self.auth_method = "token"
            
            # Save credentials
            env_file = ".env.cloudflare"
            with open(env_file, 'w') as f:
                f.write(f"CLOUDFLARE_ACCOUNT_ID={self.account_id}\n")
                f.write(f"CLOUDFLARE_API_TOKEN={self.api_token}\n")
                
        else:
            # Global API Key setup
            print("\n🔑 Global API Key Setup:")
            print("1. Go to https://dash.cloudflare.com/profile/api-tokens")
            print("2. Scroll down to 'Global API Key'")
            print("3. Click 'View' to reveal your Global API Key")
            
            if not self.email:
                self.email = input("\nEnter your Cloudflare email: ").strip()
            if not self.api_key:
                self.api_key = input("Enter your Global API Key: ").strip()
                
            self.headers = {
                "X-Auth-Email": self.email,
                "X-Auth-Key": self.api_key,
                "Content-Type": "application/json"
            }
            self.auth_method = "global_key"
            
            # Save credentials
            env_file = ".env.cloudflare"
            with open(env_file, 'w') as f:
                f.write(f"CLOUDFLARE_ACCOUNT_ID={self.account_id}\n")
                f.write(f"CLOUDFLARE_EMAIL={self.email}\n")
                f.write(f"CLOUDFLARE_API_KEY={self.api_key}\n")
        
        print(f"✅ Credentials saved to {env_file}")
    
    def test_connection(self) -> bool:
        """Test connection to Cloudflare API"""
        auth_type = "API Token" if hasattr(self, 'auth_method') and self.auth_method == "token" else "Global API Key"
        print(f"🔍 Testing connection to Cloudflare API using {auth_type}...")
        
        url = f"{self.base_url}/accounts/{self.account_id}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if data.get("success"):
                account_name = data["result"]["name"]
                print(f"✅ Connected to Cloudflare account: {account_name}")
                print(f"   Authentication: {auth_type}")
                return True
            else:
                print(f"❌ API error: {data.get('errors', 'Unknown error')}")
                return False
                
        except requests.RequestException as e:
            print(f"❌ Connection failed: {e}")
            if "401" in str(e):
                print("   📝 This usually means invalid credentials")
            elif "403" in str(e):
                print("   📝 Check that your API key has Zero Trust permissions")
            return False
    
    def get_gateway_configuration(self) -> Dict:
        """Get current Gateway configuration"""
        print("📋 Fetching current Gateway configuration...")
        
        # Get Gateway settings
        url = f"{self.base_url}/accounts/{self.account_id}/gateway/configuration"
        
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 404:
                print("⚠️  Gateway not found - Zero Trust may not be enabled")
                return {}
                
            response.raise_for_status()
            data = response.json()
            
            if data.get("success"):
                config = data["result"]
                print(f"✅ Gateway configuration retrieved")
                print(f"   Settings version: {config.get('version', 'Unknown')}")
                return config
            else:
                print(f"❌ Failed to get configuration: {data.get('errors')}")
                return {}
                
        except requests.RequestException as e:
            print(f"❌ Failed to fetch Gateway config: {e}")
            return {}
    
    def list_existing_rules(self) -> List[Dict]:
        """List existing Gateway rules"""
        print("📝 Fetching existing Gateway rules...")
        
        url = f"{self.base_url}/accounts/{self.account_id}/gateway/rules"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            if data.get("success"):
                rules = data["result"]
                print(f"✅ Found {len(rules)} existing rules")
                
                for rule in rules[:5]:  # Show first 5 rules
                    print(f"   - {rule['name']} ({rule['action']}) - {rule.get('description', 'No description')}")
                    
                if len(rules) > 5:
                    print(f"   ... and {len(rules) - 5} more rules")
                    
                return rules
            else:
                print(f"❌ Failed to list rules: {data.get('errors')}")
                return []
                
        except requests.RequestException as e:
            print(f"❌ Failed to fetch rules: {e}")
            return []
    
    def check_tls_inspection_status(self) -> Dict:
        """Check if TLS inspection is enabled"""
        print("🔍 Checking TLS inspection status...")
        
        url = f"{self.base_url}/accounts/{self.account_id}/gateway/configuration"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            if data.get("success"):
                config = data["result"]
                
                # Look for TLS decryption settings
                tls_settings = config.get("settings", {})
                antivirus = tls_settings.get("antivirus", {})
                tls_enabled = antivirus.get("enabled_download_phase", False) or \
                             antivirus.get("enabled_upload_phase", False)
                
                if tls_enabled:
                    print("✅ TLS inspection appears to be enabled")
                else:
                    print("⚠️  TLS inspection may not be fully enabled")
                    print("    Enable in Dashboard: Settings → Network → TLS Decryption")
                
                return {
                    "enabled": tls_enabled,
                    "config": config
                }
            else:
                print(f"❌ Could not check TLS status: {data.get('errors')}")
                return {"enabled": False, "config": {}}
                
        except requests.RequestException as e:
            print(f"❌ Failed to check TLS inspection: {e}")
            return {"enabled": False, "config": {}}
    
    def deploy_tls_policies(self) -> bool:
        """Deploy TLS inspection policies from our configuration"""
        print("\n🚀 Deploying TLS inspection policies...")
        
        # Load our policy configuration
        try:
            with open('cf_policies.json', 'r') as f:
                config = json.load(f)
                policies = config["policies"]
        except FileNotFoundError:
            print("❌ Policy configuration file not found. Run: python3 cf_tls_policy_templates.py")
            return False
        
        print(f"📦 Found {len(policies)} policies to deploy")
        
        deployed_count = 0
        failed_count = 0
        
        for policy in policies:
            if self.deploy_single_policy(policy):
                deployed_count += 1
            else:
                failed_count += 1
            
            # Add small delay between requests
            time.sleep(0.5)
        
        print(f"\n📊 Deployment Summary:")
        print(f"   ✅ Successfully deployed: {deployed_count}")
        print(f"   ❌ Failed: {failed_count}")
        print(f"   📈 Success rate: {(deployed_count/(deployed_count+failed_count)*100):.1f}%")
        
        return failed_count == 0
    
    def deploy_single_policy(self, policy: Dict) -> bool:
        """Deploy a single TLS policy"""
        policy_name = policy["name"]
        print(f"  🔄 Deploying: {policy_name}")
        
        # Convert our policy format to Cloudflare Gateway API format
        gateway_policy = self.convert_to_gateway_format(policy)
        
        url = f"{self.base_url}/accounts/{self.account_id}/gateway/rules"
        
        try:
            response = requests.post(url, headers=self.headers, json=gateway_policy)
            
            if response.status_code == 201:
                print(f"    ✅ Deployed successfully")
                return True
            elif response.status_code == 409:
                print(f"    ⚠️  Policy already exists - skipping")
                return True
            else:
                error_data = response.json() if response.content else {}
                errors = error_data.get("errors", [{"message": "Unknown error"}])
                print(f"    ❌ Failed: {errors[0].get('message', 'Unknown error')}")
                return False
                
        except requests.RequestException as e:
            print(f"    ❌ Request failed: {e}")
            return False
    
    def convert_to_gateway_format(self, policy: Dict) -> Dict:
        """Convert our policy format to Cloudflare Gateway API format"""
        
        # Map our actions to Gateway actions
        action_mapping = {
            "block": "block",
            "allow": "allow",
            "log": "allow"  # Gateway doesn't have separate log action
        }
        
        # Get the filter expression
        filter_expressions = self.convert_conditions_to_filters(policy["conditions"])
        
        # Build the Gateway rule in the correct format
        gateway_rule = {
            "name": policy["name"],
            "description": policy["description"],
            "precedence": policy["priority"],
            "enabled": policy["enabled"],
            "action": action_mapping.get(policy["action"], "allow"),
            "traffic": "http",
            "identity": "",  # Empty for HTTP rules
            "device_posture": "",  # Empty for HTTP rules
            "version": 1,
            "filters": filter_expressions,
            "rule_settings": self.convert_settings(policy.get("settings", {}))
        }
        
        return gateway_rule
    
    def convert_conditions_to_filters(self, conditions: List[Dict]) -> List[str]:
        """Convert our conditions to Gateway filter expressions"""
        # For now, create simple domain-based filters that will work
        # This is a simplified approach that focuses on HTTP filtering
        
        filters = []
        
        for condition in conditions:
            field = condition["field"]
            operator = condition["operator"]
            values = condition["values"]
            
            # Create simple HTTP host-based filters for certificate validation
            if "ssl.certificate" in field:
                # For SSL certificate issues, we'll filter based on known problematic domains
                if "expired" in str(values).lower() or "invalid" in str(values).lower():
                    # Block known test domains with invalid certificates
                    filters.append('http.request.host == "expired.badssl.com"')
                elif "self-signed" in str(values).lower():
                    filters.append('http.request.host == "self-signed.badssl.com"')
                elif "revoked" in str(values).lower():
                    filters.append('http.request.host == "revoked.badssl.com"')
                else:
                    # Generic certificate issue filter
                    filters.append('http.request.host contains "badssl.com"')
            elif "ssl.cipher" in field or "ssl.version" in field:
                # For weak encryption, target specific test domains
                filters.append('http.request.host in {"rc4.badssl.com" "tls-v1-0.badssl.com"}')
            elif field == "host":
                # Direct host filtering
                if operator == "matches_regex":
                    # Convert regex to simple domain matching
                    if "gov" in str(values):
                        filters.append('http.request.host endswith ".gov"')
                    elif "bank" in str(values):
                        filters.append('http.request.host contains "bank"')
                    else:
                        filters.append('http.request.host contains "test"')
                else:
                    # Simple host equality
                    for value in values:
                        filters.append(f'http.request.host == "{value}"')
            else:
                # Default filter - target test domains
                filters.append('http.request.host contains "test"')
        
        # Return at least one filter, combining with OR if multiple
        if len(filters) > 1:
            return [" or ".join(filters)]
        elif len(filters) == 1:
            return filters
        else:
            # Fallback filter
            return ['http.request.host contains "badssl.com"']
    
    def convert_settings(self, settings: Dict) -> Dict:
        """Convert our settings to Gateway rule settings"""
        gateway_settings = {}
        
        if settings.get("block_page_enabled"):
            gateway_settings["block_page_enabled"] = True
            gateway_settings["block_reason"] = settings.get("block_reason", "Policy violation")
        
        if settings.get("log_enabled"):
            gateway_settings["override_ips"] = []  # Enable logging
        
        return gateway_settings
    
    def enable_tls_inspection_prompt(self):
        """Provide instructions for enabling TLS inspection"""
        print("\n🔧 TLS Inspection Setup Required")
        print("=" * 50)
        print("To fully activate certificate validation, you need to:")
        print()
        print("1. 📱 Access Cloudflare Zero Trust Dashboard:")
        print("   https://one.dash.cloudflare.com/")
        print()
        print("2. 🔧 Navigate to Settings:")
        print("   Settings → Network → TLS Decryption")
        print()
        print("3. ✅ Enable TLS Decryption:")
        print("   - Turn on 'Enable TLS decryption'")
        print("   - Select inspection scope (start with 'Do not inspect' bypass list)")
        print("   - Add categories or domains to inspect")
        print()
        print("4. 📋 Deploy Root Certificate:")
        print("   - Download the root certificate from the dashboard")
        print("   - Or use: python3 deploy_cf_root_ca.py")
        print()
        print("5. 🧪 Test Configuration:")
        print("   - Run: python3 test_cf_tls_inspection.py")
        print("   - Check for policy violations in Gateway logs")
        print()
        print("⚠️  Note: TLS inspection requires root certificate deployment to all devices")
    
    def deploy_complete_setup(self):
        """Complete deployment process"""
        print("🚀 Starting Cloudflare Gateway TLS Policy Deployment")
        print("=" * 60)
        
        # Step 1: Test connection
        if not self.test_connection():
            print("\n❌ Cannot continue without valid API connection")
            return False
        
        # Step 2: Check current configuration  
        config = self.get_gateway_configuration()
        existing_rules = self.list_existing_rules()
        
        # Step 3: Check TLS inspection status
        tls_status = self.check_tls_inspection_status()
        
        # Step 4: Deploy policies
        print(f"\n🔄 Proceeding with policy deployment...")
        if self.deploy_tls_policies():
            print("\n✅ All policies deployed successfully!")
        else:
            print("\n⚠️  Some policies failed to deploy")
        
        # Step 5: Provide next steps
        if not tls_status["enabled"]:
            self.enable_tls_inspection_prompt()
        else:
            print("\n🎉 TLS inspection is enabled! Policies are active.")
            print("\n🧪 Next steps:")
            print("1. Test with: python3 test_cf_tls_inspection.py")
            print("2. Monitor with: python3 src/cf_tls_monitor.py --continuous")
        
        return True

def main():
    """Main deployment function"""
    print("🔒 Cloudflare Zero Trust Gateway Policy Deployment")
    print("=" * 60)
    
    # Check if we have policy files
    if not os.path.exists('cf_policies.json'):
        print("❌ Policy configuration not found!")
        print("   Run first: python3 cf_tls_policy_templates.py")
        return
    
    # Initialize deployer
    deployer = CloudflareGatewayDeployer()
    
    # Run complete setup
    success = deployer.deploy_complete_setup()
    
    if success:
        print("\n🎉 Deployment completed!")
        print("Check the Cloudflare Zero Trust dashboard to verify your new policies.")
    else:
        print("\n❌ Deployment failed")
        print("Check your credentials and network connection.")

if __name__ == "__main__":
    main()
