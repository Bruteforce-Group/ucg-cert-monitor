#!/usr/bin/env python3
"""
Cloudflare Zero Trust Policy Deployment Script
Deploy TLS inspection policies via Cloudflare API
"""

import requests
import json
import os
from typing import Dict, List

class CloudflarePolicyDeployer:
    def __init__(self, account_id: str, api_token: str):
        self.account_id = account_id
        self.api_token = api_token
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        
    def deploy_http_policy(self, policy_config: Dict) -> bool:
        """Deploy an HTTP policy to Cloudflare Gateway"""
        url = f"{self.base_url}/accounts/{self.account_id}/gateway/rules"
        
        # Convert our policy format to Cloudflare API format
        cf_policy = {
            "name": policy_config["name"],
            "description": policy_config["description"],
            "precedence": policy_config["priority"],
            "enabled": policy_config["enabled"],
            "action": policy_config["action"],
            "filters": self._convert_conditions(policy_config["conditions"]),
            "traffic": "http",
            "rule_settings": policy_config.get("settings", {})
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=cf_policy)
            response.raise_for_status()
            
            result = response.json()
            print(f"✅ Policy '{policy_config['name']}' deployed successfully")
            return True
            
        except requests.RequestException as e:
            print(f"❌ Failed to deploy policy '{policy_config['name']}': {e}")
            return False
            
    def _convert_conditions(self, conditions: List[Dict]) -> List[Dict]:
        """Convert our condition format to Cloudflare format"""
        cf_conditions = []
        
        for condition in conditions:
            cf_condition = {
                "expression": f"{condition['field']} {condition['operator']} {condition['values']}"
            }
            cf_conditions.append(cf_condition)
            
        return cf_conditions
        
    def deploy_all_policies(self, policies_file: str = "cf_policies.json"):
        """Deploy all policies from configuration file"""
        try:
            with open(policies_file, 'r') as f:
                config = json.load(f)
                
            success_count = 0
            total_count = 0
            
            for policy in config.get("policies", []):
                total_count += 1
                if self.deploy_http_policy(policy):
                    success_count += 1
                    
            print(f"\nDeployment complete: {success_count}/{total_count} policies deployed successfully")
            
        except Exception as e:
            print(f"❌ Deployment failed: {e}")

def main():
    # Configuration from environment variables
    account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID")
    api_token = os.getenv("CLOUDFLARE_API_TOKEN")
    
    if not account_id or not api_token:
        print("❌ Please set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN environment variables")
        return
        
    deployer = CloudflarePolicyDeployer(account_id, api_token)
    deployer.deploy_all_policies()

if __name__ == "__main__":
    main()
