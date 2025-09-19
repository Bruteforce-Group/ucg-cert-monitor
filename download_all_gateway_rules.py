#!/usr/bin/env python3
"""
Download All Cloudflare Gateway Rules in JSON Format
Exports all rules with complete configuration details
"""

import os
import sys
import json
import requests
from datetime import datetime

class GatewayRuleDownloader:
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
        
    def download_all_rules(self) -> dict:
        """Download all Gateway rules"""
        url = f"{self.base_url}/rules"
        
        try:
            print("📡 Fetching all Gateway rules from Cloudflare API...")
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Successfully retrieved {len(data['result'])} rules")
                return data
            else:
                print(f"❌ Failed to fetch rules: {response.status_code}")
                try:
                    error_detail = response.json()
                    print(f"   Error: {error_detail}")
                except:
                    print(f"   Response: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Network error: {e}")
            return None

    def save_rules_json(self, rules_data: dict, filename: str = None) -> str:
        """Save rules to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"gateway_rules_export_{timestamp}.json"
            
        filepath = f"/Users/danielborrowman/ucg-cert-monitor/{filename}"
        
        # Create enhanced export with metadata
        export_data = {
            "export_metadata": {
                "export_timestamp": datetime.now().isoformat(),
                "export_source": "Cloudflare Gateway API",
                "account_id": self.account_id,
                "total_rules": len(rules_data['result']),
                "api_response_success": rules_data.get('success', False)
            },
            "gateway_rules": rules_data['result'],
            "raw_api_response": rules_data
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            print(f"💾 Rules exported to: {filename}")
            return filepath
            
        except Exception as e:
            print(f"❌ Failed to save JSON file: {e}")
            return None

    def print_rules_summary(self, rules_data: dict):
        """Print summary of downloaded rules"""
        if not rules_data or 'result' not in rules_data:
            return
            
        rules = rules_data['result']
        
        print(f"\n📊 Gateway Rules Summary")
        print("=" * 50)
        
        # Count by type and status
        by_type = {}
        by_status = {"enabled": 0, "disabled": 0}
        by_action = {}
        
        for rule in rules:
            # Count by type
            rule_filters = rule.get('filters', ['unknown'])
            for filter_type in rule_filters:
                by_type[filter_type] = by_type.get(filter_type, 0) + 1
                
            # Count by status
            if rule.get('enabled', False):
                by_status['enabled'] += 1
            else:
                by_status['disabled'] += 1
                
            # Count by action
            action = rule.get('action', 'unknown')
            by_action[action] = by_action.get(action, 0) + 1
        
        print(f"📈 Total Rules: {len(rules)}")
        print(f"   • Enabled: {by_status['enabled']}")
        print(f"   • Disabled: {by_status['disabled']}")
        
        print(f"\n🔧 Rules by Type:")
        for rule_type, count in sorted(by_type.items()):
            print(f"   • {rule_type.upper()}: {count}")
            
        print(f"\n🎯 Rules by Action:")
        for action, count in sorted(by_action.items()):
            print(f"   • {action.capitalize()}: {count}")

    def run_export(self) -> str:
        """Run the complete export process"""
        print("🔄 Cloudflare Gateway Rules Export")
        print("=" * 50)
        
        # Download rules
        rules_data = self.download_all_rules()
        if not rules_data:
            print("❌ Failed to download rules")
            return None
            
        # Print summary
        self.print_rules_summary(rules_data)
        
        # Save to JSON
        filepath = self.save_rules_json(rules_data)
        if filepath:
            print(f"\n✅ Export completed successfully!")
            print(f"📁 File saved at: {filepath}")
            
            # Show file size
            try:
                file_size = os.path.getsize(filepath)
                if file_size > 1024 * 1024:
                    size_str = f"{file_size / (1024*1024):.1f}MB"
                elif file_size > 1024:
                    size_str = f"{file_size / 1024:.1f}KB"
                else:
                    size_str = f"{file_size}B"
                print(f"📏 File size: {size_str}")
            except:
                pass
                
            return filepath
        else:
            print("❌ Export failed")
            return None

def main():
    """Main function"""
    # Get credentials from environment
    api_key = os.getenv('CF_API_KEY')
    email = os.getenv('CF_API_EMAIL') 
    account_id = "0b0ee2b5eaf1fb8a2612e40ab6488052"
    
    if not api_key or not email:
        print("❌ Error: CF_API_KEY and CF_API_EMAIL environment variables are required")
        sys.exit(1)
        
    # Create downloader and run export
    downloader = GatewayRuleDownloader(api_key, email, account_id)
    filepath = downloader.run_export()
    
    if filepath:
        print(f"\n📚 Next Steps:")
        print(f"  • Review the exported rules: cat {os.path.basename(filepath)}")
        print(f"  • Use jq for filtering: cat {os.path.basename(filepath)} | jq '.gateway_rules[] | select(.enabled==true)'")
        print(f"  • Import to other tools or backup systems")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
