#!/usr/bin/env python3
"""
Cloudflare Gateway Rules Restore Script
=======================================

This script restores all Gateway rules from a backup JSON file, recreating them
exactly as they were when exported. It handles precedence conflicts, rule updates,
and provides comprehensive restore capabilities.

Usage:
    ./restore_gateway_rules.py [backup_file.json]

Features:
- Restores all rules with exact configuration
- Handles precedence conflicts automatically  
- Updates existing rules or creates new ones
- Preserves all rule settings and metadata
- Provides detailed restore reporting
- Supports both full and partial restores

Environment variables required:
  * CF_API_KEY    – Cloudflare API key
  * CF_API_EMAIL  – Email address for API key
  * CF_ACCOUNT_ID – Account ID (optional, defaults to UCG-Fiber)
"""

import json
import os
import sys
import requests
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Configuration
API_BASE_URL = "https://api.cloudflare.com/client/v4"
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "0b0ee2b5eaf1fb8a2612e40ab6488052")
API_KEY = os.environ.get("CF_API_KEY")
EMAIL = os.environ.get("CF_API_EMAIL")

if not API_KEY or not EMAIL:
    print("❌ Error: CF_API_KEY and CF_API_EMAIL environment variables are required")
    sys.exit(1)

# Initialize session
session = requests.Session()
session.headers.update({
    "X-Auth-Email": EMAIL,
    "X-Auth-Key": API_KEY,
    "Content-Type": "application/json",
})

class GatewayRuleRestorer:
    def __init__(self):
        self.session = session
        self.account_id = ACCOUNT_ID
        self.stats = {
            "rules_processed": 0,
            "rules_created": 0,
            "rules_updated": 0,
            "rules_failed": 0,
            "precedence_conflicts_resolved": 0,
            "errors": []
        }

    def api_get(self, path: str) -> Dict:
        """Perform GET request to Cloudflare API"""
        url = f"{API_BASE_URL}{path}"
        response = self.session.get(url)
        if not response.ok:
            raise RuntimeError(f"GET {path} failed: {response.status_code} - {response.text}")
        data = response.json()
        if not data.get("success", True):
            raise RuntimeError(f"API error: {data}")
        return data["result"]

    def api_post(self, path: str, payload: Dict) -> Dict:
        """Perform POST request to Cloudflare API"""
        url = f"{API_BASE_URL}{path}"
        response = self.session.post(url, data=json.dumps(payload))
        if not response.ok:
            raise RuntimeError(f"POST {path} failed: {response.status_code} - {response.text}")
        data = response.json()
        if not data.get("success", True):
            raise RuntimeError(f"API error: {data}")
        return data["result"]

    def api_put(self, path: str, payload: Dict) -> Dict:
        """Perform PUT request to Cloudflare API"""
        url = f"{API_BASE_URL}{path}"
        response = self.session.put(url, data=json.dumps(payload))
        if not response.ok:
            raise RuntimeError(f"PUT {path} failed: {response.status_code} - {response.text}")
        data = response.json()
        if not data.get("success", True):
            raise RuntimeError(f"API error: {data}")
        return data["result"]

    def load_backup_file(self, backup_file: str) -> List[Dict]:
        """Load rules from backup JSON file"""
        try:
            with open(backup_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle different backup file formats
            if 'gateway_rules' in data:
                # Full export format with metadata
                rules = data['gateway_rules']
                print(f"📄 Loaded backup from: {backup_file}")
                print(f"📅 Export date: {data.get('export_metadata', {}).get('export_timestamp', 'Unknown')}")
            elif isinstance(data, list):
                # Compact format (rules array only)
                rules = data
                print(f"📄 Loaded compact backup from: {backup_file}")
            else:
                raise ValueError("Invalid backup file format")
            
            print(f"📊 Found {len(rules)} rules in backup")
            return rules
            
        except FileNotFoundError:
            print(f"❌ Error: Backup file '{backup_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ Error: Invalid JSON in backup file - {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error loading backup file: {e}")
            sys.exit(1)

    def get_existing_rules(self) -> Tuple[List[Dict], Dict[str, Dict], Dict[int, Dict]]:
        """Get current Gateway rules and create lookup mappings"""
        try:
            rules = self.api_get(f"/accounts/{self.account_id}/gateway/rules")
            
            # Create lookup maps
            name_map = {rule.get("name"): rule for rule in rules}
            precedence_map = {rule.get("precedence"): rule for rule in rules if rule.get("precedence")}
            
            return rules, name_map, precedence_map
            
        except Exception as e:
            print(f"❌ Error fetching existing rules: {e}")
            return [], {}, {}

    def find_available_precedence(self, desired_precedence: int, precedence_map: Dict[int, Dict]) -> int:
        """Find available precedence value, starting from desired value"""
        precedence = desired_precedence
        while precedence in precedence_map:
            precedence += 1
        if precedence != desired_precedence:
            self.stats["precedence_conflicts_resolved"] += 1
        return precedence

    def prepare_rule_payload(self, rule: Dict, precedence_map: Dict[int, Dict]) -> Dict:
        """Prepare rule payload for API, removing read-only fields"""
        # Remove read-only fields that shouldn't be included in create/update
        readonly_fields = {
            "id", "created_at", "updated_at", "deleted_at", "source_account", "version"
        }
        
        payload = {k: v for k, v in rule.items() if k not in readonly_fields}
        
        # Handle precedence conflicts
        original_precedence = payload.get("precedence")
        if original_precedence and original_precedence in precedence_map:
            new_precedence = self.find_available_precedence(original_precedence, precedence_map)
            if new_precedence != original_precedence:
                payload["precedence"] = new_precedence
                print(f"    ⚠️  Precedence conflict: {original_precedence} → {new_precedence}")
            # Update our map to track this precedence is now used
            precedence_map[new_precedence] = {"name": payload.get("name")}
        
        return payload

    def restore_rule(self, rule: Dict, name_map: Dict[str, Dict], precedence_map: Dict[int, Dict]) -> bool:
        """Restore a single rule"""
        rule_name = rule.get("name", "Unknown")
        
        try:
            payload = self.prepare_rule_payload(rule, precedence_map)
            
            # Check if rule already exists
            if rule_name in name_map:
                # Update existing rule
                existing_rule = name_map[rule_name]
                rule_id = existing_rule["id"]
                
                print(f"  🔄 Updating: {rule_name}")
                self.api_put(f"/accounts/{self.account_id}/gateway/rules/{rule_id}", payload)
                print(f"    ✅ Updated successfully")
                self.stats["rules_updated"] += 1
                
            else:
                # Create new rule
                print(f"  🆕 Creating: {rule_name}")
                self.api_post(f"/accounts/{self.account_id}/gateway/rules", payload)
                print(f"    ✅ Created successfully")
                self.stats["rules_created"] += 1
                
            return True
            
        except Exception as e:
            print(f"    ❌ Failed: {e}")
            self.stats["rules_failed"] += 1
            self.stats["errors"].append({
                "rule_name": rule_name,
                "error": str(e)
            })
            return False

    def restore_rules(self, backup_file: str, dry_run: bool = False, rule_filter: str = None) -> Dict:
        """Main restore function"""
        print("🔄 Cloudflare Gateway Rules Restore")
        print("=" * 60)
        
        if dry_run:
            print("🔍 DRY RUN MODE - No changes will be made")
            print("=" * 60)
        
        # Load backup
        backup_rules = self.load_backup_file(backup_file)
        
        # Apply filter if specified
        if rule_filter:
            original_count = len(backup_rules)
            backup_rules = [r for r in backup_rules if rule_filter.lower() in r.get("name", "").lower()]
            print(f"🔍 Filter '{rule_filter}' applied: {len(backup_rules)}/{original_count} rules selected")
        
        if not backup_rules:
            print("❌ No rules to restore")
            return self.stats
        
        # Get existing rules
        print(f"\n📡 Fetching current Gateway rules...")
        existing_rules, name_map, precedence_map = self.get_existing_rules()
        print(f"📊 Found {len(existing_rules)} existing rules")
        
        # Sort backup rules by precedence for ordered restoration
        backup_rules.sort(key=lambda x: x.get("precedence", 9999))
        
        print(f"\n🚀 Starting restore of {len(backup_rules)} rules...")
        print("=" * 60)
        
        if dry_run:
            # Dry run - analyze what would happen
            for rule in backup_rules:
                rule_name = rule.get("name", "Unknown")
                if rule_name in name_map:
                    print(f"  📝 Would UPDATE: {rule_name}")
                else:
                    print(f"  🆕 Would CREATE: {rule_name}")
            print(f"\n🔍 Dry run complete - {len(backup_rules)} rules analyzed")
            return self.stats
        
        # Actual restore
        for rule in backup_rules:
            self.stats["rules_processed"] += 1
            success = self.restore_rule(rule, name_map, precedence_map)
            
            # Update name_map if rule was created successfully
            if success and rule.get("name") not in name_map:
                name_map[rule.get("name")] = rule
        
        return self.stats

    def print_restore_summary(self, stats: Dict, backup_file: str):
        """Print comprehensive restore summary"""
        print(f"\n📊 Gateway Rules Restore Summary")
        print("=" * 60)
        
        print(f"📁 Backup File: {backup_file}")
        print(f"📅 Restore Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        print(f"📈 Restore Statistics:")
        print(f"   • Total Rules Processed: {stats['rules_processed']}")
        print(f"   • Rules Created: {stats['rules_created']}")
        print(f"   • Rules Updated: {stats['rules_updated']}")
        print(f"   • Rules Failed: {stats['rules_failed']}")
        print(f"   • Precedence Conflicts Resolved: {stats['precedence_conflicts_resolved']}")
        
        success_rate = 0
        if stats['rules_processed'] > 0:
            success_rate = ((stats['rules_created'] + stats['rules_updated']) / stats['rules_processed']) * 100
        print(f"   • Success Rate: {success_rate:.1f}%")
        
        if stats['errors']:
            print(f"\n❌ Failed Rules ({len(stats['errors'])}):")
            for error in stats['errors'][:10]:  # Show first 10 errors
                print(f"   • {error['rule_name']}: {error['error']}")
            if len(stats['errors']) > 10:
                print(f"   ... and {len(stats['errors']) - 10} more errors")
        
        if stats['rules_created'] + stats['rules_updated'] > 0:
            print(f"\n✅ Restore completed successfully!")
            print(f"📚 Next Steps:")
            print(f"  1. Verify rules in Cloudflare Zero Trust dashboard")
            print(f"  2. Test rule functionality: python3 test_all_gateway_rules_dynamic.py") 
            print(f"  3. Monitor Gateway logs for rule effectiveness")
            print(f"  4. Check for any precedence or configuration issues")
        else:
            print(f"\n❌ Restore failed - no rules were created or updated")

def main():
    """Main function with command line argument parsing"""
    parser = argparse.ArgumentParser(description="Restore Cloudflare Gateway rules from backup")
    parser.add_argument("backup_file", nargs="?", help="Backup JSON file to restore from")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be restored without making changes")
    parser.add_argument("--filter", help="Filter rules by name (case-insensitive substring match)")
    parser.add_argument("--list-backups", action="store_true", help="List available backup files")
    
    args = parser.parse_args()
    
    # List available backups
    if args.list_backups:
        print("📁 Available Gateway rule backup files:")
        backup_files = [f for f in os.listdir('.') if f.startswith('gateway_rules_') and f.endswith('.json')]
        if backup_files:
            for i, f in enumerate(sorted(backup_files, reverse=True), 1):
                size = os.path.getsize(f) / 1024
                mtime = datetime.fromtimestamp(os.path.getmtime(f))
                print(f"  {i:2d}. {f} ({size:.1f}KB, {mtime.strftime('%Y-%m-%d %H:%M')})")
        else:
            print("   No backup files found")
        return
    
    # Find backup file
    if not args.backup_file:
        # Find most recent backup
        backup_files = [f for f in os.listdir('.') if f.startswith('gateway_rules_export_') and f.endswith('.json')]
        if not backup_files:
            print("❌ Error: No backup file specified and no gateway_rules_export_*.json files found")
            print("Usage: ./restore_gateway_rules.py <backup_file.json>")
            print("   or: ./restore_gateway_rules.py --list-backups")
            sys.exit(1)
        
        args.backup_file = sorted(backup_files)[-1]  # Most recent
        print(f"ℹ️  Using most recent backup: {args.backup_file}")
    
    # Perform restore
    restorer = GatewayRuleRestorer()
    stats = restorer.restore_rules(args.backup_file, args.dry_run, args.filter)
    restorer.print_restore_summary(stats, args.backup_file)
    
    # Exit with appropriate code
    if stats['rules_created'] + stats['rules_updated'] > 0:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
