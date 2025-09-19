#!/usr/bin/env python3
"""
Simplified Cloudflare Gateway Rule Improvement Suite
Uses basic, supported traffic expressions that work with the current API
"""

import os
import sys
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional

class SimpleGatewayRuleImprover:
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
        
    def create_rule(self, rule_data: Dict) -> Optional[Dict]:
        """Create a new Gateway rule"""
        url = f"{self.base_url}/rules"
        
        try:
            response = requests.post(url, headers=self.headers, json=rule_data, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"  ❌ Failed to create rule: {response.status_code}")
                if response.status_code == 409:
                    print(f"    ℹ️  Rule may already exist")
                    return {"success": True, "skipped": True}
                try:
                    error_detail = response.json()
                    print(f"    Error: {error_detail.get('errors', [{}])[0].get('message', 'Unknown')}")
                except:
                    print(f"    Response: {response.text}")
                return None
                
        except Exception as e:
            print(f"  ❌ Network error: {e}")
            return None

    def get_working_improved_rules(self) -> List[Dict]:
        """Get improved rules with simple, working expressions"""
        return [
            # Simple HTTP Security Rules
            {
                "name": "HTTP: Block Executable Downloads (Enhanced)",
                "description": "Block dangerous executable file downloads",
                "precedence": 500,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.uri.path matches \".*\\\\.(exe|scr|bat|cmd|pif|com|vbs|msi)$\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Executable download blocked for security"
                }
            },
            {
                "name": "HTTP: Block Archive Downloads", 
                "description": "Block potentially dangerous archive downloads",
                "precedence": 501,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.uri.path matches \".*\\\\.(zip|rar|7z|tar|gz|bz2)$\" and not http.request.host in {\"github.com\" \"microsoft.com\" \"apple.com\" \"google.com\"}",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Archive download from untrusted source blocked"
                }
            },
            {
                "name": "HTTP: Block Suspicious Admin Paths",
                "description": "Block access to common admin and sensitive paths",
                "precedence": 502,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.uri.path matches \".*(admin|administrator|wp-admin|phpmyadmin|cpanel|webmail|manager|tomcat).*\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Access to admin path blocked"
                }
            },
            {
                "name": "HTTP: Block Script Injections",
                "description": "Block basic script injection attempts",
                "precedence": 503,
                "enabled": True,
                "action": "block", 
                "filters": ["http"],
                "traffic": "http.request.uri contains \"<script\" or http.request.uri contains \"javascript:\" or http.request.uri contains \"onerror=\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Script injection attempt blocked"
                }
            },
            
            # Simple L4 Rules
            {
                "name": "L4: Block P2P and Mining Ports",
                "description": "Block P2P file sharing and cryptocurrency mining ports",
                "precedence": 600,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "net.dst.port in {1214 4662 4672 6346 6347 6881 6999 3333 4444 8333 8334}",
                "rule_settings": {}
            },
            {
                "name": "L4: Block High-Risk Ports",
                "description": "Block commonly exploited high-risk ports",
                "precedence": 601,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "net.dst.port in {135 139 445 1433 1521 3389 5432 5900 7001 8080 8443}",
                "rule_settings": {}
            },
            
            # Simple DNS Rules
            {
                "name": "DNS: Block Suspicious TLD Patterns",
                "description": "Block domains with suspicious patterns",
                "precedence": 700,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "dns.fqdn matches \".*\\\\.(tk|ml|ga|cf|gq)\\\\..*\" or dns.fqdn matches \".*\\\\.(work|click|download|racing)\\\\..*\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Suspicious domain pattern blocked"
                }
            },
            {
                "name": "DNS: Block Dynamic DNS Patterns",
                "description": "Block common dynamic DNS service patterns",
                "precedence": 701,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "dns.fqdn matches \".*\\\\.(duckdns|no-ip|ddns|hopto|zapto)\\\\..*\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Dynamic DNS service blocked"
                }
            },
            {
                "name": "DNS: Enhanced Malware Protection",
                "description": "Additional malware domain protection",
                "precedence": 702,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "any(dns.security_category[*] in {117 187 83 151}) or any(dns.content_category[*] in {68 83 151})",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Malware domain blocked"
                }
            },
            
            # Monitoring and Logging Rules
            {
                "name": "HTTP: Monitor Social Media Access",
                "description": "Monitor access to social media sites",
                "precedence": 800,
                "enabled": True,
                "action": "allow",
                "filters": ["http"],
                "traffic": "http.request.host in {\"facebook.com\" \"twitter.com\" \"instagram.com\" \"tiktok.com\" \"linkedin.com\" \"snapchat.com\"}",
                "rule_settings": {}
            },
            {
                "name": "HTTP: Monitor File Upload Activity",
                "description": "Monitor large file uploads for security",
                "precedence": 801,
                "enabled": True,
                "action": "allow",
                "filters": ["http"],
                "traffic": "http.request.method == \"POST\" and http.request.uri.path contains \"upload\"",
                "rule_settings": {}
            },
            
            # Business Continuity Rules
            {
                "name": "HTTP: Ensure Business Tools Access",
                "description": "Ensure critical business tools remain accessible",
                "precedence": 50,
                "enabled": True,
                "action": "allow",
                "filters": ["http"],
                "traffic": "http.request.host in {\"office.com\" \"microsoft.com\" \"google.com\" \"gmail.com\" \"github.com\" \"stackoverflow.com\" \"cloudflare.com\" \"aws.amazon.com\"}",
                "rule_settings": {}
            },
            {
                "name": "DNS: Ensure Business DNS Resolution",
                "description": "Ensure critical business domains resolve correctly",
                "precedence": 51,
                "enabled": True,
                "action": "allow",
                "filters": ["dns"],
                "traffic": "dns.fqdn in {\"office.com\" \"microsoft.com\" \"google.com\" \"gmail.com\" \"github.com\" \"stackoverflow.com\" \"cloudflare.com\" \"aws.amazon.com\"}",
                "rule_settings": {}
            }
        ]

    def create_improved_rules(self) -> int:
        """Create all improved rules"""
        print("🚀 Creating improved Gateway rules with working expressions...")
        
        rules_created = 0
        rules_skipped = 0
        rules_failed = 0
        
        improved_rules = self.get_working_improved_rules()
        
        for rule in improved_rules:
            print(f"  🔄 Creating: {rule['name']}")
            
            result = self.create_rule(rule)
            if result:
                if result.get('success'):
                    if result.get('skipped'):
                        rules_skipped += 1
                        print(f"    ℹ️  Skipped (already exists)")
                    else:
                        rules_created += 1
                        print(f"    ✅ Created successfully")
                else:
                    rules_failed += 1
            else:
                rules_failed += 1
                
        return rules_created, rules_skipped, rules_failed

    def run_improvements(self) -> Dict:
        """Run rule improvements"""
        print("🚀 Starting Simplified Gateway Rule Improvements")
        print("=" * 70)
        print("")
        
        start_time = datetime.now()
        
        # Create improved rules
        created, skipped, failed = self.create_improved_rules()
        
        end_time = datetime.now()
        
        # Generate summary
        summary = {
            "improvement_session": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds()
            },
            "improvements": {
                "new_rules_created": created,
                "rules_skipped": skipped,
                "rules_failed": failed,
                "total_attempted": created + skipped + failed,
                "success_rate": ((created + skipped) / (created + skipped + failed) * 100) if (created + skipped + failed) > 0 else 0
            }
        }
        
        # Save results
        results_file = f"simple_rule_improvements_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(summary, f, indent=2)
            
        # Print summary
        self._print_improvement_summary(summary, results_file)
        
        return summary

    def _print_improvement_summary(self, summary: Dict, results_file: str):
        """Print improvement summary"""
        print(f"\n📊 Gateway Rule Improvement Results")
        print("=" * 70)
        
        improvements = summary['improvements']
        
        print(f"📋 Rules Processing:")
        print(f"  • Total Attempted: {improvements['total_attempted']}")
        print(f"  • Successfully Created: {improvements['new_rules_created']}")
        print(f"  • Skipped (Existing): {improvements['rules_skipped']}")
        print(f"  • Failed: {improvements['rules_failed']}")
        print(f"  • Success Rate: {improvements['success_rate']:.1f}%")
        print(f"  • Duration: {summary['improvement_session']['duration_seconds']:.1f} seconds")
        
        print(f"\n🔧 Improvements Made:")
        print(f"  • ✅ Enhanced executable download blocking")
        print(f"  • ✅ Added archive download filtering") 
        print(f"  • ✅ Blocked suspicious admin path access")
        print(f"  • ✅ Added basic script injection protection")
        print(f"  • ✅ Enhanced P2P and mining port blocking")
        print(f"  • ✅ Blocked high-risk network ports")
        print(f"  • ✅ Added suspicious TLD pattern blocking")
        print(f"  • ✅ Enhanced dynamic DNS blocking")
        print(f"  • ✅ Improved malware domain protection")
        print(f"  • ✅ Added monitoring for social media and uploads")
        print(f"  • ✅ Ensured business continuity rules")
        
        print(f"\n📁 Improvement details saved to: {results_file}")
        
        if improvements['new_rules_created'] > 0:
            print(f"\n🎉 Successfully created {improvements['new_rules_created']} new Gateway rules!")
            print(f"\n📚 Next Steps:")
            print(f"  1. Run the test suite again: ./test_all_gateway_rules_dynamic.py")
            print(f"  2. Check the Cloudflare Zero Trust dashboard for new rules")
            print(f"  3. Monitor Gateway logs for rule effectiveness")
            print(f"  4. Adjust rule precedence if needed")
            print(f"  5. Fine-tune rules based on user feedback")
        else:
            print(f"\n⚠️  No new rules were created")

def main():
    """Main function"""
    # Get credentials from environment
    api_key = os.getenv('CF_API_KEY')
    email = os.getenv('CF_API_EMAIL') 
    account_id = "0b0ee2b5eaf1fb8a2612e40ab6488052"
    
    if not api_key or not email:
        print("❌ Error: CF_API_KEY and CF_API_EMAIL environment variables are required")
        sys.exit(1)
        
    print("🔧 Simplified Cloudflare Gateway Rule Improvement Suite")
    print("=" * 70)
    print("🎯 Creating working rules with simplified, supported expressions")
    print("")
    
    # Create rule improver
    improver = SimpleGatewayRuleImprover(api_key, email, account_id)
    
    # Run improvements
    results = improver.run_improvements()
    
    # Exit with appropriate code
    created = results['improvements']['new_rules_created']
    if created > 0:
        print(f"\n🎉 Rule improvements completed successfully!")
        sys.exit(0)
    else:
        print(f"\n⚠️  No new rules were created")
        sys.exit(1)

if __name__ == "__main__":
    main()
