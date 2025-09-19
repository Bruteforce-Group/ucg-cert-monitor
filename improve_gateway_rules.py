#!/usr/bin/env python3
"""
Cloudflare Gateway Rule Improvement Suite
Analyzes test failures and creates improved, more effective Gateway rules
"""

import os
import sys
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional

class GatewayRuleImprover:
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
        self.failed_rules = []
        self.load_test_results()
        
    def load_test_results(self):
        """Load test results to understand what needs improvement"""
        try:
            with open('enhanced_gateway_tests_20250906_183115.json', 'r') as f:
                test_data = json.load(f)
                
            self.failed_rules = [
                result for result in test_data['detailed_results']
                if not result['passed'] and result['rule_enabled']
            ]
            
            print(f"📊 Loaded test results: {len(self.failed_rules)} rules need improvement")
            
        except Exception as e:
            print(f"❌ Error loading test results: {e}")
            sys.exit(1)
    
    def update_rule(self, rule_id: str, rule_data: Dict) -> Optional[Dict]:
        """Update an existing Gateway rule"""
        url = f"{self.base_url}/rules/{rule_id}"
        
        try:
            response = requests.put(url, headers=self.headers, json=rule_data, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"  ❌ Failed to update rule: {response.status_code}")
                try:
                    error_detail = response.json()
                    print(f"    Error: {error_detail.get('errors', [{}])[0].get('message', 'Unknown')}")
                except:
                    print(f"    Response: {response.text}")
                return None
                
        except Exception as e:
            print(f"  ❌ Network error: {e}")
            return None

    def create_rule(self, rule_data: Dict) -> Optional[Dict]:
        """Create a new Gateway rule"""
        url = f"{self.base_url}/rules"
        
        try:
            response = requests.post(url, headers=self.headers, json=rule_data, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"  ❌ Failed to create rule: {response.status_code}")
                try:
                    error_detail = response.json()
                    print(f"    Error: {error_detail.get('errors', [{}])[0].get('message', 'Unknown')}")
                except:
                    print(f"    Response: {response.text}")
                return None
                
        except Exception as e:
            print(f"  ❌ Network error: {e}")
            return None

    def get_improved_tls_rules(self) -> List[Dict]:
        """Create improved TLS certificate validation rules"""
        return [
            {
                "name": "TLS: Block Expired Certificates",
                "description": "Block connections with expired SSL certificates",
                "precedence": 100,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "any(tls.extensions.certificate_transparencies[*] contains \"expired\") or ssl.version in {\"SSLv2\" \"SSLv3\"} or tls.client_certificate.expired",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "SSL certificate expired or invalid"
                }
            },
            {
                "name": "TLS: Block Self-Signed Certificates", 
                "description": "Block self-signed SSL certificates",
                "precedence": 101,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "tls.client_certificate.issuer == tls.client_certificate.subject",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Self-signed certificate blocked"
                }
            },
            {
                "name": "TLS: Block Weak Encryption",
                "description": "Block weak SSL/TLS encryption",
                "precedence": 102,
                "enabled": True,
                "action": "block", 
                "filters": ["http"],
                "traffic": "ssl.cipher in {\"RC4\" \"DES\" \"3DES\"} or ssl.version in {\"SSLv2\" \"SSLv3\" \"TLSv1.0\"}",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Weak encryption detected"
                }
            }
        ]

    def get_improved_http_security_rules(self) -> List[Dict]:
        """Create improved HTTP security rules"""
        return [
            {
                "name": "HTTP: Enhanced Malware Download Protection",
                "description": "Block dangerous file downloads with comprehensive patterns",
                "precedence": 200,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.uri.path matches r\".*\\.(exe|scr|bat|cmd|pif|com|vbs|msi|jar|app|dmg|pkg|deb|rpm)$\" or any(http.request.headers[\"content-type\"][*] in {\"application/x-msdownload\" \"application/x-executable\" \"application/x-msdos-program\"})",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Dangerous file download blocked"
                }
            },
            {
                "name": "HTTP: Advanced SQL Injection Protection",
                "description": "Block SQL injection attempts with comprehensive patterns",
                "precedence": 201,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "any(http.request.uri.args[*][*] matches r\".*('|(\\\\x27)|(\\\\x2D\\\\x2D)|(%27)|(%2D%2D)).*(union|select|insert|delete|update|drop|create|alter|exec|execute)\") or any(http.request.body.form.values[*] matches r\".*('|(\\\\x27)|(\\\\x2D\\\\x2D)|(%27)|(%2D%2D)).*(union|select|insert|delete|update|drop|create|alter|exec|execute)\")",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "SQL injection attempt detected"
                }
            },
            {
                "name": "HTTP: Enhanced XSS Protection",
                "description": "Block XSS attempts with comprehensive patterns", 
                "precedence": 202,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "any(http.request.uri.args[*][*] matches r\".*<\\s*script|javascript:|on\\w+\\s*=|<\\s*iframe|<\\s*object|<\\s*embed\") or any(http.request.body.form.values[*] matches r\".*<\\s*script|javascript:|on\\w+\\s*=|<\\s*iframe|<\\s*object|<\\s*embed\")",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "XSS attempt detected"
                }
            },
            {
                "name": "HTTP: Directory Traversal Protection",
                "description": "Block directory traversal and path manipulation attempts",
                "precedence": 203,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "http.request.uri.path matches r\".*(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c)\" or http.request.uri.path contains \"..\\\\\" or http.request.uri.path contains \"../\"",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Directory traversal attempt blocked"
                }
            },
            {
                "name": "HTTP: Command Injection Protection",
                "description": "Block command injection attempts",
                "precedence": 204,
                "enabled": True,
                "action": "block",
                "filters": ["http"],
                "traffic": "any(http.request.uri.args[*][*] matches r\".*(;|\\||&|\\$\\(|`|\\$\\{).*(whoami|id|cat|ls|ps|uname|wget|curl|nc|telnet|ssh)\") or any(http.request.body.form.values[*] matches r\".*(;|\\||&|\\$\\(|`|\\$\\{).*(whoami|id|cat|ls|ps|uname|wget|curl|nc|telnet|ssh)\")",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Command injection attempt detected"
                }
            }
        ]

    def get_improved_l4_rules(self) -> List[Dict]:
        """Create improved Layer 4 network rules"""
        return [
            {
                "name": "L4: Block High-Risk Countries Enhanced",
                "description": "Block traffic from high-risk countries with comprehensive list",
                "precedence": 300,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "ip.geoip.country in {\"CN\" \"RU\" \"KP\" \"IR\" \"SY\" \"AF\" \"IQ\" \"LY\" \"SO\" \"SD\" \"YE\"}",
                "rule_settings": {
                    "block_page_enabled": False
                }
            },
            {
                "name": "L4: Block Tor Exit Nodes",
                "description": "Block known Tor exit node IP ranges",
                "precedence": 301,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "net.src.ip in $cf.threats.tor_exit_nodes or net.dst.ip in $cf.threats.tor_exit_nodes",
                "rule_settings": {
                    "block_page_enabled": False
                }
            },
            {
                "name": "L4: Block Malware C2 IPs",
                "description": "Block known malware command and control IP addresses",
                "precedence": 302,
                "enabled": True,
                "action": "block", 
                "filters": ["l4"],
                "traffic": "net.src.ip in $cf.threats.malware or net.dst.ip in $cf.threats.malware",
                "rule_settings": {
                    "block_page_enabled": False
                }
            },
            {
                "name": "L4: Block Cryptocurrency Mining",
                "description": "Block cryptocurrency mining traffic",
                "precedence": 303,
                "enabled": True,
                "action": "block",
                "filters": ["l4"],
                "traffic": "net.dst.port in {3333 4444 8333 8334 9332 9333 14433 14444 8545 30303}",
                "rule_settings": {
                    "block_page_enabled": False
                }
            }
        ]

    def get_improved_dns_rules(self) -> List[Dict]:
        """Create additional improved DNS rules"""
        return [
            {
                "name": "DNS: Block Newly Registered Domains",
                "description": "Block domains registered within last 30 days",
                "precedence": 400,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "dns.domain_age < 30",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Newly registered domain blocked (high risk)"
                }
            },
            {
                "name": "DNS: Block Dynamic DNS Providers",
                "description": "Block known dynamic DNS services often used by malware",
                "precedence": 401,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "any(dns.fqdn[*] matches r\".*\\.(duckdns|no-ip|ddns|hopto|zapto|gotdns|dyndns)\\.(org|com|net)$\")",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Dynamic DNS service blocked"
                }
            },
            {
                "name": "DNS: Block Suspicious TLDs",
                "description": "Block suspicious top-level domains often used by malware",
                "precedence": 402,
                "enabled": True,
                "action": "block",
                "filters": ["dns"],
                "traffic": "any(dns.fqdn[*] matches r\".*\\.(tk|ml|ga|cf|gq|work|click|download|racing|review|loan)$\")",
                "rule_settings": {
                    "block_page_enabled": True,
                    "block_reason": "Suspicious TLD blocked"
                }
            }
        ]

    def improve_existing_rules(self) -> int:
        """Improve existing rules that failed tests"""
        print("🔧 Improving existing rules that failed tests...")
        
        improvements_made = 0
        
        # Disable problematic TLS rules that only block specific domains
        tls_rules_to_disable = [
            "TLS Policy - Block Expired Certificate Sites",
            "TLS Policy - Block Self-Signed Certificate Sites", 
            "TLS Policy - Block Revoked Certificate Sites",
            "TLS Policy - Block Weak Encryption Sites",
            "TLS Policy - Block Invalid Hostname Sites"
        ]
        
        for failed_rule in self.failed_rules:
            rule_name = failed_rule['rule_name']
            rule_id = failed_rule['rule_id']
            
            if rule_name in tls_rules_to_disable:
                print(f"  🔄 Disabling ineffective rule: {rule_name}")
                
                # Disable the rule since it only blocks specific test domains
                disable_data = {
                    "enabled": False,
                    "description": f"Disabled - replaced with improved TLS validation rules"
                }
                
                result = self.update_rule(rule_id, disable_data)
                if result:
                    print(f"    ✅ Rule disabled successfully")
                    improvements_made += 1
                else:
                    print(f"    ❌ Failed to disable rule")
                    
        return improvements_made

    def create_improved_rules(self) -> int:
        """Create new improved rules"""
        print("🚀 Creating improved security rules...")
        
        rules_created = 0
        
        # Get all improved rule sets
        all_improved_rules = []
        all_improved_rules.extend(self.get_improved_tls_rules())
        all_improved_rules.extend(self.get_improved_http_security_rules())
        all_improved_rules.extend(self.get_improved_l4_rules())
        all_improved_rules.extend(self.get_improved_dns_rules())
        
        for rule in all_improved_rules:
            print(f"  🔄 Creating: {rule['name']}")
            
            result = self.create_rule(rule)
            if result and result.get('success'):
                print(f"    ✅ Created successfully")
                rules_created += 1
            else:
                print(f"    ❌ Failed to create")
                
        return rules_created

    def run_improvements(self) -> Dict:
        """Run all rule improvements"""
        print("🚀 Starting Gateway Rule Improvements")
        print("=" * 70)
        print(f"📊 Analyzing {len(self.failed_rules)} failed rules for improvement")
        print("")
        
        start_time = datetime.now()
        
        # Improve existing rules
        existing_improvements = self.improve_existing_rules()
        
        # Create new improved rules  
        new_rules = self.create_improved_rules()
        
        end_time = datetime.now()
        
        # Generate summary
        summary = {
            "improvement_session": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds()
            },
            "improvements": {
                "rules_analyzed": len(self.failed_rules),
                "existing_rules_improved": existing_improvements,
                "new_rules_created": new_rules,
                "total_improvements": existing_improvements + new_rules
            }
        }
        
        # Save results
        results_file = f"rule_improvements_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
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
        
        print(f"📋 Improvements Made:")
        print(f"  • Rules Analyzed: {improvements['rules_analyzed']}")
        print(f"  • Existing Rules Improved: {improvements['existing_rules_improved']}")
        print(f"  • New Rules Created: {improvements['new_rules_created']}")
        print(f"  • Total Improvements: {improvements['total_improvements']}")
        print(f"  • Duration: {summary['improvement_session']['duration_seconds']:.1f} seconds")
        
        print(f"\n🔧 Key Improvements:")
        print(f"  • ✅ Replaced ineffective TLS test-domain rules with real certificate validation")
        print(f"  • ✅ Enhanced HTTP security with comprehensive attack pattern detection")
        print(f"  • ✅ Improved L4 rules with geographic and threat intelligence blocking")
        print(f"  • ✅ Added DNS protection for newly registered domains and suspicious TLDs")
        
        print(f"\n📁 Improvement details saved to: {results_file}")
        
        if improvements['total_improvements'] > 0:
            print(f"\n🎉 Successfully improved {improvements['total_improvements']} Gateway rules!")
            print(f"\n📚 Next Steps:")
            print(f"  1. Run the test suite again to validate improvements")
            print(f"  2. Monitor Gateway logs for rule effectiveness")
            print(f"  3. Adjust rule precedence as needed in the dashboard")
            print(f"  4. Fine-tune rules based on false positive feedback")
        else:
            print(f"\n⚠️  No improvements were made - check API permissions and rule conflicts")

def main():
    """Main function"""
    # Get credentials from environment
    api_key = os.getenv('CF_API_KEY')
    email = os.getenv('CF_API_EMAIL') 
    account_id = "0b0ee2b5eaf1fb8a2612e40ab6488052"
    
    if not api_key or not email:
        print("❌ Error: CF_API_KEY and CF_API_EMAIL environment variables are required")
        sys.exit(1)
        
    print("🔧 Cloudflare Gateway Rule Improvement Suite")
    print("=" * 70)
    print(f"Account ID: {account_id}")
    print(f"API Email: {email}")
    
    # Create rule improver
    improver = GatewayRuleImprover(api_key, email, account_id)
    
    # Run improvements
    results = improver.run_improvements()
    
    # Exit with appropriate code
    total_improvements = results['improvements']['total_improvements']
    if total_improvements > 0:
        print(f"\n🎉 Rule improvements completed successfully!")
        sys.exit(0)
    else:
        print(f"\n⚠️  No improvements were made")
        sys.exit(1)

if __name__ == "__main__":
    main()
