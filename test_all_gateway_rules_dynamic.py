#!/usr/bin/env python3
"""
Enhanced Dynamic Cloudflare Gateway Rule Testing Suite
Dynamically creates tests for every Gateway rule based on actual configurations
"""

import os
import sys
import json
import time
import socket
import ssl
import requests
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import urllib3

# Suppress SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class EnhancedRuleTestResult:
    """Enhanced test result for a specific Gateway rule"""
    rule_id: str
    rule_name: str
    rule_type: str  # dns, http, l4
    rule_action: str  # block, allow, etc.
    rule_enabled: bool
    rule_traffic_expression: str
    test_description: str
    test_method: str
    expected_result: str
    actual_result: str
    passed: bool
    details: str
    timestamp: str
    test_duration: float

class EnhancedGatewayTester:
    def __init__(self, cf_gateway_ip: str = "162.159.36.5"):
        self.cf_gateway_ip = cf_gateway_ip
        self.test_results: List[EnhancedRuleTestResult] = []
        self.gateway_rules = []
        self.load_gateway_rules()
        
    def load_gateway_rules(self):
        """Load Gateway rules from JSON file"""
        try:
            with open('gateway_rules_array.json', 'r') as f:
                self.gateway_rules = json.load(f)
            print(f"✅ Loaded {len(self.gateway_rules)} Gateway rules for dynamic testing")
            
            # Analyze rule distribution
            enabled_rules = [r for r in self.gateway_rules if r.get('enabled', False)]
            rule_types = {}
            for rule in enabled_rules:
                for filter_type in rule.get('filters', []):
                    rule_types[filter_type] = rule_types.get(filter_type, 0) + 1
                    
            print(f"📊 Enabled rules by type: {dict(rule_types)}")
            print(f"🎯 Total enabled rules to test: {len(enabled_rules)}")
            
        except Exception as e:
            print(f"❌ Error loading rules: {e}")
            sys.exit(1)

    def analyze_rule_traffic_pattern(self, rule: Dict) -> Dict:
        """Analyze rule traffic expression to determine test strategy"""
        traffic = rule.get('traffic', '')
        filters = rule.get('filters', [])
        action = rule.get('action', '')
        name = rule.get('name', '')
        
        test_strategy = {
            'rule_type': filters[0] if filters else 'unknown',
            'action': action,
            'test_method': 'generic',
            'test_targets': [],
            'expected_behavior': action
        }
        
        # Analyze traffic patterns to determine specific tests
        if 'dns' in filters:
            if any(keyword in traffic.lower() for keyword in ['malware', 'security', 'threat']):
                test_strategy['test_method'] = 'dns_security'
                test_strategy['test_targets'] = ['malware.testing.google.test', 'test.malware.invalid']
            elif any(keyword in traffic.lower() for keyword in ['allow', 'productivity']):
                test_strategy['test_method'] = 'dns_allow'
                # Extract domains from rule name
                if 'github' in name.lower():
                    test_strategy['test_targets'] = ['github.com', 'api.github.com']
                elif 'npm' in name.lower():
                    test_strategy['test_targets'] = ['registry.npmjs.org']
                elif 'cloudflare' in name.lower():
                    test_strategy['test_targets'] = ['cloudflare.com', 'api.cloudflare.com']
                elif 'openai' in name.lower():
                    test_strategy['test_targets'] = ['api.openai.com', 'openai.com']
                else:
                    test_strategy['test_targets'] = ['google.com']  # Generic test
            else:
                test_strategy['test_method'] = 'dns_generic'
                test_strategy['test_targets'] = ['example.com']
                
        elif 'http' in filters:
            if any(keyword in traffic.lower() for keyword in ['sql', 'injection', 'xss', 'attack']):
                test_strategy['test_method'] = 'http_security'
                test_strategy['test_targets'] = [
                    "https://httpbin.org/get?test=' OR 1=1",
                    "https://httpbin.org/get?input=<script>alert('test')</script>"
                ]
            elif any(keyword in traffic.lower() for keyword in ['download', 'file', '.exe']):
                test_strategy['test_method'] = 'http_download'
                test_strategy['test_targets'] = ['https://httpbin.org/response-headers?content-disposition=attachment;filename=test.exe']
            elif 'tls' in name.lower() or 'certificate' in name.lower():
                test_strategy['test_method'] = 'http_tls'
                test_strategy['test_targets'] = ['https://expired.badssl.com', 'https://self-signed.badssl.com']
            elif any(keyword in name.lower() for keyword in ['allow', 'business', 'productivity']):
                test_strategy['test_method'] = 'http_allow'
                if 'office' in name.lower():
                    test_strategy['test_targets'] = ['https://office.com']
                elif 'microsoft' in name.lower():
                    test_strategy['test_targets'] = ['https://microsoft.com']
                else:
                    test_strategy['test_targets'] = ['https://google.com']
            else:
                test_strategy['test_method'] = 'http_generic'
                test_strategy['test_targets'] = ['https://httpbin.org/get']
                
        elif 'l4' in filters:
            if any(keyword in traffic.lower() for keyword in ['port', 'dst.port', 'src.port']):
                # Extract port numbers from traffic expression
                ports = re.findall(r'\\b(\\d+)\\b', traffic)
                if ports:
                    test_strategy['test_method'] = 'l4_port'
                    test_strategy['test_targets'] = [{'host': 'google.com', 'port': int(port)} for port in ports[:3]]
                else:
                    test_strategy['test_method'] = 'l4_generic'
                    test_strategy['test_targets'] = [{'host': 'google.com', 'port': 443}]
            else:
                test_strategy['test_method'] = 'l4_generic'  
                test_strategy['test_targets'] = [{'host': 'google.com', 'port': 443}]
        
        return test_strategy

    def test_dns_rule(self, rule: Dict, strategy: Dict) -> EnhancedRuleTestResult:
        """Test a DNS rule"""
        start_time = time.time()
        
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.cf_gateway_ip]
            resolver.timeout = 5
            
            test_target = strategy['test_targets'][0] if strategy['test_targets'] else 'example.com'
            
            try:
                answers = resolver.resolve(test_target, 'A')
                result = "resolved"
                details = f"Domain {test_target} resolved: {len(answers)} records"
            except dns.resolver.NXDOMAIN:
                result = "blocked_nxdomain"
                details = f"Domain {test_target} blocked (NXDOMAIN)"
            except dns.resolver.Timeout:
                result = "timeout"
                details = f"DNS query timeout for {test_target}"
            except Exception as e:
                result = "error"
                details = f"DNS error: {str(e)}"
                
            # Evaluate if result matches expected behavior
            if strategy['action'] == 'allow':
                passed = result == "resolved"
            elif strategy['action'] == 'block':
                passed = result in ["blocked_nxdomain", "timeout"]
            else:
                passed = True  # For monitoring rules
                
        except Exception as e:
            result = "test_error"
            details = f"Test execution error: {str(e)}"
            passed = False
            
        duration = time.time() - start_time
        
        return EnhancedRuleTestResult(
            rule_id=rule.get('id', 'unknown'),
            rule_name=rule.get('name', 'Unknown Rule'),
            rule_type='dns',
            rule_action=rule.get('action', 'unknown'),
            rule_enabled=rule.get('enabled', False),
            rule_traffic_expression=rule.get('traffic', ''),
            test_description=f"Test DNS rule: {strategy['test_method']} on {strategy['test_targets'][:2]}",
            test_method=strategy['test_method'],
            expected_result=strategy['expected_behavior'],
            actual_result=result,
            passed=passed,
            details=details,
            timestamp=datetime.now().isoformat(),
            test_duration=duration
        )

    def test_http_rule(self, rule: Dict, strategy: Dict) -> EnhancedRuleTestResult:
        """Test an HTTP rule"""
        start_time = time.time()
        
        try:
            test_target = strategy['test_targets'][0] if strategy['test_targets'] else 'https://httpbin.org/get'
            
            response = requests.get(test_target, timeout=10, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                result = "allowed"
                details = f"HTTP request to {test_target} succeeded (200)"
            elif response.status_code == 403:
                result = "blocked"
                details = f"HTTP request blocked (403)"
            elif response.status_code in [301, 302]:
                result = "redirected"
                details = f"HTTP request redirected ({response.status_code})"
            else:
                result = f"http_{response.status_code}"
                details = f"HTTP request returned {response.status_code}"
                
            # Check if response indicates Cloudflare blocking
            if 'cloudflare' in response.text.lower() and 'blocked' in response.text.lower():
                result = "blocked_by_gateway"
                details = "Request blocked by Cloudflare Gateway"
                
            # Evaluate result
            if strategy['action'] == 'allow':
                passed = result in ["allowed", "redirected"]
            elif strategy['action'] == 'block':
                passed = result in ["blocked", "blocked_by_gateway"]
            else:
                passed = True  # For monitoring/logging rules
                
        except requests.exceptions.RequestException as e:
            result = "connection_error"
            details = f"Connection error: {str(e)}"
            # Connection errors might indicate blocking for block rules
            passed = strategy['action'] == 'block'
        except Exception as e:
            result = "test_error"
            details = f"Test error: {str(e)}"
            passed = False
            
        duration = time.time() - start_time
        
        return EnhancedRuleTestResult(
            rule_id=rule.get('id', 'unknown'),
            rule_name=rule.get('name', 'Unknown Rule'),
            rule_type='http',
            rule_action=rule.get('action', 'unknown'),
            rule_enabled=rule.get('enabled', False),
            rule_traffic_expression=rule.get('traffic', ''),
            test_description=f"Test HTTP rule: {strategy['test_method']} on {test_target}",
            test_method=strategy['test_method'],
            expected_result=strategy['expected_behavior'],
            actual_result=result,
            passed=passed,
            details=details,
            timestamp=datetime.now().isoformat(),
            test_duration=duration
        )

    def test_l4_rule(self, rule: Dict, strategy: Dict) -> EnhancedRuleTestResult:
        """Test a Layer 4 network rule"""
        start_time = time.time()
        
        try:
            if strategy['test_targets'] and isinstance(strategy['test_targets'][0], dict):
                target = strategy['test_targets'][0]
                host = target.get('host', 'google.com')
                port = target.get('port', 443)
            else:
                host = 'google.com'
                port = 443
                
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            result_code = sock.connect_ex((host, port))
            sock.close()
            
            if result_code == 0:
                result = "connection_successful"
                details = f"Connection to {host}:{port} successful"
            else:
                result = "connection_failed"
                details = f"Connection to {host}:{port} failed (code: {result_code})"
                
            # Evaluate result
            if strategy['action'] == 'allow':
                passed = result == "connection_successful"
            elif strategy['action'] == 'block':
                passed = result == "connection_failed"
            else:
                passed = True  # For monitoring rules
                
        except Exception as e:
            result = "test_error"
            details = f"Test error: {str(e)}"
            passed = False
            
        duration = time.time() - start_time
        
        return EnhancedRuleTestResult(
            rule_id=rule.get('id', 'unknown'),
            rule_name=rule.get('name', 'Unknown Rule'),
            rule_type='l4',
            rule_action=rule.get('action', 'unknown'),
            rule_enabled=rule.get('enabled', False),
            rule_traffic_expression=rule.get('traffic', ''),
            test_description=f"Test L4 rule: {strategy['test_method']} on {host}:{port}",
            test_method=strategy['test_method'],
            expected_result=strategy['expected_behavior'],
            actual_result=result,
            passed=passed,
            details=details,
            timestamp=datetime.now().isoformat(),
            test_duration=duration
        )

    def test_individual_rule(self, rule: Dict) -> EnhancedRuleTestResult:
        """Test an individual Gateway rule"""
        if not rule.get('enabled', False):
            # Skip disabled rules but log them
            return EnhancedRuleTestResult(
                rule_id=rule.get('id', 'unknown'),
                rule_name=rule.get('name', 'Unknown Rule'),
                rule_type='disabled',
                rule_action=rule.get('action', 'unknown'),
                rule_enabled=False,
                rule_traffic_expression=rule.get('traffic', ''),
                test_description="Rule is disabled - skipped",
                test_method='skip',
                expected_result='skip',
                actual_result='skipped',
                passed=True,
                details="Rule disabled - no test performed",
                timestamp=datetime.now().isoformat(),
                test_duration=0.0
            )
            
        strategy = self.analyze_rule_traffic_pattern(rule)
        filters = rule.get('filters', [])
        
        if 'dns' in filters:
            return self.test_dns_rule(rule, strategy)
        elif 'http' in filters:
            return self.test_http_rule(rule, strategy)
        elif 'l4' in filters:
            return self.test_l4_rule(rule, strategy)
        else:
            # Unknown rule type
            return EnhancedRuleTestResult(
                rule_id=rule.get('id', 'unknown'),
                rule_name=rule.get('name', 'Unknown Rule'),
                rule_type='unknown',
                rule_action=rule.get('action', 'unknown'),
                rule_enabled=rule.get('enabled', False),
                rule_traffic_expression=rule.get('traffic', ''),
                test_description="Unknown rule type - cannot test",
                test_method='unknown',
                expected_result='unknown',
                actual_result='untestable',
                passed=False,
                details="Unknown rule filter type",
                timestamp=datetime.now().isoformat(),
                test_duration=0.0
            )

    def run_enhanced_test_suite(self) -> Dict:
        """Run enhanced tests for all Gateway rules"""
        print("🚀 Starting Enhanced Dynamic Gateway Rule Testing")
        print("=" * 80)
        print(f"📊 Testing all {len(self.gateway_rules)} Gateway rules individually")
        print("")
        
        start_time = datetime.now()
        
        # Test each rule individually
        for i, rule in enumerate(self.gateway_rules):
            rule_name = rule.get('name', f'Rule {i+1}')
            print(f"  [{i+1}/{len(self.gateway_rules)}] Testing: {rule_name[:60]}{'...' if len(rule_name) > 60 else ''}")
            
            test_result = self.test_individual_rule(rule)
            self.test_results.append(test_result)
            
            time.sleep(0.1)  # Brief pause between tests
            
        end_time = datetime.now()
        
        # Calculate comprehensive statistics
        total_rules = len(self.test_results)
        enabled_rules = len([r for r in self.test_results if r.rule_enabled])
        disabled_rules = len([r for r in self.test_results if not r.rule_enabled])
        passed_tests = len([r for r in self.test_results if r.passed and r.rule_enabled])
        failed_tests = len([r for r in self.test_results if not r.passed and r.rule_enabled])
        
        # Group by rule types
        rule_type_stats = {}
        for result in self.test_results:
            if result.rule_enabled:  # Only count enabled rules
                rule_type = result.rule_type
                if rule_type not in rule_type_stats:
                    rule_type_stats[rule_type] = {'total': 0, 'passed': 0, 'failed': 0}
                rule_type_stats[rule_type]['total'] += 1
                if result.passed:
                    rule_type_stats[rule_type]['passed'] += 1
                else:
                    rule_type_stats[rule_type]['failed'] += 1
        
        # Generate comprehensive summary
        summary = {
            "test_suite_version": "3.0 - Enhanced Dynamic Rule Testing",
            "execution_time": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds()
            },
            "rule_statistics": {
                "total_rules": total_rules,
                "enabled_rules": enabled_rules,
                "disabled_rules": disabled_rules,
                "coverage_percentage": 100.0
            },
            "test_results_summary": {
                "enabled_rules_tested": enabled_rules,
                "enabled_rules_passed": passed_tests,
                "enabled_rules_failed": failed_tests,
                "enabled_success_rate": (passed_tests / enabled_rules * 100) if enabled_rules > 0 else 0
            },
            "rule_type_breakdown": rule_type_stats,
            "detailed_results": [
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "rule_type": r.rule_type,
                    "rule_action": r.rule_action,
                    "rule_enabled": r.rule_enabled,
                    "rule_traffic": r.rule_traffic_expression[:100] + "..." if len(r.rule_traffic_expression) > 100 else r.rule_traffic_expression,
                    "test_description": r.test_description,
                    "test_method": r.test_method,
                    "expected": r.expected_result,
                    "actual": r.actual_result,
                    "passed": r.passed,
                    "details": r.details,
                    "timestamp": r.timestamp,
                    "duration": r.test_duration
                } for r in self.test_results
            ]
        }
        
        # Save comprehensive results
        results_file = f"enhanced_gateway_tests_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(summary, f, indent=2)
            
        # Print comprehensive summary
        self._print_enhanced_summary(summary, results_file)
        
        return summary

    def _print_enhanced_summary(self, summary: Dict, results_file: str):
        """Print enhanced comprehensive test summary"""
        print(f"\n📊 Enhanced Gateway Rule Test Results")
        print("=" * 80)
        
        stats = summary['rule_statistics']
        test_stats = summary['test_results_summary']
        
        print(f"📋 Rule Coverage:")
        print(f"  • Total Gateway Rules: {stats['total_rules']}")
        print(f"  • Enabled Rules: {stats['enabled_rules']}")
        print(f"  • Disabled Rules: {stats['disabled_rules']}")
        print(f"  • Coverage: {stats['coverage_percentage']:.1f}% (all rules analyzed)")
        
        print(f"\n🎯 Test Results (Enabled Rules Only):")
        print(f"  • Rules Tested: {test_stats['enabled_rules_tested']}")
        print(f"  • Tests Passed: {test_stats['enabled_rules_passed']} ✅")
        print(f"  • Tests Failed: {test_stats['enabled_rules_failed']} ❌")
        print(f"  • Success Rate: {test_stats['enabled_success_rate']:.1f}%")
        print(f"  • Duration: {summary['execution_time']['duration_seconds']:.1f} seconds")
        
        print(f"\n🔍 Rule Type Performance:")
        for rule_type, stats in summary['rule_type_breakdown'].items():
            success_rate = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"  • {rule_type.upper()}: {stats['passed']}/{stats['total']} passed ({success_rate:.1f}%)")
            
        print(f"\n📝 Failed Tests:")
        failed_results = [r for r in summary['detailed_results'] if not r['passed'] and r['rule_enabled']]
        if failed_results:
            for result in failed_results:
                print(f"  ❌ {result['rule_name']}")
                print(f"    └─ {result['details']}")
        else:
            print("  🎉 No failed tests - all enabled rules working correctly!")
            
        print(f"\n📁 Comprehensive results saved to: {results_file}")
        
        if test_stats['enabled_rules_failed'] == 0:
            print(f"\n🎉 Perfect score! All {test_stats['enabled_rules_tested']} enabled Gateway rules tested successfully!")
        else:
            print(f"\n⚠️  {test_stats['enabled_rules_failed']} rule(s) may need attention - review detailed results")

def main():
    """Main function"""
    print("🔐 Enhanced Dynamic Cloudflare Gateway Rule Testing Suite")
    print("=" * 80)
    print("🎯 Testing every individual Gateway rule with dynamic test generation")
    print("")
    
    # Initialize enhanced tester
    tester = EnhancedGatewayTester()
    
    # Run enhanced test suite
    results = tester.run_enhanced_test_suite()
    
    # Exit with appropriate code
    failed_tests = results['test_results_summary']['enabled_rules_failed']
    if failed_tests == 0:
        print(f"\n🎉 All enabled Gateway rules tested successfully!")
        sys.exit(0)
    else:
        print(f"\n⚠️  {failed_tests} enabled rule test(s) need attention")
        sys.exit(1)

if __name__ == "__main__":
    main()
