#!/usr/bin/env python3
"""
Test script for Gateway Monitor Agent
Tests the core functionality without running the full service
"""

import sys
import os
import json
from gateway_monitor import GatewayMonitor, LogEvent, GatewayLogAnalyzer

def create_test_events():
    """Create test log events for analysis"""
    test_events = [
        # Blocked Apple CDN (should recommend ALLOW)
        LogEvent(
            timestamp="2025-09-06T12:00:00Z",
            client_ip="104.28.250.151",
            host="app-site-association.cdn-apple.com",
            uri="/a/v1/tuyaSmart.app.tuya.com",
            method="GET",
            status=403,
            user_agent="tuyaSmart/20250729114034 CFNetwork/3860.100.1 Darwin/25.0.0"
        ),
        # Multiple blocks of the same service
        LogEvent(
            timestamp="2025-09-06T12:01:00Z",
            client_ip="104.28.250.151",
            host="app-site-association.cdn-apple.com",
            uri="/a/v1/another-app.com",
            method="GET", 
            status=403,
            user_agent="iOS/15.0 CFNetwork/1331.0.7 Darwin/21.4.0"
        ),
        # Suspicious SQL injection attempt (should recommend BLOCK)
        LogEvent(
            timestamp="2025-09-06T12:02:00Z",
            client_ip="104.28.250.151",
            host="suspicious-site.com",
            uri="/search?q=test' UNION SELECT * FROM users--",
            method="GET",
            status=200,
            user_agent="curl/7.68.0"
        ),
        # High volume bot traffic (should recommend rate limit)
        LogEvent(
            timestamp="2025-09-06T12:03:00Z",
            client_ip="104.28.250.151",
            host="example.com",
            uri="/",
            method="GET",
            status=200,
            user_agent="BadBot/1.0 (crawler; +http://badbot.com/)"
        ),
        # Normal traffic (should not generate recommendations)
        LogEvent(
            timestamp="2025-09-06T12:04:00Z",
            client_ip="104.28.250.151",
            host="google.com",
            uri="/search?q=test",
            method="GET",
            status=200,
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        )
    ]
    
    # Add more Apple CDN blocks to trigger high-priority recommendation
    for i in range(10):
        test_events.append(LogEvent(
            timestamp=f"2025-09-06T12:0{i}:00Z",
            client_ip="104.28.250.151", 
            host="app-site-association.cdn-apple.com",
            uri=f"/a/v1/test-app-{i}.com",
            method="GET",
            status=403,
            user_agent="iOS/15.0 CFNetwork/1331.0.7 Darwin/21.4.0"
        ))
    
    # Add bot traffic to trigger rate limit recommendation
    for i in range(60):
        test_events.append(LogEvent(
            timestamp=f"2025-09-06T12:{i:02d}:00Z",
            client_ip="104.28.250.151",
            host="target-site.com", 
            uri=f"/page-{i}",
            method="GET",
            status=200,
            user_agent="BadBot/1.0 (crawler; +http://badbot.com/)"
        ))
    
    return test_events

def test_analyzer():
    """Test the log analyzer"""
    print("🧪 Testing Gateway Log Analyzer...")
    
    analyzer = GatewayLogAnalyzer()
    test_events = create_test_events()
    
    print(f"📊 Created {len(test_events)} test events")
    
    # Analyze events
    recommendations = analyzer.analyze_events(test_events)
    
    print(f"🎯 Generated {len(recommendations)} recommendations:")
    
    for i, rec in enumerate(recommendations, 1):
        print(f"\n{i}. {rec.priority} Priority - {rec.action} {rec.target}")
        print(f"   Reason: {rec.reason}")
        print(f"   Confidence: {rec.confidence:.1%}")
        print(f"   Rule Type: {rec.rule_type}")
        
        if rec.suggested_rule:
            print(f"   Suggested Rule: {rec.suggested_rule.get('name', 'N/A')}")
    
    return len(recommendations) > 0

def test_config():
    """Test configuration loading"""
    print("\n⚙️  Testing Configuration...")
    
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        required_keys = ['cloudflare', 'monitoring', 'notifications']
        for key in required_keys:
            if key not in config:
                print(f"❌ Missing required config key: {key}")
                return False
            else:
                print(f"✅ Found config section: {key}")
        
        # Check Cloudflare credentials
        cf_config = config['cloudflare']
        if not all(k in cf_config for k in ['api_email', 'api_key', 'account_id', 'zone_id']):
            print("❌ Missing Cloudflare API credentials")
            return False
        
        print("✅ Configuration appears valid")
        return True
        
    except Exception as e:
        print(f"❌ Config test failed: {e}")
        return False

def test_api_connectivity():
    """Test Cloudflare API connectivity"""
    print("\n🌐 Testing API Connectivity...")
    
    try:
        import requests
        
        # Load config
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        headers = {
            "X-Auth-Email": config['cloudflare']['api_email'],
            "X-Auth-Key": config['cloudflare']['api_key'],
            "Content-Type": "application/json"
        }
        
        # Test basic API access
        response = requests.get(
            f"https://api.cloudflare.com/client/v4/accounts/{config['cloudflare']['account_id']}/gateway/rules",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ Cloudflare API connectivity successful")
            print(f"📋 Found {len(response.json().get('result', []))} existing Gateway rules")
            return True
        else:
            print(f"❌ API request failed with status {response.status_code}")
            print(f"Response: {response.text[:200]}...")
            return False
            
    except Exception as e:
        print(f"❌ API connectivity test failed: {e}")
        return False

def test_database():
    """Test database functionality"""
    print("\n🗄️  Testing Database...")
    
    try:
        import sqlite3
        
        # Test database creation
        monitor = GatewayMonitor('config.json')
        
        # Test storing a recommendation
        from gateway_monitor import RuleRecommendation
        test_rec = RuleRecommendation(
            priority="TEST",
            action="ALLOW",
            rule_type="HTTP",
            target="test.example.com",
            reason="Test recommendation",
            evidence=["Test evidence"],
            suggested_rule={"name": "Test Rule"},
            confidence=0.5
        )
        
        monitor.store_recommendation(test_rec)
        
        # Verify storage
        conn = sqlite3.connect(monitor.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM recommendations WHERE target = 'test.example.com'")
        count = cursor.fetchone()[0]
        conn.close()
        
        if count > 0:
            print("✅ Database functionality working")
            return True
        else:
            print("❌ Database test failed - no records found")
            return False
            
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🔍 Gateway Monitor Agent - Test Suite")
    print("=" * 50)
    
    # Change to script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    tests = [
        ("Configuration", test_config),
        ("Log Analyzer", test_analyzer), 
        ("API Connectivity", test_api_connectivity),
        ("Database", test_database)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("🎯 Test Results Summary:")
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\n📊 Overall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("🎉 All tests passed! Gateway Monitor is ready to run.")
        return 0
    else:
        print("⚠️  Some tests failed. Check configuration and dependencies.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
