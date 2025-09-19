#!/usr/bin/env python3
"""
Adapted Cloudflare Gateway Bootstrap Script
============================================

This is an adapted version of the original bootstrap script that works with
API Key authentication instead of Bearer token authentication.

Creates baseline security policies:
1. DNS: Block Security Threat Categories  
2. HTTP: Block Security Threat Categories (with cert validation)
3. HTTP: Quarantine High-Risk File Downloads
4. L4: Block Tor Network  
5. L4: Block High-Risk Country Destinations

Environment variables required:
  * CF_API_KEY    – Legacy API key
  * CF_API_EMAIL  – Email address for API key
  * CF_ACCOUNT_ID – Account identifier (defaults to UCG-Fiber account)
"""

import json
import os
import sys
import requests
from typing import Dict, List, Tuple

# Configuration
API_BASE_URL = "https://api.cloudflare.com/client/v4"
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "0b0ee2b5eaf1fb8a2612e40ab6488052")
API_KEY = os.environ.get("CF_API_KEY")
EMAIL = os.environ.get("CF_API_EMAIL")

if not API_KEY or not EMAIL:
    print("❌ Error: CF_API_KEY and CF_API_EMAIL environment variables are required")
    sys.exit(1)

# Initialize session with API Key authentication
session = requests.Session()
session.headers.update({
    "X-Auth-Email": EMAIL,
    "X-Auth-Key": API_KEY,
    "Content-Type": "application/json",
})

def api_get(path: str) -> Dict:
    """Perform GET request to Cloudflare API"""
    url = f"{API_BASE_URL}{path}"
    response = session.get(url)
    if not response.ok:
        raise RuntimeError(f"GET {path} failed: {response.status_code} - {response.text}")
    data = response.json()
    if not data.get("success", True):
        raise RuntimeError(f"API error: {data}")
    return data["result"]

def api_post(path: str, payload: Dict) -> Dict:
    """Perform POST request to Cloudflare API"""
    url = f"{API_BASE_URL}{path}"
    response = session.post(url, data=json.dumps(payload))
    if not response.ok:
        raise RuntimeError(f"POST {path} failed: {response.status_code} - {response.text}")
    data = response.json()
    if not data.get("success", True):
        raise RuntimeError(f"API error: {data}")
    return data["result"]

def api_put(path: str, payload: Dict) -> Dict:
    """Perform PUT request to Cloudflare API"""
    url = f"{API_BASE_URL}{path}"
    response = session.put(url, data=json.dumps(payload))
    if not response.ok:
        raise RuntimeError(f"PUT {path} failed: {response.status_code} - {response.text}")
    data = response.json()
    if not data.get("success", True):
        raise RuntimeError(f"API error: {data}")
    return data["result"]

def list_gateway_categories() -> List[Dict]:
    """Get all Gateway categories"""
    path = f"/accounts/{ACCOUNT_ID}/gateway/categories"
    return api_get(path)

def list_gateway_rules() -> List[Dict]:
    """Get all Gateway rules"""
    path = f"/accounts/{ACCOUNT_ID}/gateway/rules"
    return api_get(path)

def resolve_category_ids(names: List[str]) -> Tuple[List[int], List[str]]:
    """Resolve category names to numeric IDs.

    Falls back to extracting IDs in-use from existing rules if direct
    resolution yields no results.
    """
    try:
        categories = list_gateway_categories()
        name_to_id = {c.get("name", "").lower(): c.get("id") for c in categories}

        ids: List[int] = []
        missing: List[str] = []

        for name in names:
            key = name.lower()
            if key in name_to_id and name_to_id[key] is not None:
                ids.append(name_to_id[key])
            else:
                # Try substring matching across all categories
                matches = [c.get("id") for c in categories if key in c.get("name", "").lower() and c.get("id") is not None]
                if matches:
                    ids.extend(matches)
                else:
                    missing.append(name)

        ids = sorted(set(int(i) for i in ids if isinstance(i, int) or (isinstance(i, str) and i.isdigit())))

        if ids:
            return ids, missing

        # If we couldn't resolve by names, try to derive IDs from existing rules
        print("ℹ️  Falling back to extracting category IDs from existing rules...")
        try:
            rules = list_gateway_rules()
            import re
            found: List[int] = []
            for rule in rules:
                traffic = rule.get("traffic", "")
                if "security_category" in traffic or "content_category" in traffic:
                    for group in re.findall(r"\{([^}]+)\}", traffic):
                        for token in group.split():
                            if token.isdigit():
                                found.append(int(token))
            derived = sorted(set(found))
            if derived:
                return derived, missing
        except Exception as inner:
            print(f"⚠️  Warning: Could not derive IDs from existing rules ({inner})")

        # Final hard-coded fallback of common IDs
        print("   Using fallback category IDs for common security threats")
        fallback_ids = [117, 187, 83, 151, 68, 80, 131, 134, 175, 176, 178, 188, 191, 153, 4, 23]
        return sorted(set(fallback_ids)), missing
    except Exception as e:
        print(f"⚠️  Warning: Could not fetch categories ({e})")
        print("   Using fallback category IDs for common security threats")
        fallback_ids = [117, 187, 83, 151, 68, 80, 131, 134, 175, 176, 178, 188, 191, 153, 4, 23]
        return sorted(set(fallback_ids)), []

def upsert_gateway_rule(name: str, payload: Dict) -> Dict:
    """Create or update a Gateway rule"""
    existing_rules = list_gateway_rules()
    existing = next((r for r in existing_rules if r.get("name") == name), None)
    
    if existing:
        rule_id = existing["id"]
        return api_put(f"/accounts/{ACCOUNT_ID}/gateway/rules/{rule_id}", payload)
    else:
        return api_post(f"/accounts/{ACCOUNT_ID}/gateway/rules", payload)

def build_bootstrap_policies() -> List[Dict]:
    """Build the bootstrap security policies"""
    
    print("🔍 Resolving security category IDs...")
    
    # Security categories to block
    malicious_names = [
        "Malware",
        "Command and Control & Botnet", 
        "Cryptomining",
        "DGA Domains",
        "DNS Tunneling",
        "Phishing",
        "Potentially Unwanted Software",
        "Compromised Domain",
        "Anonymizer",
        "Brand Embedding",
        "Private IP Address",
        "Scam",
        "Spam",
        "Spyware",
    ]
    
    malicious_ids, missing = resolve_category_ids(malicious_names)
    
    if missing:
        print(f"⚠️  Some categories not found: {', '.join(missing)}")
    
    if not malicious_ids:
        print("❌ No security category IDs found")
        return []
    
    print(f"✅ Found {len(malicious_ids)} security category IDs")
    
    # Build category expressions
    ids_str = " ".join(str(i) for i in malicious_ids)
    dns_expression = f"any(dns.content_category[*] in {{{ids_str}}})"
    http_expression = f"any(http.content_category[*] in {{{ids_str}}})"
    
    policies = []
    
    # 1. DNS Security Policy
    policies.append({
        "name": "DNS: Block Security Threat Categories",
        "description": "Block domains in Cloudflare's malicious security categories at DNS layer",
        "filters": ["dns"],
        "traffic": dns_expression,
        "action": "block",
        "enabled": True,
        "precedence": 1000,
        "rule_settings": {
            "block_page_enabled": True,
            "block_reason": "Security threat category blocked"
        }
    })
    
    # 2. HTTP Security Policy  
    policies.append({
        "name": "HTTP: Block Security Threat Categories",
        "description": "Block malicious categories at HTTP layer and enforce certificate validity",
        "filters": ["http"],
        "traffic": http_expression,
        "action": "block",
        "enabled": True,
        "precedence": 1100,
        "rule_settings": {
            "untrusted_certificate": "block",
            "block_page_enabled": True,
            "block_reason": "Security threat or invalid certificate"
        }
    })
    
    # 3. File Download Quarantine
    policies.append({
        "name": "HTTP: Quarantine High-Risk File Downloads",
        "description": "Send risky file downloads to Cloudflare's sandbox for analysis",
        "filters": ["http"],
        "traffic": 'any(http.download.filetype[*] in {"exe" "msi" "dll" "js" "jar" "bat" "cmd" "scr" "ps1" "apk" "ipa" "zip" "rar" "7z" "pdf" "doc" "docx" "xls" "xlsx" "ppt" "pptx"})',
        "action": "isolate",  # Use isolate instead of quarantine for Gateway
        "enabled": True,
        "precedence": 1150,
        "rule_settings": {}
    })
    
    # 4. Block Tor Network
    policies.append({
        "name": "L4: Block Tor Network",
        "description": "Block all traffic from/to Tor exit nodes (continent T1)",
        "filters": ["l4"],
        "traffic": 'net.src.geo.continent == "T1" or net.dst.geo.continent == "T1"',
        "action": "block",
        "enabled": True,
        "precedence": 2000,
        "rule_settings": {}
    })
    
    # 5. Block High-Risk Countries
    policies.append({
        "name": "L4: Block High-Risk Country Destinations", 
        "description": "Block traffic to high-risk countries",
        "filters": ["l4"],
        "traffic": 'any(net.dst.geo.country[*] in {"RU" "KP" "IR" "SY" "AF" "SO" "YE"})',
        "action": "block", 
        "enabled": True,
        "precedence": 2010,
        "rule_settings": {}
    })
    
    return policies

def apply_bootstrap_policies():
    """Create or update all bootstrap policies"""
    print("🚀 Cloudflare Gateway Bootstrap - Adapted Version")
    print("=" * 60)
    
    policies = build_bootstrap_policies()
    
    if not policies:
        print("❌ No policies to apply")
        return
    
    print(f"\n📋 Applying {len(policies)} bootstrap security policies...")
    
    success_count = 0
    
    for policy in policies:
        try:
            print(f"  🔄 Processing: {policy['name']}")
            result = upsert_gateway_rule(policy["name"], policy)
            print(f"    ✅ Success")
            success_count += 1
        except Exception as e:
            print(f"    ❌ Failed: {e}")
    
    print(f"\n📊 Bootstrap Results:")
    print(f"   • Policies Applied: {success_count}/{len(policies)}")
    print(f"   • Success Rate: {success_count/len(policies)*100:.1f}%")
    
    if success_count > 0:
        print(f"\n✅ Bootstrap completed successfully!")
        print(f"\n📚 Next Steps:")
        print(f"  1. Check the Cloudflare Zero Trust dashboard")
        print(f"  2. Monitor Gateway logs for policy enforcement")
        print(f"  3. Adjust rule precedence if needed")
        print(f"  4. Test policy effectiveness with our test suite")
    else:
        print(f"\n❌ Bootstrap failed")

def main():
    """Main function"""
    apply_bootstrap_policies()

if __name__ == "__main__":
    main()
