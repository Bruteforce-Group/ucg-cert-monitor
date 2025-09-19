#!/usr/bin/env python3
"""
Rename and Restore Cloudflare Gateway Rules
==========================================

This script removes all existing Gateway rules in a Cloudflare account,
reads a backup JSON file of rules, analyzes and renames the rules using a
consistent naming scheme, drops obsolete rules, reorders them, and then
recreates the rules via the Cloudflare API.

Key features:
 - Deletes all existing rules before restoration.
 - Identifies and skips obsolete policies (such as legacy TLS policies and
   redundant "Allow HTTPS" rule).
 - Renames rules using a logical naming convention based on their layer,
   action, and purpose.
 - Assigns fresh, sequential precedence values to the renamed rules to
   provide a clean evaluation order.
 - Uses Cloudflare API authentication via API key and email.

Environment variables required:
  * CF_API_KEY    – Your Cloudflare API key
  * CF_API_EMAIL  – The email address associated with the API key
  * CF_ACCOUNT_ID – The account ID where the rules will be managed

Usage:
  python3 rename_and_restore_rules.py <backup_file.json>

The backup file should be in the format exported by the Cloudflare Gateway
rule export feature (with keys 'export_metadata' and 'gateway_rules'),
though the script will also accept a flat list of rules.
"""

import os
import sys
import json
import requests
from typing import Dict, List, Set, Optional, Tuple

# Configuration from environment
API_BASE_URL = "https://api.cloudflare.com/client/v4"
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID")
API_KEY = os.environ.get("CF_API_KEY")
EMAIL = os.environ.get("CF_API_EMAIL")

if not ACCOUNT_ID or not API_KEY or not EMAIL:
    print("❌ Environment variables CF_API_KEY, CF_API_EMAIL, and CF_ACCOUNT_ID must be set.")
    sys.exit(1)

session = requests.Session()
session.headers.update({
    "X-Auth-Email": EMAIL,
    "X-Auth-Key": API_KEY,
    "Content-Type": "application/json",
})

# Define obsolete rule names (rules to drop entirely)
OBSOLETE_RULE_PREFIXES = [
    "TLS Policy - ",  # all TLS host-specific policies
]
OBSOLETE_RULE_EXACT = {
    "Network: Allow HTTPS",
    "DNS: Bootstrap Security Categories",
    "HTTP: Bootstrap Security Categories",
    "HTTP: Bootstrap File Download Security",
    "L4: Bootstrap Block High-Risk Countries",
    "L4: Bootstrap Block Suspicious Ports",
}

# Mapping of specific old names to new names
RENAME_MAP = {
    "HTTP: Ensure Business Tools Access": "HTTP Allow: Business Applications",
    "DNS: Ensure Business DNS Resolution": "DNS Allow: Business Applications",
    "L4: Block Cryptocurrency Mining": "L4 Block: Mining Ports",
    "HTTP: Productivity - Allow Block Page Domains": "HTTP Allow: Block Page Domains",
    "HTTP: Block Archive Downloads": "HTTP Block: Archive Downloads",
    "HTTP: Block Suspicious Admin Paths": "HTTP Block: Admin Path Access",
    "HTTP: Block Script Injections (Fixed)": "HTTP Block: Script Injection Regex",
    "L4: Block P2P and Mining Ports": "L4 Block: P2P & Mining Ports",
    "L4: Block High-Risk Ports": "L4 Block: High-Risk Ports",
    "DNS: Block Suspicious TLD Patterns": "DNS Block: Suspicious TLD Patterns",
    "DNS: Block Dynamic DNS Patterns": "DNS Block: Dynamic DNS Patterns",
    "DNS: Enhanced Malware Protection": "DNS Block: Malware & Suspicious Categories",
    "DNS: Productivity - Allow Block Page Domains (DNS)": "DNS Allow: Block Page Domains",
    "HTTP: Monitor Social Media Access": "HTTP Allow: Social Media Monitoring",
    "HTTP: Monitor File Upload Activity (Fixed)": "HTTP Allow: File Upload Monitoring",
    "HTTP: Custom - Security: Block Suspicious File Downloads": "HTTP Block: Suspicious Executable & Script Downloads",
    "DNS: Block Adult Content": "DNS Block: Adult Content",
    "DNS: Block Gambling (Optional)": "DNS Block: Gambling Sites",
    "DNS: Custom - Security: Compromised Domain": "DNS Block: Compromised Domain",
    "DNS: Custom - Security: Block Malware": "DNS Block: Malware",
    "TLS Policy - Block Expired Certificate Sites": "(obsolete)",  # handled via untrusted cert rule
    "TLS Policy - Block Self-Signed Certificate Sites": "(obsolete)",
    "TLS Policy - Block Revoked Certificate Sites": "(obsolete)",
    "TLS Policy - Block Weak Encryption Sites": "(obsolete)",
    "TLS Policy - Block Invalid Hostname Sites": "(obsolete)",
    "TLS Policy - Monitor Certificate Test Sites": "HTTP Allow: Certificate Test Sites (Pass-Through)",
    "Network: Allow HTTPS": "(obsolete)",
    "HTTP: Custom - Network Security: Block Dangerous File Downloads": "HTTP Block: Dangerous File Types",
    "HTTP: Block Social Media (Optional)": "HTTP Block: Social Media (Optional)",
    "DNS: Bootstrap Security Categories": "(obsolete)",
    "HTTP: Allow Business Tools": "HTTP Allow: Business Applications",
    "HTTP: Bootstrap Security Categories": "(obsolete)",
    "HTTP: Bootstrap File Download Security": "(obsolete)",
    "L4: Bootstrap Block High-Risk Countries": "(obsolete)",
    "L4: Productivity (Allow) - Infrastructure: SSH Access Monitoring": "L4 Allow: SSH",
    "L4: Bootstrap Block Suspicious Ports": "(obsolete)",
    "HTTP: Custom - Network Security: Block SQL Injection Attempts": "HTTP Block: SQL Injection Regex",
    "NETWORK: Block Security Risks": "L4 Block: Security Risk Categories",
    "HTTP: Custom - Network Security: Block XSS Attempts": "HTTP Block: XSS Regex",
    "HTTP: Custom - Network Security: Block Admin Path Brute Force": "HTTP Block: Admin Path Brute Force",
    "Block Crap": "L4 Block: Known Malicious IPs & Hostnames",
    "DNS: Custom - Security: Block Botnets": "DNS Block: Botnets",
    "DNS: Custom - Security: Block Phishing": "DNS Block: Phishing",
    "HTTP: Custom - App Control: Block Suspicious Downloads": "HTTP Block: Suspicious Download Paths",
    "DNS: Custom - Security: Block Spam": "DNS Block: Spam",
    "DNS: Custom - Security: Block Command & Control": "DNS Block: Command & Control",
    "DNS: Block All Security Risks": "DNS Block: All Security Risks",
    "HTTP: Custom - Risk-Based: Block Common Attack Patterns": "HTTP Block: Common Attack Patterns",
    "L4: Custom - Security: Block High-Risk Countries": "L4 Block: High-Risk Countries",
    "HTTP: Block Security Risks": "HTTP Block: Security Risk Categories",
    "DNS: Productivity - Social: Allow Grindr (DNS)": "DNS Allow: Social App (Grindr)",
    "DNS: Productivity - Allow a.simplemdm.com": "DNS Allow: simpleMDM",
    "DNS: Productivity (Allow) - Certificate: OCSP and CRL Infrastructure (DNS)": "DNS Allow: OCSP & CRL Infrastructure",
    "DNS: Productivity (Allow) - Certificate: SSL/TLS Validation Services": "DNS Allow: SSL/TLS Validation",
    "DNS: Productivity - Allow NPM Registry": "DNS Allow: NPM Registry",
    "DNS: Productivity - Allow GitHub": "DNS Allow: GitHub",
    "DNS: Productivity - Allow OpenAI API": "DNS Allow: OpenAI",
    "DNS: Productivity - Allow Cloudflare API": "DNS Allow: Cloudflare",
    "DNS: Productivity - Allow Apple Homekit and Google Home Ecosystems": "DNS Allow: Apple Homekit & Google Home",
    "Microsoft 365 Auto Generated": "HTTP Off: Microsoft 365 Decryption Bypass",
}

def api_get(path: str) -> Dict:
    url = f"{API_BASE_URL}{path}"
    resp = session.get(url)
    if not resp.ok:
        raise RuntimeError(f"GET {path} failed: {resp.status_code} - {resp.text}")
    data = resp.json()
    if not data.get("success", True):
        raise RuntimeError(f"API error: {data}")
    return data["result"]

def api_delete(path: str) -> None:
    url = f"{API_BASE_URL}{path}"
    resp = session.delete(url)
    if not resp.ok:
        raise RuntimeError(f"DELETE {path} failed: {resp.status_code} - {resp.text}")
    return

def api_post(path: str, payload: Dict) -> Dict:
    url = f"{API_BASE_URL}{path}"
    resp = session.post(url, data=json.dumps(payload))
    if not resp.ok:
        raise RuntimeError(f"POST {path} failed: {resp.status_code} - {resp.text}")
    data = resp.json()
    if not data.get("success", True):
        raise RuntimeError(f"API error: {data}")
    return data["result"]

def delete_all_rules():
    """Delete all existing Gateway rules"""
    rules = api_get(f"/accounts/{ACCOUNT_ID}/gateway/rules")
    for rule in rules:
        rid = rule.get("id")
        name = rule.get("name")
        print(f"Deleting rule: {name}")
        api_delete(f"/accounts/{ACCOUNT_ID}/gateway/rules/{rid}")
    print(f"Deleted {len(rules)} existing rules.")

def load_rules_from_file(backup_file: str) -> List[Dict]:
    with open(backup_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, dict) and 'gateway_rules' in data:
        return data['gateway_rules']
    elif isinstance(data, list):
        return data
    else:
        raise ValueError("Invalid backup file format.")

def is_obsolete_rule(rule_name: str) -> bool:
    # Check exact obsolete names
    if rule_name in OBSOLETE_RULE_EXACT:
        return True
    # Check prefix for TLS policies
    for prefix in OBSOLETE_RULE_PREFIXES:
        if rule_name.startswith(prefix):
            return True
    # Check if mapped to obsolete in rename map
    new_name = RENAME_MAP.get(rule_name)
    if new_name == "(obsolete)":
        return True
    return False

def rename_rule(rule: Dict) -> Dict:
    """
    Generate a new name for a rule using a mapping or a generic naming convention.

    This function does not assign precedence; ordering is handled separately.  It preserves
    the existing rule structure (filters, traffic, action, enabled state, rule_settings,
    identity and device posture) but returns a new name string which will be applied
    in a later stage when constructing the final payload.
    """
    old_name = rule.get("name", "Unknown")
    action = rule.get("action", "block")
    filters = rule.get("filters", [])

    # If a specific mapping exists and is not marked obsolete, use it
    mapped_name = RENAME_MAP.get(old_name)
    if mapped_name and mapped_name != "(obsolete)":
        return mapped_name

    # Derive a generic name: "<LAYER> <Action>: <Description>"
    layer = filters[0] if filters else "unknown"
    # Determine an action prefix: allow/block/off or capitalised value
    if action.lower() == "allow":
        action_prefix = "Allow"
    elif action.lower() == "block":
        action_prefix = "Block"
    elif action.lower() == "off":
        action_prefix = "Off"
    else:
        action_prefix = action.capitalize()

    # Remove common leading prefixes from the original name for the description part
    desc = old_name
    for prefix in ["HTTP: ", "DNS: ", "L4: "]:
        if desc.startswith(prefix):
            desc = desc[len(prefix):]
            break
    # Remove known sub-prefixes that clutter names
    desc = desc.replace("Custom - ", "").replace("Network Security: ", "").replace("Security: ", "")
    desc = desc.replace("Productivity - ", "").replace("Bootstrap ", "")
    desc = desc.replace("App Control: ", "").replace("Risk-Based: ", "")

    # Assemble the generic name
    generic_name = f"{layer.upper()} {action_prefix}: {desc.strip()}"
    return generic_name


def build_payload(rule: Dict, new_name: str, precedence: int) -> Dict:
    """Construct a new payload for a rule with a given name and precedence."""
    payload = {
        "name": new_name,
        "description": rule.get("description", ""),
        "filters": rule.get("filters", []),
        "traffic": rule.get("traffic", ""),
        "action": rule.get("action"),
        "enabled": rule.get("enabled", True),
        "precedence": precedence,
    }
    # Preserve rule_settings if present
    if rule.get("rule_settings"):
        payload["rule_settings"] = rule.get("rule_settings")
    # Preserve identity and device posture conditions
    if rule.get("identity"):
        payload["identity"] = rule.get("identity")
    if rule.get("device_posture"):
        payload["device_posture"] = rule.get("device_posture")
    return payload

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 rename_and_restore_rules.py <backup_file.json>")
        sys.exit(1)
    backup_file = sys.argv[1]
    # Step 1: Delete all existing rules
    delete_all_rules()

    # Step 2: Load rules from backup file
    rules = load_rules_from_file(backup_file)

    # Step 3: Filter out obsolete rules and rename remaining rules
    # Collect tuples of (original_rule, new_name) to sort later
    renamed: List[Tuple[Dict, str]] = []
    for rule in rules:
        old_name = rule.get("name")
        if is_obsolete_rule(old_name):
            print(f"Skipping obsolete rule: {old_name}")
            continue
        new_name = rename_rule(rule)
        renamed.append((rule, new_name))

    # Step 4: Combine rules with identical new names when appropriate
    from copy import deepcopy

    combined: Dict[str, List[Dict]] = {}
    for rule, new_name in renamed:
        combined.setdefault(new_name, []).append(rule)

    merged_items: List[Tuple[Dict, str]] = []
    for new_name, group in combined.items():
        # If only one rule produces this name, keep as-is
        if len(group) == 1:
            merged_items.append((group[0], new_name))
            continue
        # Multiple rules share this name. Attempt to merge if they have identical action and filters.
        base_rule = deepcopy(group[0])
        can_merge = True
        # Check all have same action, filters, rule_settings, identity, device_posture
        for r in group[1:]:
            if r.get("action") != base_rule.get("action") or r.get("filters") != base_rule.get("filters"):
                can_merge = False
                break
            # Rule settings must be equal or absent
            if r.get("rule_settings") != base_rule.get("rule_settings"):
                can_merge = False
                break
            if r.get("identity") != base_rule.get("identity"):
                can_merge = False
                break
            if r.get("device_posture") != base_rule.get("device_posture"):
                can_merge = False
                break
        if can_merge:
            # Try to unify traffic expressions for host-based allow lists.
            traffic_set = None
            host_prefix = None
            # pattern for host equality: http.request.host == "host"
            import re
            set_pattern = re.compile(r'^\s*http\.request\.host\s+in\s+\{(.+)\}\s*$')
            eq_pattern = re.compile(r'^\s*http\.request\.host\s*==\s*"([^"]+)"\s*$')
            unified_strings = []
            parse_failed = False
            for r in group:
                t = r.get("traffic", "").strip()
                # Try to match 'in {..}'
                m_set = set_pattern.match(t)
                m_eq = eq_pattern.match(t)
                if m_set:
                    items_str = m_set.group(1)
                    # split by spaces but maintain quoted tokens
                    parts = re.findall(r'"([^"]+)"', items_str)
                    if traffic_set is None:
                        traffic_set = set(parts)
                        host_prefix = 'http.request.host'
                    else:
                        traffic_set.update(parts)
                elif m_eq:
                    host = m_eq.group(1)
                    if traffic_set is None:
                        traffic_set = {host}
                        host_prefix = 'http.request.host'
                    else:
                        traffic_set.add(host)
                else:
                    # cannot parse; fallback to OR concatenation later
                    parse_failed = True
                    unified_strings.append(f"({t})")
            # Build unified traffic
            if not parse_failed and traffic_set is not None and host_prefix:
                # Format: http.request.host in {"a" "b"}
                # Build the unified set expression manually.  Surround each host in quotes and wrap
                # the set in curly braces.  Example: http.request.host in {"a" "b"}
                hosts_sorted = sorted(traffic_set)
                unified = f"{host_prefix} in {{" + " ".join(f'\"{h}\"' for h in hosts_sorted) + "}"
                base_rule["traffic"] = unified
            else:
                # Fallback: OR all traffic expressions
                expressions = [r.get("traffic", "") for r in group]
                base_rule["traffic"] = " or ".join(f'({expr.strip()})' for expr in expressions)
            merged_items.append((base_rule, new_name))
        else:
            # Cannot merge; create separate entries with a suffix to keep names unique
            suffix = 1
            for r in group:
                unique_name = f"{new_name} ({suffix})"
                suffix += 1
                merged_items.append((r, unique_name))

    # Step 5: Determine ordering and assign precedence
    def action_order(action: str) -> int:
        a = action.lower()
        if a == "allow":
            return 0
        if a == "off":
            return 1
        # default to block or other actions
        return 2

    def layer_order(filters: List[str]) -> int:
        if not filters:
            return 3
        f = filters[0].lower()
        if f == "dns":
            return 0
        if f == "http":
            return 1
        if f == "l4":
            return 2
        return 3

    merged_items.sort(key=lambda item: (
        action_order(item[0].get("action", "block")),
        layer_order(item[0].get("filters", [])),
        item[1].lower()
    ))

    # Assign precedence values starting from 50 and increasing by 10 for readability
    new_payloads: List[Dict] = []
    precedence_value = 50
    for rule, new_name in merged_items:
        new_payloads.append(build_payload(rule, new_name, precedence_value))
        precedence_value += 10

    # Step 6: Create new rules via API
    for payload in new_payloads:
        print(f"Creating rule: {payload['name']} (precedence {payload['precedence']})")
        api_post(f"/accounts/{ACCOUNT_ID}/gateway/rules", payload)

    print(f"Created {len(new_payloads)} rules in account {ACCOUNT_ID}.")

if __name__ == "__main__":
    main()