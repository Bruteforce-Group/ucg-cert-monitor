#!/usr/bin/env python3
"""
cloudflare_gateway_bootstrap.py
=================================

This script provisions a set of baseline Gateway policies for the Cloudflare
Zero Trust platform.  It discovers the numeric category identifiers for
Cloudflare's built‑in security threat categories, then creates (or updates)
DNS, HTTP, and network rules that block or quarantine traffic associated
with malicious domains and risky destinations.  The script relies on
Cloudflare's public REST API for Zero Trust and is intended to be
idempotent; you can run it repeatedly and it will update existing rules
rather than creating duplicates.

Environment variables required:

  * ``CF_API_TOKEN``     – API token with permissions to manage Gateway rules
  * ``CF_ACCOUNT_ID``    – your Cloudflare account identifier

Optional environment variable:

  * ``CF_TEAM_NAME``     – optional label used solely for log messages

The script performs the following high‑level steps:

  1. Retrieve the full list of Gateway categories via the ``/gateway/categories``
     endpoint.  Cloudflare categorises domains into both content and
     security categories【419096146802914†L716-L733】.  Security categories include
     threats such as ``Malware``, ``Command and Control & Botnet`` and
     ``Cryptomining``【419096146802914†L750-L776】.  This script selects those
     categories deemed malicious and resolves their numeric IDs.

  2. Define expressions for common Gateway policies.  DNS and HTTP rules
     block any domain whose category ID matches one of the malicious
     categories, using the expression syntax documented in Cloudflare's
     examples (``any(dns.content_category[*] in {<ID list>})`` for DNS and
     ``any(http.content_category[*] in {<ID list>})`` for HTTP).  The HTTP
     rule also sets ``untrusted_certificate`` to ``block`` so that any
     untrusted origin certificate — expired, self‑signed or invalid — will be
     rejected【969046013694795†L882-L892】.

  3. Create or update a network rule to block Tor traffic using the special
     continent code ``T1`` and a separate network rule to block traffic
     destined for a list of high‑risk countries using the ``net.dst.geo.country``
     selector【419096146802914†L716-L733】.  Cloudflare documents that the
     Tor network can be matched by specifying continent ``T1``【419096146802914†L716-L733】.

  4. Optionally quarantine executable and archive downloads via the HTTP
     sandbox, demonstrating how to use the file download selectors.

  5. After provisioning the rules, the script fetches all Gateway rules and
     displays a summary of the ones it manages.  Users should monitor
     Gateway logs to verify policy hits; certificate enforcement events
     appear in the ``UntrustedCertificateAction`` field of Gateway log entries
     with values ``block``, ``error`` or ``passThrough``【903017829181420†L523-L532】.

Note: This script does not perform live tests of the rules, since such tests
would require generating real traffic through the Gateway.  Instead, it
verifies that the rules exist and provides guidance for monitoring.
"""

import json
import os
import sys
import textwrap
import time
from typing import Dict, List, Tuple

import requests

# -----------------------------------------------------------------------------
# Configuration and environment checks
#
# Read configuration from environment variables.  Abort early if any required
# variables are missing.

API_BASE_URL = "https://api.cloudflare.com/client/v4"

# Account ID and API token must be set for the script to function.  Exit
# gracefully with a helpful message if they are not provided.
ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID")
API_TOKEN = os.environ.get("CF_API_TOKEN")

if not ACCOUNT_ID or not API_TOKEN:
    sys.stderr.write(
        textwrap.dedent(
            """
            The environment variables CF_ACCOUNT_ID and CF_API_TOKEN must be set.
            CF_ACCOUNT_ID should be your Cloudflare account identifier and
            CF_API_TOKEN should be a token with permissions to manage Gateway rules.
            """
        )
    )
    sys.exit(2)

# Optional team name used for logging; no functional impact.
TEAM_NAME = os.environ.get("CF_TEAM_NAME", "")

# Initialise a requests session with the appropriate headers for the API.
session = requests.Session()
session.headers.update(
    {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json",
    }
)


def api_get(path: str, params: Dict = None) -> Dict:
    """Perform a GET request to the Cloudflare API and return the JSON result.

    Raises RuntimeError if the API response indicates a failure.
    """
    url = f"{API_BASE_URL}{path}"
    response = session.get(url, params=params or {})
    if not response.ok:
        raise RuntimeError(
            f"GET {path} failed with status {response.status_code}: {response.text}"
        )
    data = response.json()
    if not data.get("success", True):
        raise RuntimeError(f"API returned error: {data}")
    return data["result"]


def api_post(path: str, payload: Dict) -> Dict:
    """Perform a POST request to the Cloudflare API and return the JSON result.

    Raises RuntimeError if the API response indicates a failure.
    """
    url = f"{API_BASE_URL}{path}"
    response = session.post(url, data=json.dumps(payload))
    if not response.ok:
        raise RuntimeError(
            f"POST {path} failed with status {response.status_code}: {response.text}"
        )
    data = response.json()
    if not data.get("success", True):
        raise RuntimeError(f"API returned error: {data}")
    return data["result"]


def api_put(path: str, payload: Dict) -> Dict:
    """Perform a PUT request to the Cloudflare API and return the JSON result."""
    url = f"{API_BASE_URL}{path}"
    response = session.put(url, data=json.dumps(payload))
    if not response.ok:
        raise RuntimeError(
            f"PUT {path} failed with status {response.status_code}: {response.text}"
        )
    data = response.json()
    if not data.get("success", True):
        raise RuntimeError(f"API returned error: {data}")
    return data["result"]


# -----------------------------------------------------------------------------
# Category management
#
def list_gateway_categories() -> List[Dict]:
    """Return all Gateway categories available to this account.

    Cloudflare categorises domains into content categories and security categories
    based on vendor data and internal models【419096146802914†L716-L733】.  Each
    category dictionary contains an ``id`` and ``name`` among other fields.
    """
    path = f"/accounts/{ACCOUNT_ID}/gateway/categories"
    return api_get(path)


def resolve_category_ids(names: List[str]) -> Tuple[List[int], List[str]]:
    """Resolve a list of category names to their numeric IDs.

    Returns a tuple (ids, missing) where ``ids`` is a list of unique category
    identifiers corresponding to the requested names (case‑insensitive), and
    ``missing`` is a list of names that were not found.  The function also
    performs a simple substring match if an exact match fails, to handle
    slight differences in naming (for example, ``command and control`` vs.
    ``Command and Control & Botnet``).  Unknown names are returned in
    ``missing`` without raising an exception.
    """
    categories = list_gateway_categories()
    # Build a mapping from lowercase names to IDs.  Some category names may
    # contain special characters like ampersands; normalise by lowercasing.
    name_to_id = {c["name"].lower(): c["id"] for c in categories}
    ids: List[int] = []
    missing: List[str] = []
    for name in names:
        key = name.lower()
        if key in name_to_id:
            ids.append(name_to_id[key])
        else:
            # Attempt substring match against all categories.  This is a
            # best‑effort approach since Cloudflare occasionally changes
            # category naming.  If multiple categories match, include all.
            matches = [c["id"] for c in categories if key in c["name"].lower()]
            if matches:
                ids.extend(matches)
            else:
                missing.append(name)
    # Return unique IDs sorted for determinism.
    unique_ids = sorted(set(ids))
    return unique_ids, missing


# -----------------------------------------------------------------------------
# Gateway rule management
#
def list_gateway_rules() -> List[Dict]:
    """Retrieve all Gateway rules for this account."""
    path = f"/accounts/{ACCOUNT_ID}/gateway/rules"
    return api_get(path)


def upsert_gateway_rule(name: str, payload: Dict) -> Dict:
    """Create or update a Gateway rule by name.

    If a rule with the same name already exists, it will be updated in place
    using the provided payload.  Otherwise a new rule will be created.
    """
    # Look up existing rule by name; names are unique per account.
    existing = next((r for r in list_gateway_rules() if r.get("name") == name), None)
    if existing:
        rule_id = existing["id"]
        return api_put(f"/accounts/{ACCOUNT_ID}/gateway/rules/{rule_id}", payload)
    else:
        return api_post(f"/accounts/{ACCOUNT_ID}/gateway/rules", payload)


# -----------------------------------------------------------------------------
# Policy definitions
#
def build_policies() -> List[Dict]:
    """Construct a list of policy definitions to be applied.

    The definitions returned by this function contain all the fields required
    by the Cloudflare API, including ``name``, ``filters``, ``traffic``
    expressions, ``action``, and optional ``rule_settings`` such as the
    untrusted certificate behaviour for HTTP rules.
    """
    # Choose malicious categories to block.  These names correspond to
    # Cloudflare's security categories which cover threats like malware,
    # phishing and command‑and‑control activity【419096146802914†L750-L776】.
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
        print("Warning: some category names were not resolved:", ", ".join(missing))
    if not malicious_ids:
        raise RuntimeError(
            "Failed to resolve any malicious category IDs; cannot proceed without them."
        )
    # Build expressions using the resolved IDs.  Join IDs with spaces per
    # Cloudflare's expression syntax, for example {1 2 3}.
    ids_str = " ".join(str(i) for i in malicious_ids)
    dns_expression = f"any(dns.content_category[*] in {{{ids_str}}})"
    http_expression = f"any(http.content_category[*] in {{{ids_str}}})"

    policies: List[Dict] = []

    # DNS policy to block malicious categories
    policies.append(
        {
            "name": "DNS: Block Security Threat Categories",
            "description": "Block domains in Cloudflare's malicious security categories at the DNS layer.",
            "filters": ["dns"],
            "traffic": dns_expression,
            "action": "block",
            "enabled": True,
            "precedence": 1000,
        }
    )

    # HTTP policy to block malicious categories and enforce certificate validity
    policies.append(
        {
            "name": "HTTP: Block Security Threat Categories",
            "description": "Block malicious security categories at the HTTP layer and block untrusted certificates.",
            "filters": ["http"],
            "traffic": http_expression,
            "action": "block",
            "enabled": True,
            "precedence": 1100,
            "rule_settings": {
                # Valid options for untrusted_certificate: block | error | pass_through
                # Setting this to 'block' causes Gateway to display the organisation's
                # block page when a site presents an expired or self‑signed certificate【969046013694795†L882-L892】.
                "untrusted_certificate": "block",
            },
        }
    )

    # HTTP policy to quarantine risky downloads via sandbox (optional)
    policies.append(
        {
            "name": "HTTP: Quarantine High‑Risk File Downloads",
            "description": "Send executable, archive and document downloads to Cloudflare's file sandbox.",
            "filters": ["http"],
            # Cloudflare supports file type selectors for downloads.  This expression
            # matches file extensions and MIME types associated with risky files.
            "traffic": 'any(http.download.filetype[*] in {"exe" "msi" "dll" "js" "jar" "bat" "cmd" "scr" "ps1" "apk" "ipa" "zip" "rar" "7z" "pdf" "doc" "docx" "xls" "xlsx" "ppt" "pptx"})',
            "action": "quarantine",
            "enabled": True,
            "precedence": 1150,
            "rule_settings": {
                # Limit sandboxing to the specified file types rather than all files
                "sandbox_all_file_types": False,
            },
        }
    )

    # Network rule to block Tor traffic.  Cloudflare's docs state that the Tor
    # network can be matched via the special continent code 'T1'【419096146802914†L716-L733】.
    policies.append(
        {
            "name": "L4: Block Tor Network",
            "description": "Block all network traffic originating from or destined to Tor exit nodes.",
            "filters": ["l4"],
            "traffic": 'net.src.geo.continent == "T1" or net.dst.geo.continent == "T1"',
            "action": "block",
            "enabled": True,
            "precedence": 2000,
        }
    )

    # Network rule to block traffic to a list of high‑risk countries.  This
    # example uses a few ISO‑3166 country codes; adjust the list as needed.
    policies.append(
        {
            "name": "L4: Block High‑Risk Country Destinations",
            "description": "Block traffic destined for selected high‑risk countries at the network layer.",
            "filters": ["l4"],
            # The 'any' operator allows matching against a set of destination
            # countries.  You can modify the set to suit your organisation's
            # policy.  For sources, use net.src.geo.country.
            "traffic": 'any(net.dst.geo.country[*] in {"RU" "KP" "IR" "SY" "AF" "SO" "YE"})',
            "action": "block",
            "enabled": True,
            "precedence": 2010,
        }
    )

    return policies


def apply_policies(policies: List[Dict]) -> None:
    """Create or update all policies defined in the provided list."""
    for policy in policies:
        print(f"Upserting rule: {policy['name']}")
        upsert_gateway_rule(policy["name"], policy)


def disable_rules(names: List[str]) -> None:
    """Disable existing rules by name.

    For each rule name in the provided list, this function fetches the current
    rule configuration and updates its ``enabled`` field to ``False``.  If a
    rule does not exist, the function prints a warning and proceeds to the
    next.  The update uses the existing rule payload to ensure that all
    required fields are preserved when disabling the rule.
    """
    existing_rules = list_gateway_rules()
    name_to_rule = {r.get("name"): r for r in existing_rules}
    for name in names:
        rule = name_to_rule.get(name)
        if not rule:
            print(f"Warning: rule '{name}' not found for disabling")
            continue
        if not rule.get("enabled", False):
            print(f"Rule '{name}' is already disabled")
            continue
        # Prepare payload by copying existing fields and toggling enabled flag
        payload = {k: v for k, v in rule.items() if k not in {"id", "created_at", "updated_at", "deleted_at", "source_account"}}
        payload["enabled"] = False
        rule_id = rule["id"]
        print(f"Disabling rule: {name}")
        api_put(f"/accounts/{ACCOUNT_ID}/gateway/rules/{rule_id}", payload)


def summarize_policies(names: List[str]) -> None:
    """Print a summary of the specified policies after applying them."""
    existing_rules = list_gateway_rules()
    for name in names:
        rule = next((r for r in existing_rules if r.get("name") == name), None)
        if rule:
            print(json.dumps(
                {
                    "name": rule["name"],
                    "id": rule.get("id"),
                    "filters": rule.get("filters"),
                    "action": rule.get("action"),
                    "enabled": rule.get("enabled"),
                    "precedence": rule.get("precedence"),
                    "traffic": rule.get("traffic"),
                    "rule_settings": rule.get("rule_settings"),
                },
                indent=2
            ))
        else:
            print(f"Rule not found: {name}")


def main() -> None:
    # Build policy definitions and apply them to Cloudflare.
    policies = build_policies()
    # Disable legacy or host-specific TLS and obsolete network rules
    rules_to_disable = [
        "TLS Policy - Block Expired Certificate Sites",
        "TLS Policy - Block Self-Signed Certificate Sites",
        "TLS Policy - Block Revoked Certificate Sites",
        "TLS Policy - Block Weak Encryption Sites",
        "TLS Policy - Block Invalid Hostname Sites",
        # Remove the global L4 allow rule for HTTPS; explicit allow is not needed
        "Network: Allow HTTPS",
    ]
    disable_rules(rules_to_disable)
    # Apply the updated baseline policies
    apply_policies(policies)
    # Wait briefly for propagation before summarising
    time.sleep(2)
    # Summarise the policies we just applied
    names = [policy["name"] for policy in policies]
    print("\nSummary of provisioned policies:")
    summarize_policies(names)
    print(
        textwrap.dedent(
            """
            To test the DNS and HTTP rules, enable TLS decryption in your Gateway
            configuration (which requires installing the Cloudflare root certificate
            on client devices) and generate traffic to known malicious categories.
            Monitor your Gateway logs for the 'content_category' fields and the
            'UntrustedCertificateAction' field; a value of 'block' indicates
            certificate enforcement【903017829181420†L523-L532】.
            """
        )
    )


if __name__ == "__main__":
    main()