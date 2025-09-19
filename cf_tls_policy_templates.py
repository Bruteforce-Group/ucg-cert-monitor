#!/usr/bin/env python3
"""
Cloudflare Zero Trust HTTP/HTTPS Policy Templates
Provides configuration templates and automation for certificate validation rules
"""

import json
import os
import yaml
from datetime import datetime
from typing import Dict, List, Any

class CloudflarePolicyTemplates:
    def __init__(self):
        self.policy_templates = {}
        self.initialize_templates()
        
    def initialize_templates(self):
        """Initialize all policy templates"""
        self.policy_templates = {
            'certificate_validation': self.get_certificate_validation_policies(),
            'security_hardening': self.get_security_hardening_policies(),
            'compliance': self.get_compliance_policies(),
            'monitoring': self.get_monitoring_policies(),
        }
        
    def get_certificate_validation_policies(self) -> List[Dict[str, Any]]:
        """Certificate validation policy templates"""
        return [
            {
                "name": "Block Invalid SSL Certificates",
                "description": "Block connections to sites with invalid, expired, or self-signed certificates",
                "type": "http",
                "action": "block",
                "enabled": True,
                "priority": 100,
                "conditions": [
                    {
                        "field": "ssl.certificate.status",
                        "operator": "in",
                        "values": ["invalid", "expired", "self-signed", "revoked"]
                    }
                ],
                "settings": {
                    "block_page_enabled": True,
                    "block_reason": "Invalid SSL certificate detected",
                    "log_enabled": True
                }
            },
            {
                "name": "Warn on Weak SSL/TLS",
                "description": "Warn users about weak encryption protocols and cipher suites",
                "type": "http",
                "action": "allow",
                "enabled": True,
                "priority": 200,
                "conditions": [
                    {
                        "field": "ssl.cipher_suite",
                        "operator": "contains_any",
                        "values": ["RC4", "DES", "MD5", "NULL"]
                    },
                    {
                        "field": "ssl.version",
                        "operator": "in", 
                        "values": ["SSLv2", "SSLv3", "TLSv1.0"]
                    }
                ],
                "settings": {
                    "warning_enabled": True,
                    "warning_message": "This connection uses weak encryption",
                    "log_enabled": True
                }
            },
            {
                "name": "Block Untrusted Certificate Authorities",
                "description": "Block connections from certificates issued by untrusted CAs",
                "type": "http",
                "action": "block",
                "enabled": False,  # Disabled by default - requires customization
                "priority": 150,
                "conditions": [
                    {
                        "field": "ssl.certificate.issuer",
                        "operator": "not_in",
                        "values": [
                            "DigiCert Inc",
                            "Let's Encrypt Authority",
                            "Amazon",
                            "Google Trust Services",
                            "Sectigo Limited",
                            "GlobalSign",
                            "Entrust"
                            # Add your trusted CAs here
                        ]
                    }
                ],
                "settings": {
                    "block_page_enabled": True,
                    "block_reason": "Certificate issued by untrusted authority",
                    "log_enabled": True
                }
            },
            {
                "name": "Require Certificate Transparency",
                "description": "Block certificates not logged in Certificate Transparency logs",
                "type": "http", 
                "action": "block",
                "enabled": True,
                "priority": 175,
                "conditions": [
                    {
                        "field": "ssl.certificate.ct_compliance",
                        "operator": "equals",
                        "values": ["non_compliant"]
                    },
                    {
                        "field": "host",
                        "operator": "matches_regex",
                        "values": [".*\\.(bank|financial|gov)\\..*"]  # Critical domains
                    }
                ],
                "settings": {
                    "block_page_enabled": True,
                    "block_reason": "Certificate not logged in CT logs",
                    "log_enabled": True
                }
            }
        ]
        
    def get_security_hardening_policies(self) -> List[Dict[str, Any]]:
        """Security hardening policy templates"""
        return [
            {
                "name": "Enforce HSTS for Critical Sites",
                "description": "Ensure HSTS is enabled for critical business applications",
                "type": "http",
                "action": "block",
                "enabled": True,
                "priority": 300,
                "conditions": [
                    {
                        "field": "host",
                        "operator": "in",
                        "values": [
                            "*.company.com",
                            "*.internal.local",
                            # Add your internal domains
                        ]
                    },
                    {
                        "field": "ssl.hsts_enabled",
                        "operator": "equals",
                        "values": [False]
                    }
                ],
                "settings": {
                    "block_page_enabled": True,
                    "block_reason": "HSTS not enabled on critical site",
                    "log_enabled": True
                }
            },
            {
                "name": "Block Short Certificate Validity",
                "description": "Block certificates that expire too soon",
                "type": "http",
                "action": "allow",  # Start with allow + warning
                "enabled": True,
                "priority": 250,
                "conditions": [
                    {
                        "field": "ssl.certificate.days_until_expiry",
                        "operator": "less_than",
                        "values": [30]
                    }
                ],
                "settings": {
                    "warning_enabled": True,
                    "warning_message": "Certificate expires within 30 days",
                    "log_enabled": True
                }
            },
            {
                "name": "Enforce Strong Key Sizes",
                "description": "Block certificates with weak key sizes",
                "type": "http",
                "action": "block",
                "enabled": True,
                "priority": 180,
                "conditions": [
                    {
                        "field": "ssl.certificate.public_key_size",
                        "operator": "less_than",
                        "values": [2048]
                    }
                ],
                "settings": {
                    "block_page_enabled": True,
                    "block_reason": "Certificate uses weak key size",
                    "log_enabled": True
                }
            },
            {
                "name": "Block Mixed Content",
                "description": "Block HTTP resources loaded over HTTPS pages",
                "type": "http",
                "action": "block",
                "enabled": True,
                "priority": 320,
                "conditions": [
                    {
                        "field": "http.request.uri.scheme",
                        "operator": "equals",
                        "values": ["http"]
                    },
                    {
                        "field": "http.referer.scheme", 
                        "operator": "equals",
                        "values": ["https"]
                    }
                ],
                "settings": {
                    "block_page_enabled": True,
                    "block_reason": "Mixed content not allowed",
                    "log_enabled": True
                }
            }
        ]
        
    def get_compliance_policies(self) -> List[Dict[str, Any]]:
        """Compliance-focused policy templates"""
        return [
            {
                "name": "PCI DSS Certificate Requirements",
                "description": "Enforce PCI DSS certificate requirements for payment processing",
                "type": "http",
                "action": "block",
                "enabled": False,  # Enable for PCI environments
                "priority": 400,
                "conditions": [
                    {
                        "field": "host",
                        "operator": "matches_regex",
                        "values": [".*\\.(payment|billing|checkout)\\..*"]
                    },
                    {
                        "field": "ssl.certificate.type",
                        "operator": "not_equals",
                        "values": ["extended_validation"]
                    }
                ],
                "settings": {
                    "block_page_enabled": True,
                    "block_reason": "EV certificate required for payment processing",
                    "log_enabled": True
                }
            },
            {
                "name": "HIPAA Compliance Certificate Validation",
                "description": "Enhanced certificate validation for healthcare applications",
                "type": "http",
                "action": "block",
                "enabled": False,  # Enable for healthcare environments
                "priority": 450,
                "conditions": [
                    {
                        "field": "host",
                        "operator": "matches_regex",
                        "values": [".*\\.(health|medical|hipaa)\\..*"]
                    },
                    {
                        "field": "ssl.certificate.validation_level",
                        "operator": "in",
                        "values": ["domain_validated"]
                    }
                ],
                "settings": {
                    "block_page_enabled": True,
                    "block_reason": "Organization validated certificate required",
                    "log_enabled": True
                }
            },
            {
                "name": "Government Site Certificate Validation",
                "description": "Enhanced validation for government websites",
                "type": "http",
                "action": "block",
                "enabled": True,
                "priority": 475,
                "conditions": [
                    {
                        "field": "host",
                        "operator": "matches_regex",
                        "values": [".*\\.gov$", ".*\\.mil$", ".*\\.edu$"]
                    },
                    {
                        "field": "ssl.certificate.issuer",
                        "operator": "not_contains",
                        "values": ["Government", "Federal", "DigiCert"]
                    }
                ],
                "settings": {
                    "block_page_enabled": True,
                    "block_reason": "Invalid certificate authority for government site",
                    "log_enabled": True
                }
            }
        ]
        
    def get_monitoring_policies(self) -> List[Dict[str, Any]]:
        """Monitoring and alerting policy templates"""
        return [
            {
                "name": "Monitor Certificate Changes",
                "description": "Log certificate changes for monitoring",
                "type": "http",
                "action": "allow",
                "enabled": True,
                "priority": 500,
                "conditions": [
                    {
                        "field": "ssl.certificate.fingerprint_changed",
                        "operator": "equals",
                        "values": [True]
                    }
                ],
                "settings": {
                    "log_enabled": True,
                    "log_details": "full_certificate_info",
                    "alert_enabled": True,
                    "alert_threshold": 1
                }
            },
            {
                "name": "Track Certificate Authority Usage",
                "description": "Monitor which CAs are being used across your traffic",
                "type": "http",
                "action": "allow",
                "enabled": True,
                "priority": 550,
                "conditions": [
                    {
                        "field": "ssl.enabled",
                        "operator": "equals",
                        "values": [True]
                    }
                ],
                "settings": {
                    "log_enabled": True,
                    "log_fields": ["ssl.certificate.issuer", "ssl.certificate.subject"],
                    "sampling_rate": 0.1  # Log 10% of requests
                }
            },
            {
                "name": "Alert on New Certificate Authorities",
                "description": "Alert when certificates from new/unknown CAs are encountered",
                "type": "http",
                "action": "allow",
                "enabled": True,
                "priority": 525,
                "conditions": [
                    {
                        "field": "ssl.certificate.issuer",
                        "operator": "not_in_baseline",
                        "values": ["learned_ca_baseline"]  # Cloudflare learns normal CAs
                    }
                ],
                "settings": {
                    "alert_enabled": True,
                    "alert_message": "New certificate authority detected",
                    "log_enabled": True
                }
            }
        ]
        
    def generate_cloudflare_config(self, policy_categories: List[str] = None) -> Dict[str, Any]:
        """Generate Cloudflare Zero Trust configuration"""
        if policy_categories is None:
            policy_categories = list(self.policy_templates.keys())
            
        config = {
            "account_id": "your-account-id",  # Replace with actual account ID
            "team_name": "your-team",         # Replace with actual team name
            "policies": [],
            "generated_at": datetime.now().isoformat(),
            "version": "1.0"
        }
        
        for category in policy_categories:
            if category in self.policy_templates:
                config["policies"].extend(self.policy_templates[category])
                
        return config
        
    def export_terraform(self, output_file: str = "cloudflare_policies.tf"):
        """Export policies as Terraform configuration"""
        terraform_config = []
        
        # Add Terraform provider configuration
        terraform_config.append('''
terraform {
  required_providers {
    cloudflare = {
      source = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "cloudflare" {
  # Configuration will be taken from environment variables:
  # CLOUDFLARE_API_TOKEN or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY
}

variable "account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "team_name" {
  description = "Cloudflare Zero Trust team name"
  type        = string
}
''')

        # Generate policy resources
        policy_count = 1
        for category, policies in self.policy_templates.items():
            for policy in policies:
                tf_resource = f'''
resource "cloudflare_access_policy" "tls_policy_{policy_count}" {{
  account_id     = var.account_id
  name          = "{policy['name']}"
  precedence    = {policy['priority']}
  decision      = "{policy['action']}"
  
  include {{
    # Configure your include conditions based on policy requirements
    everyone = {str(policy.get('enabled', True)).lower()}
  }}
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}}
'''
                terraform_config.append(tf_resource)
                policy_count += 1
                
        # Write Terraform file
        with open(output_file, 'w') as f:
            f.write('\n'.join(terraform_config))
            
        return output_file
        
    def export_json(self, output_file: str = "cf_policies.json"):
        """Export policies as JSON configuration"""
        config = self.generate_cloudflare_config()
        
        with open(output_file, 'w') as f:
            json.dump(config, f, indent=2, sort_keys=True)
            
        return output_file
        
    def export_yaml(self, output_file: str = "cf_policies.yaml"):
        """Export policies as YAML configuration"""
        config = self.generate_cloudflare_config()
        
        with open(output_file, 'w') as f:
            yaml.dump(config, f, indent=2, sort_keys=True)
            
        return output_file
        
    def create_policy_deployment_script(self, output_file: str = "deploy_cf_policies.py"):
        """Create a deployment script for the policies"""
        script_content = '''#!/usr/bin/env python3
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
                    
            print(f"\\nDeployment complete: {success_count}/{total_count} policies deployed successfully")
            
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
'''
        
        with open(output_file, 'w') as f:
            f.write(script_content)
            
        os.chmod(output_file, 0o755)
        return output_file
        
    def generate_all_configs(self):
        """Generate all configuration formats"""
        print("Generating Cloudflare Zero Trust TLS Policy Configurations...")
        
        # Export in different formats
        json_file = self.export_json()
        yaml_file = self.export_yaml()
        tf_file = self.export_terraform()
        deploy_script = self.create_policy_deployment_script()
        
        print(f"✅ Generated configuration files:")
        print(f"  - JSON: {json_file}")
        print(f"  - YAML: {yaml_file}")
        print(f"  - Terraform: {tf_file}")
        print(f"  - Deployment script: {deploy_script}")
        
        # Create summary
        summary = {
            "total_policies": sum(len(policies) for policies in self.policy_templates.values()),
            "categories": list(self.policy_templates.keys()),
            "files_generated": [json_file, yaml_file, tf_file, deploy_script],
            "next_steps": [
                "Review and customize policy configurations",
                "Set Cloudflare account ID and API token",
                "Test policies in staging environment",
                "Deploy to production using deployment script"
            ]
        }
        
        with open('policy_generation_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
            
        return summary

def main():
    templates = CloudflarePolicyTemplates()
    summary = templates.generate_all_configs()
    
    print("\n📋 Summary:")
    print(f"Generated {summary['total_policies']} policies across {len(summary['categories'])} categories")
    
    print("\n🚀 Next Steps:")
    for step in summary['next_steps']:
        print(f"  1. {step}")

if __name__ == "__main__":
    main()
