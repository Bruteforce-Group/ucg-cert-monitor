#!/usr/bin/env python3
"""
Test Cloudflare Gateway Security Features
Tests various security capabilities including TLS inspection
"""

import dns.resolver
import requests
import ssl
import socket
import json
from datetime import datetime

class CloudflareGatewayTester:
    def __init__(self, gateway_ip="162.159.36.5"):
        self.gateway_ip = gateway_ip
        self.results = {}
        
    def test_dns_filtering(self):
        """Test DNS-based filtering capabilities"""
        print("\n=== DNS Filtering Tests ===")
        
        test_domains = [
            "google.com",  # Should work
            "malware.testing.google.test",  # Test domain
            "3386.com",  # Known malware domain
            "testmaliciousdomain.org",  # Test blocked domain
        ]
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.gateway_ip]
        resolver.timeout = 3
        
        for domain in test_domains:
            try:
                answers = resolver.resolve(domain, 'A')
                ips = [str(rdata) for rdata in answers]
                print(f"✓ {domain}: {ips}")
                
                # Check if it's blocked by looking for Cloudflare block page IPs
                if any(ip.startswith('0.0.0.0') or 'blocked' in str(answers) for ip in ips):
                    print(f"  🚫 Domain appears to be blocked")
                    
            except Exception as e:
                print(f"✗ {domain}: DNS query failed - {str(e)}")
                # This might indicate blocking
                
    def test_tls_inspection_indicators(self):
        """Test for TLS inspection capabilities"""
        print("\n=== TLS Inspection Detection ===")
        
        test_sites = [
            "httpbin.org",
            "google.com", 
            "github.com",
        ]
        
        for site in test_sites:
            try:
                # Create SSL context
                context = ssl.create_default_context()
                
                # Connect and get certificate
                with socket.create_connection((site, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=site) as ssock:
                        cert = ssock.getpeercert()
                        
                        print(f"\n🔒 {site}:")
                        print(f"  Subject: {cert.get('subject', 'N/A')}")
                        print(f"  Issuer: {cert.get('issuer', 'N/A')}")
                        print(f"  Version: {cert.get('version', 'N/A')}")
                        
                        # Check if cert is from Cloudflare or indicates inspection
                        issuer_str = str(cert.get('issuer', ''))
                        if 'cloudflare' in issuer_str.lower() or 'gateway' in issuer_str.lower():
                            print(f"  🔍 TLS INSPECTION DETECTED - Certificate issued by Cloudflare/Gateway")
                        
                        # Look for signs of TLS inspection (intermediate CA that's not expected)
                        for rdn in cert.get('issuer', []):
                            for k, v in rdn:
                                if k == 'organizationName' or k == 'commonName':
                                    print(f"  Issuer {k}: {v}")
                            
            except Exception as e:
                print(f"✗ {site}: TLS test failed - {str(e)}")
    
    def test_category_blocking(self):
        """Test different category blocking"""
        print("\n=== Category Blocking Tests ===")
        
        categories_to_test = {
            "Social Media": ["facebook.com", "twitter.com"],
            "Malware": ["malware.testing.google.test"],
            "Adult Content": ["adult-test-domain.com"],
        }
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [self.gateway_ip]
        resolver.timeout = 3
        
        for category, domains in categories_to_test.items():
            print(f"\n📂 {category}:")
            for domain in domains:
                try:
                    answers = resolver.resolve(domain, 'A')
                    ips = [str(rdata) for rdata in answers]
                    
                    # Check for Cloudflare block page responses
                    blocked_indicators = [
                        '0.0.0.0',
                        '162.159.36.1',  # Cloudflare block page
                        '162.159.37.1',
                    ]
                    
                    if any(ip in blocked_indicators for ip in ips):
                        print(f"  🚫 {domain}: BLOCKED")
                    else:
                        print(f"  ✓ {domain}: Allowed - {ips[0] if ips else 'No IP'}")
                        
                except dns.resolver.NXDOMAIN:
                    print(f"  ❓ {domain}: Domain doesn't exist")
                except Exception as e:
                    print(f"  ⚠️  {domain}: Query failed - {str(e)}")
    
    def check_security_features(self):
        """Check for active security features"""
        print("\n=== Security Feature Detection ===")
        
        # Test for DNS over HTTPS blocking
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.gateway_ip]
            answers = resolver.resolve('cloudflare-dns.com', 'A')
            print(f"DoH providers: {[str(rdata) for rdata in answers]}")
        except:
            print("DoH providers: May be blocked")
            
        # Test for safe browsing
        print("\nSafe Browsing Integration:")
        print("- Cloudflare Gateway integrates with multiple threat intel feeds")
        print("- Can inspect TLS traffic when configured")
        print("- Provides DNS-based security filtering")
        print("- May block malicious domains, C&C servers, etc.")

    def run_all_tests(self):
        """Run all security tests"""
        print("Cloudflare Gateway Security Analysis")
        print("=" * 50)
        print(f"Gateway IP: {self.gateway_ip}")
        print(f"Test Time: {datetime.now().isoformat()}")
        
        self.test_dns_filtering()
        self.test_tls_inspection_indicators()
        self.test_category_blocking() 
        self.check_security_features()
        
        print("\n" + "=" * 50)
        print("Analysis Complete")

if __name__ == "__main__":
    tester = CloudflareGatewayTester()
    tester.run_all_tests()
