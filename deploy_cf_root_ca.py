#!/usr/bin/env python3
"""
Cloudflare Zero Trust Root CA Certificate Deployment Tool
Automatically downloads and installs CF ZT root CA on various platforms
"""

import os
import sys
import subprocess
import platform
import requests
import tempfile
import logging
from pathlib import Path

class CloudflareCADeployer:
    def __init__(self):
        self.cf_ca_url = "https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt"
        self.cert_content = None
        self.platform = platform.system().lower()
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cf_ca_deployment.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def download_certificate(self):
        """Download Cloudflare root CA certificate"""
        self.logger.info("Downloading Cloudflare Zero Trust root CA certificate...")
        
        try:
            response = requests.get(self.cf_ca_url, timeout=30)
            response.raise_for_status()
            
            self.cert_content = response.text
            self.logger.info("Successfully downloaded certificate")
            
            # Validate certificate format
            if "BEGIN CERTIFICATE" not in self.cert_content:
                raise ValueError("Downloaded content is not a valid certificate")
                
            return True
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to download certificate: {e}")
            return False
        except ValueError as e:
            self.logger.error(f"Invalid certificate format: {e}")
            return False
            
    def install_macos(self):
        """Install certificate on macOS"""
        self.logger.info("Installing certificate on macOS...")
        
        try:
            # Create temporary certificate file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(self.cert_content)
                cert_file = f.name
                
            try:
                # Install certificate to system keychain
                cmd = [
                    'sudo', 'security', 'add-trusted-cert',
                    '-d', '-r', 'trustRoot',
                    '-k', '/Library/Keychains/System.keychain',
                    cert_file
                ]
                
                self.logger.info("Installing to system keychain (requires sudo)...")
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                
                # Verify installation
                verify_cmd = [
                    'security', 'find-certificate',
                    '-c', 'Cloudflare',
                    '-p', '/Library/Keychains/System.keychain'
                ]
                
                subprocess.run(verify_cmd, capture_output=True, text=True, check=True)
                self.logger.info("✅ Certificate successfully installed and verified on macOS")
                
                # Also install for current user
                user_cmd = [
                    'security', 'add-trusted-cert',
                    '-d', '-r', 'trustRoot',
                    '-k', os.path.expanduser('~/Library/Keychains/login.keychain-db'),
                    cert_file
                ]
                
                subprocess.run(user_cmd, capture_output=True, text=True)
                self.logger.info("Certificate also installed to user keychain")
                
                return True
                
            finally:
                # Clean up temporary file
                os.unlink(cert_file)
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install certificate on macOS: {e}")
            self.logger.error(f"Command output: {e.stderr}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during macOS installation: {e}")
            return False
            
    def install_linux(self):
        """Install certificate on Linux"""
        self.logger.info("Installing certificate on Linux...")
        
        try:
            # Determine certificate directory
            cert_dirs = [
                '/usr/local/share/ca-certificates',
                '/etc/pki/ca-trust/source/anchors',  # RHEL/CentOS
                '/usr/share/ca-certificates/extra'    # Some distributions
            ]
            
            cert_dir = None
            for directory in cert_dirs:
                if os.path.exists(directory):
                    cert_dir = directory
                    break
                    
            if not cert_dir:
                # Create the most common directory
                cert_dir = '/usr/local/share/ca-certificates'
                os.makedirs(cert_dir, exist_ok=True)
                
            cert_file = os.path.join(cert_dir, 'cloudflare-zero-trust-ca.crt')
            
            # Write certificate file
            with open(cert_file, 'w') as f:
                f.write(self.cert_content)
                
            # Update certificate store
            update_commands = [
                ['update-ca-certificates'],  # Debian/Ubuntu
                ['update-ca-trust'],         # RHEL/CentOS
            ]
            
            success = False
            for cmd in update_commands:
                try:
                    result = subprocess.run(['sudo'] + cmd, capture_output=True, text=True, check=True)
                    self.logger.info(f"Certificate store updated using {cmd[0]}")
                    success = True
                    break
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
                    
            if success:
                self.logger.info("✅ Certificate successfully installed on Linux")
                return True
            else:
                self.logger.warning("Certificate file created but certificate store update may have failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to install certificate on Linux: {e}")
            return False
            
    def install_windows(self):
        """Install certificate on Windows (PowerShell required)"""
        self.logger.info("Installing certificate on Windows...")
        
        try:
            # Create temporary certificate file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(self.cert_content)
                cert_file = f.name
                
            try:
                # PowerShell command to install certificate
                ps_cmd = f'''
                $cert = "{cert_file}"
                Import-Certificate -FilePath $cert -CertStoreLocation "Cert:\\LocalMachine\\Root"
                Write-Output "Certificate installed successfully"
                '''
                
                # Execute PowerShell command
                result = subprocess.run([
                    'powershell', '-Command', ps_cmd
                ], capture_output=True, text=True, check=True)
                
                self.logger.info("✅ Certificate successfully installed on Windows")
                return True
                
            finally:
                os.unlink(cert_file)
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install certificate on Windows: {e}")
            self.logger.error(f"PowerShell output: {e.stderr}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during Windows installation: {e}")
            return False
            
    def create_mobile_profiles(self):
        """Create mobile device configuration profiles"""
        self.logger.info("Creating mobile device configuration profiles...")
        
        try:
            # iOS Configuration Profile
            ios_profile = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>cloudflare-zero-trust-ca.crt</string>
            <key>PayloadContent</key>
            <data>
{self._cert_to_base64()}
            </data>
            <key>PayloadDescription</key>
            <string>Cloudflare Zero Trust Root CA</string>
            <key>PayloadDisplayName</key>
            <string>Cloudflare Zero Trust CA</string>
            <key>PayloadIdentifier</key>
            <string>com.company.cloudflare-zt-ca</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>cloudflare-zt-ca-uuid</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Installs Cloudflare Zero Trust Root CA</string>
    <key>PayloadDisplayName</key>
    <string>Cloudflare Zero Trust Certificate</string>
    <key>PayloadIdentifier</key>
    <string>com.company.cloudflare-zt-profile</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>cloudflare-zt-profile-uuid</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>'''
            
            # Save iOS profile
            with open('cloudflare_zt_ca_ios.mobileconfig', 'w') as f:
                f.write(ios_profile)
                
            # Save certificate for Android
            with open('cloudflare_zt_ca.crt', 'w') as f:
                f.write(self.cert_content)
                
            self.logger.info("✅ Mobile configuration profiles created:")
            self.logger.info("  - iOS: cloudflare_zt_ca_ios.mobileconfig")
            self.logger.info("  - Android: cloudflare_zt_ca.crt")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create mobile profiles: {e}")
            return False
            
    def _cert_to_base64(self):
        """Convert certificate content to base64 for mobile profiles"""
        import base64
        
        # Extract the certificate content (remove headers)
        cert_lines = self.cert_content.strip().split('\n')
        cert_data = '\n'.join([line for line in cert_lines 
                              if not line.startswith('---')])
        
        return cert_data
        
    def verify_installation(self):
        """Verify certificate installation"""
        self.logger.info("Verifying certificate installation...")
        
        try:
            if self.platform == 'darwin':  # macOS
                cmd = ['security', 'find-certificate', '-c', 'Cloudflare', '-p']
                result = subprocess.run(cmd, capture_output=True, text=True)
                return result.returncode == 0
                
            elif self.platform == 'linux':
                # Check if certificate exists in CA bundle
                cmd = ['openssl', 'x509', '-in', '/etc/ssl/certs/ca-certificates.crt', '-text', '-noout']
                result = subprocess.run(cmd, capture_output=True, text=True)
                return 'Cloudflare' in result.stdout
                
            elif self.platform == 'windows':
                # PowerShell command to check certificate store
                ps_cmd = 'Get-ChildItem -Path "Cert:\\LocalMachine\\Root" | Where-Object {$_.Subject -like "*Cloudflare*"}'
                result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                      capture_output=True, text=True)
                return len(result.stdout.strip()) > 0
                
        except Exception as e:
            self.logger.error(f"Verification failed: {e}")
            
        return False
        
    def deploy(self):
        """Main deployment function"""
        self.logger.info("Starting Cloudflare Zero Trust root CA deployment...")
        self.logger.info(f"Detected platform: {self.platform}")
        
        # Download certificate
        if not self.download_certificate():
            return False
            
        # Install based on platform
        success = False
        if self.platform == 'darwin':
            success = self.install_macos()
        elif self.platform == 'linux':
            success = self.install_linux()
        elif self.platform == 'windows':
            success = self.install_windows()
        else:
            self.logger.error(f"Unsupported platform: {self.platform}")
            
        # Create mobile profiles regardless of current platform
        self.create_mobile_profiles()
        
        # Verify installation
        if success:
            if self.verify_installation():
                self.logger.info("✅ Certificate installation verified successfully!")
            else:
                self.logger.warning("⚠️ Certificate installed but verification failed")
                
        return success
        
    def generate_deployment_script(self):
        """Generate deployment scripts for different platforms"""
        self.logger.info("Generating deployment scripts...")
        
        # macOS script
        macos_script = '''#!/bin/bash
# macOS Cloudflare Zero Trust CA Deployment Script

echo "Downloading Cloudflare Zero Trust Root CA..."
curl -o /tmp/cloudflare_ca.crt https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt

echo "Installing certificate to system keychain..."
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/cloudflare_ca.crt

echo "Installing certificate to user keychain..."
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db /tmp/cloudflare_ca.crt

echo "Cleaning up..."
rm /tmp/cloudflare_ca.crt

echo "✅ Cloudflare Zero Trust CA installed successfully!"
'''
        
        # Linux script  
        linux_script = '''#!/bin/bash
# Linux Cloudflare Zero Trust CA Deployment Script

echo "Downloading Cloudflare Zero Trust Root CA..."
wget -O /tmp/cloudflare_ca.crt https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt

echo "Installing certificate..."
sudo mkdir -p /usr/local/share/ca-certificates
sudo cp /tmp/cloudflare_ca.crt /usr/local/share/ca-certificates/cloudflare-zero-trust-ca.crt

echo "Updating certificate store..."
sudo update-ca-certificates || sudo update-ca-trust

echo "Cleaning up..."
rm /tmp/cloudflare_ca.crt

echo "✅ Cloudflare Zero Trust CA installed successfully!"
'''
        
        # Windows PowerShell script
        windows_script = '''# Windows Cloudflare Zero Trust CA Deployment Script
# Run as Administrator

Write-Host "Downloading Cloudflare Zero Trust Root CA..."
$url = "https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt"
$cert_file = "$env:TEMP\\cloudflare_ca.crt"
Invoke-WebRequest -Uri $url -OutFile $cert_file

Write-Host "Installing certificate to machine root store..."
Import-Certificate -FilePath $cert_file -CertStoreLocation "Cert:\\LocalMachine\\Root"

Write-Host "Cleaning up..."
Remove-Item $cert_file

Write-Host "✅ Cloudflare Zero Trust CA installed successfully!"
'''
        
        # Save scripts
        with open('deploy_cf_ca_macos.sh', 'w') as f:
            f.write(macos_script)
            
        with open('deploy_cf_ca_linux.sh', 'w') as f:
            f.write(linux_script)
            
        with open('deploy_cf_ca_windows.ps1', 'w') as f:
            f.write(windows_script)
            
        # Make shell scripts executable
        os.chmod('deploy_cf_ca_macos.sh', 0o755)
        os.chmod('deploy_cf_ca_linux.sh', 0o755)
        
        self.logger.info("✅ Deployment scripts generated:")
        self.logger.info("  - macOS: deploy_cf_ca_macos.sh")
        self.logger.info("  - Linux: deploy_cf_ca_linux.sh") 
        self.logger.info("  - Windows: deploy_cf_ca_windows.ps1")
        

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--generate-scripts':
        deployer = CloudflareCADeployer()
        deployer.generate_deployment_script()
        return
        
    print("Cloudflare Zero Trust Root CA Deployment Tool")
    print("=" * 50)
    
    deployer = CloudflareCADeployer()
    success = deployer.deploy()
    
    if success:
        print("\\n🎉 Deployment completed successfully!")
        print("\\nNext steps:")
        print("1. Configure TLS inspection policies in Cloudflare Zero Trust dashboard")
        print("2. Test certificate validation with test sites")
        print("3. Monitor Gateway logs for certificate-related blocks")
    else:
        print("\\n❌ Deployment failed. Check logs for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()
