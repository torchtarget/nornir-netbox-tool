#!/usr/bin/env python3
"""
Script to add discovered unknown devices to NetBox using pynetbox.

Usage:
    python add_devices_to_netbox.py unknown_devices_20250104_143052.txt

This script parses the nmap scan results and creates devices in NetBox with:
- Device name (from hostname or IP)
- IP address
- MAC address
- Device type (inferred from services)
- Operating system
- Services (as comments or custom fields)
"""

import sys
import re
import argparse
from typing import Dict, List, Optional
import pynetbox


class NetBoxDeviceAdder:
    def __init__(self, netbox_url: str, netbox_token: str):
        """Initialize NetBox API connection."""
        self.api = pynetbox.api(netbox_url, token=netbox_token)
        
    def parse_scan_file(self, filename: str) -> List[Dict]:
        """Parse the nmap scan results file."""
        devices = []
        
        with open(filename, 'r') as f:
            content = f.read()
        
        # Split by device sections
        device_sections = content.split('=' * 80)
        
        for section in device_sections:
            if 'Device:' not in section:
                continue
                
            device_info = self.parse_device_section(section)
            if device_info:
                devices.append(device_info)
        
        return devices
    
    def parse_device_section(self, section: str) -> Optional[Dict]:
        """Parse a single device section from the scan file."""
        lines = section.strip().split('\n')
        device_info = {}
        
        # Extract IP from header line
        for line in lines:
            if line.startswith('Device:'):
                match = re.search(r'Device: (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    device_info['ip'] = match.group(1)
                break
        
        if 'ip' not in device_info:
            return None
        
        # Parse nmap output to get MAC and other info
        nmap_output = '\n'.join(lines)
        nmap_info = self.parse_nmap_output(nmap_output)
        device_info.update(nmap_info)
        
        # Extract MAC from nmap output if not found
        if 'mac' not in device_info:
            for line in lines:
                if line.strip().startswith('MAC Address:'):
                    mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})', line)
                    if mac_match:
                        device_info['mac'] = mac_match.group(1)
                    break
            
            # If still no MAC found, set to Unknown
            if 'mac' not in device_info:
                device_info['mac'] = 'Unknown'
        
        return device_info
    
    def parse_nmap_output(self, nmap_output: str) -> Dict:
        """Parse nmap output to extract device information."""
        info = {
            'services': [],
            'os': None,
            'hostname': None,
            'manufacturer': 'Generic',
            'model': 'Unknown Device'
        }
        
        lines = nmap_output.split('\n')
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Extract hostname from scan report line
            # Format: "Nmap scan report for hostname (ip)" or "Nmap scan report for hostname.local (ip)" or just "Nmap scan report for ip"
            if line.startswith('Nmap scan report for'):
                hostname_match = re.search(r'Nmap scan report for ([^\s]+(?:\.[^\s]+)*)', line)
                if hostname_match:
                    hostname = hostname_match.group(1)
                    # Only use as hostname if it's not just an IP address
                    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
                        info['hostname'] = hostname.replace('.local', '')  # Clean up .local suffix
            
            # Extract manufacturer from MAC address line
            # Format: "MAC Address: XX:XX:XX:XX:XX:XX (Manufacturer Name)" or "MAC Address: XX:XX:XX:XX:XX:XX (Unknown)"
            if line.startswith('MAC Address:'):
                mac_match = re.search(r'MAC Address: [0-9A-Fa-f:]{17} \(([^)]+)\)', line)
                if mac_match:
                    manufacturer = mac_match.group(1).strip()
                    if manufacturer != 'Unknown':
                        info['manufacturer'] = manufacturer
            
            # Extract services (port/protocol open service version)
            # Format: "22/tcp open ssh OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)"
            service_match = re.search(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+?))?(?:\s+\([^)]+\))?$', line)
            if service_match:
                port = service_match.group(1)
                protocol = service_match.group(2)
                service = service_match.group(3)
                version = service_match.group(4) or ""
                
                info['services'].append({
                    'port': int(port),
                    'protocol': protocol,
                    'service': service,
                    'version': version.strip()
                })
            
            # Extract OS information - use as model
            # Format: "OS details: Linux 2.6.32"
            if line.startswith('OS details:'):
                info['os'] = line.split('OS details:')[1].strip()
                info['model'] = info['os']
            elif line.startswith('Running:') and not info['os']:
                info['os'] = line.split('Running:')[1].strip()
                info['model'] = info['os']
            
            # Extract device type from Service Info line
            # Format: "Service Info: OS: Linux; Devices: media device, webcam; CPE: cpe:/h:axis:q7404_video_encoder"
            if line.startswith('Service Info:'):
                # Look for Devices: section
                devices_match = re.search(r'Devices:\s*([^;]+)', line)
                if devices_match:
                    device_types = devices_match.group(1).strip()
                    if not info['model'] or info['model'] == 'Unknown Device':
                        info['model'] = device_types
                
                # Look for CPE hardware info
                cpe_match = re.search(r'cpe:/h:([^:]+):([^,;]+)', line)
                if cpe_match:
                    cpe_vendor = cpe_match.group(1).replace('_', ' ').title()
                    cpe_product = cpe_match.group(2).replace('_', ' ').title()
                    if info['manufacturer'] == 'Generic':
                        info['manufacturer'] = cpe_vendor
                    if not info['model'] or info['model'] == 'Unknown Device':
                        info['model'] = cpe_product
            
            # Extract HTTP titles (useful for device names)
            if '|_http-title:' in line:
                title_match = re.search(r'\|_http-title:\s*(.+)', line)
                if title_match and not info['hostname']:
                    title = title_match.group(1).strip()
                    if title != 'Index page':  # Skip generic titles
                        info['hostname'] = title
            
            # Extract SNMP system description - use as model if no OS
            if 'System Description:' in line:
                snmp_desc = line.split('System Description:')[1].strip()
                info['snmp_description'] = snmp_desc
                if not info['model'] or info['model'] == 'Unknown Device':
                    info['model'] = snmp_desc
        
        # If no model found but we have services, create a generic model
        if info['model'] == 'Unknown Device' and info['services']:
            service_names = [s['service'] for s in info['services']]
            if 'ssh' in service_names:
                info['model'] = 'SSH Server'
            elif 'http' in service_names or 'https' in service_names:
                info['model'] = 'Web Server'
            elif any(s in service_names for s in ['ftp', 'rtsp']):
                info['model'] = 'Network Device'
        
        return info
    
    def ensure_manufacturer(self, manufacturer_name: str, dry_run: bool = False) -> int:
        """Ensure manufacturer exists in NetBox, create if not."""
        try:
            manufacturers = list(self.api.dcim.manufacturers.filter(name=manufacturer_name))
            if manufacturers:
                return manufacturers[0].id
            
            if dry_run:
                print(f"   🏭 Would create manufacturer: {manufacturer_name}")
                return 1  # Dummy ID for dry run
            
            slug = manufacturer_name.lower().replace(' ', '-').replace('.', '').replace(',', '')
            manufacturer = self.api.dcim.manufacturers.create(
                name=manufacturer_name,
                slug=slug
            )
            print(f"   ✅ Created manufacturer: {manufacturer_name} (ID: {manufacturer.id})")
            return manufacturer.id
            
        except Exception as e:
            print(f"   ❌ Error with manufacturer {manufacturer_name}: {e}")
            return None
    
    def ensure_device_type(
        self,
        manufacturer_id: int,
        model: str,
        height: int = 1,
        dry_run: bool = False,
    ) -> int:
        """Ensure device type exists in NetBox, create if not.

        Device types require a model (name), manufacturer and rack unit height. If no
        height is provided, default to 1U.
        """
        try:
            device_types = list(
                self.api.dcim.device_types.filter(
                    model=model, manufacturer_id=manufacturer_id
                )
            )
            if device_types:
                return device_types[0].id

            if dry_run:
                print(f"   📱 Would create device type: {model} (height {height}U)")
                return 1  # Dummy ID for dry run

            slug = (
                model.lower().replace(" ", "-").replace(".", "").replace(",", "")[:50]
            )  # NetBox slug limit
            device_type = self.api.dcim.device_types.create(
                model=model,
                slug=slug,
                manufacturer=manufacturer_id,
                u_height=height,
            )

            # Add a basic interface template (eth0)
            self.api.dcim.interface_templates.create(
                device_type=device_type.id,
                name="eth0",
                type="1000base-t",
            )

            print(
                f"   ✅ Created device type: {model} (ID: {device_type.id}, {height}U) with interface eth0"
            )
            return device_type.id

        except Exception as e:
            print(f"   ❌ Error with device type {model}: {e}")
            return None
    
    def create_device_in_netbox(self, device_info: Dict, site_name: str = "Default", dry_run: bool = False):
        """Create a device in NetBox following proper hierarchy."""
        
        # Generate device name
        device_name = device_info.get('hostname') or f"device-{device_info['ip'].replace('.', '-')}"
        
        print(f"\n📝 Processing device: {device_name}")
        print(f"   IP: {device_info['ip']}")
        print(f"   MAC: {device_info['mac']}")
        print(f"   Manufacturer: {device_info['manufacturer']}")
        print(f"   Model: {device_info['model']}")
        print(f"   OS: {device_info.get('os', 'Unknown')}")
        print(f"   Services: {len(device_info['services'])} found")
        
        if dry_run:
            print("   🏃 DRY RUN - Not creating in NetBox")
            return
        
        try:
            # Step 1: Ensure site exists
            site = list(self.api.dcim.sites.filter(name=site_name))
            if not site:
                print(f"   ❌ Site '{site_name}' not found in NetBox")
                return
            site = site[0]
            
            # Step 2: Ensure manufacturer exists
            manufacturer_id = self.ensure_manufacturer(device_info['manufacturer'], dry_run)
            if not manufacturer_id:
                return
            
            # Step 3: Ensure device type exists
            device_type_id = self.ensure_device_type(
                manufacturer_id, device_info['model'], dry_run=dry_run
            )
            if not device_type_id:
                return
            
            # Step 4: Get or create device role
            device_role = list(self.api.dcim.device_roles.filter(name="Auto-Discovered"))
            if not device_role:
                device_role = self.api.dcim.device_roles.create(
                    name="Auto-Discovered",
                    slug="auto-discovered",
                    color="2196f3"
                )
                print(f"   ✅ Created device role: Auto-Discovered")
            else:
                device_role = device_role[0]
            
            # Step 5: Create device
            device_data = {
                'name': device_name,
                'device_type': device_type_id,
                'device_role': device_role.id,
                'site': site.id,
                'comments': (
                    f"Auto-discovered device\nOS: {device_info.get('os', 'Unknown')}\nServices: "
                    + ', '.join(
                        [f"{s['port']}/{s['service']}" for s in device_info['services']]
                    )
                ),
            }

            device = self.api.dcim.devices.create(**device_data)
            print(f"   ✅ Device created: {device_name} (ID: {device.id})")

            # Step 6: Ensure interface exists
            interfaces = list(self.api.dcim.interfaces.filter(device_id=device.id))
            if interfaces:
                interface = interfaces[0]
            else:
                interface = self.api.dcim.interfaces.create(
                    device=device.id,
                    name="eth0",
                    type="1000base-t",
                )
                print(f"   ✅ Created interface eth0 for {device_name}")

            # Step 7: Add IP address to interface
            ip_data = {
                'address': f"{device_info['ip']}/32",
                'assigned_object_type': 'dcim.interface',
                'assigned_object_id': interface.id,
                'description': f"Auto-discovered IP for {device_name}"
            }

            ip_addr = self.api.ipam.ip_addresses.create(**ip_data)
            print(f"   ✅ IP address created: {device_info['ip']} (ID: {ip_addr.id}) and assigned to interface {interface.name}")
            
        except Exception as e:
            print(f"   ❌ Error creating device: {e}")
    
    def process_scan_file(self, filename: str, site_name: str = "Default", dry_run: bool = False):
        """Process the entire scan file and create devices."""
        print(f"📄 Processing scan file: {filename}")
        
        devices = self.parse_scan_file(filename)
        print(f"🔍 Found {len(devices)} devices to process")
        
        for device in devices:
            self.create_device_in_netbox(device, site_name, dry_run)


def main():
    parser = argparse.ArgumentParser(description="Add discovered devices to NetBox")
    parser.add_argument("scan_file", help="Path to the nmap scan results file")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml file")
    parser.add_argument("--dry-run", action="store_true", 
                       help="Show what would be created without actually creating")
    
    args = parser.parse_args()
    
    # Load config from YAML file
    try:
        import yaml
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
        
        netbox_url = config['settings']['url']
        netbox_token = config['settings']['token']
        site_name = config['settings'].get('site', 'Default')  # Default fallback
        
        print(f"📄 Using config from {args.config}")
        print(f"🔗 NetBox URL: {netbox_url}")
        print(f"🏢 Site: {site_name}")
        
    except FileNotFoundError:
        print(f"❌ Config file not found: {args.config}")
        print("Please ensure config.yaml exists or specify --config path")
        return
    except KeyError as e:
        print(f"❌ Missing key in config file: {e}")
        print("Config should have settings.url, settings.token, and settings.site")
        return
    except Exception as e:
        print(f"❌ Error reading config: {e}")
        return
    
    adder = NetBoxDeviceAdder(netbox_url, netbox_token)
    adder.process_scan_file(args.scan_file, site_name, args.dry_run)


if __name__ == "__main__":
    main()