import subprocess
import socket
import logging
from typing import Dict, List, Any
from urllib.parse import urlparse
import json
import platform
import re

logger = logging.getLogger(__name__)


class NetworkScanner:
    """
    Network reconnaissance module using nmap, nslookup, ping, traceroute
    Gathers network info to be shared with other vulnerability modules
    """
    
    def __init__(self):
        """Initialize network scanner"""
        self.os_type = platform.system()
    
    def scan_target(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive network scan
        
        Args:
            url: Target URL or hostname
        
        Returns:
            Dictionary with all network information
        """
        try:
            hostname = self._extract_hostname(url)
            logger.info(f"Starting network scan for: {hostname}")
            
            scan_results = {
                'hostname': hostname,
                'ping_results': self._ping_host(hostname),
                'dns_results': self._nslookup(hostname),
                'traceroute_results': self._traceroute(hostname),
                'nmap_results': self._nmap_scan(hostname),
                'socket_info': self._get_socket_info(hostname),
                'summary': {}
            }
            
            # Generate summary
            scan_results['summary'] = self._generate_summary(scan_results)
            
            logger.info(f"Network scan completed for: {hostname}")
            return scan_results
            
        except Exception as e:
            logger.error(f"Network scan error: {str(e)}")
            return {'error': str(e), 'success': False}
    
    def _extract_hostname(self, url: str) -> str:
        """
        Extract hostname from URL
        
        Args:
            url: Full URL or hostname
        
        Returns:
            Hostname or IP address
        """
        if url.startswith(('http://', 'https://')):
            parsed = urlparse(url)
            return parsed.netloc.split(':')[0]
        return url.split(':')[0]
    
    def _ping_host(self, hostname: str) -> Dict[str, Any]:
        """
        Execute ping command
        
        Args:
            hostname: Target hostname or IP
        
        Returns:
            Ping results
        """
        try:
            logger.info(f"Pinging: {hostname}")
            
            # Platform-specific ping command
            if self.os_type == 'Windows':
                cmd = ['ping', '-n', '4', hostname]
            else:
                cmd = ['ping', '-c', '4', hostname]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse response time from output
                if self.os_type == 'Windows':
                    times = re.findall(r'time[<=]+(\d+)ms', output)
                else:
                    times = re.findall(r'time=(\d+\.?\d*)\s*ms', output)
                
                return {
                    'success': True,
                    'host_reachable': True,
                    'response_times': times[:4] if times else [],
                    'output': output[:500]
                }
            else:
                return {
                    'success': False,
                    'host_reachable': False,
                    'error': 'Host unreachable',
                    'output': result.stderr[:500]
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Ping timeout'
            }
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'Ping command not found'
            }
        except Exception as e:
            logger.error(f"Ping error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _nslookup(self, hostname: str) -> Dict[str, Any]:
        """
        Execute nslookup/dig command for DNS resolution
        
        Args:
            hostname: Target hostname
        
        Returns:
            DNS resolution results
        """
        try:
            logger.info(f"Performing DNS lookup: {hostname}")
            
            results = {
                'hostname': hostname,
                'ipv4_addresses': [],
                'ipv6_addresses': [],
                'cname': None,
                'mx_records': []
            }
            
            # Try socket resolution first (fast, works on all OS)
            try:
                ipv4 = socket.gethostbyname(hostname)
                results['ipv4_addresses'].append(ipv4)
            except socket.gaierror:
                pass
            
            # Try IPv6 resolution
            try:
                ipv6_info = socket.getaddrinfo(hostname, None, socket.AF_INET6)
                for info in ipv6_info:
                    ipv6 = info[4][0]
                    if ipv6 not in results['ipv6_addresses']:
                        results['ipv6_addresses'].append(ipv6)
            except socket.gaierror:
                pass
            
            # Try nslookup command (if available)
            try:
                if self.os_type == 'Windows':
                    cmd = ['nslookup', hostname]
                else:
                    cmd = ['dig', hostname, '+short']
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    results['command_output'] = result.stdout[:500]
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
            
            results['success'] = len(results['ipv4_addresses']) > 0 or len(results['ipv6_addresses']) > 0
            return results
            
        except Exception as e:
            logger.error(f"NSLookup error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _traceroute(self, hostname: str) -> Dict[str, Any]:
        """
        Execute traceroute command
        
        Args:
            hostname: Target hostname or IP
        
        Returns:
            Traceroute results
        """
        try:
            logger.info(f"Tracing route to: {hostname}")
            
            if self.os_type == 'Windows':
                cmd = ['tracert', hostname]
            else:
                cmd = ['traceroute', hostname]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                hops = []
                for line in result.stdout.split('\n'):
                    if re.search(r'\d+\s+', line) and 'traceroute' not in line.lower():
                        hops.append(line.strip())
                
                return {
                    'success': True,
                    'hops': hops[:15],  # First 15 hops
                    'total_hops': len(hops),
                    'output': result.stdout[:500]
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr[:200]
                }
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Traceroute timeout'}
        except FileNotFoundError:
            return {'success': False, 'error': 'Traceroute command not found'}
        except Exception as e:
            logger.error(f"Traceroute error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _nmap_scan(self, hostname: str) -> Dict[str, Any]:
        """
        Execute nmap scan (basic port scanning)
        
        Args:
            hostname: Target hostname or IP
        
        Returns:
            Nmap scan results
        """
        try:
            logger.info(f"Performing nmap scan: {hostname}")
            
            # Check if nmap is installed
            result = subprocess.run(
                ['nmap', '-V'],
                capture_output=True,
                timeout=2
            )
            
            if result.returncode != 0:
                return {
                    'success': False,
                    'error': 'nmap not installed',
                    'install_instructions': 'Install via: apt-get install nmap (Linux) or brew install nmap (Mac)'
                }
            
            # Perform basic nmap scan
            cmd = ['nmap', '-p', '80,443,22,21,25,53,3306,5432', '-T3', hostname]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                open_ports = []
                for line in result.stdout.split('\n'):
                    if 'open' in line.lower():
                        open_ports.append(line.strip())
                
                return {
                    'success': True,
                    'open_ports': open_ports,
                    'scan_data': result.stdout[:1000]
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr[:200]
                }
                
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'nmap not installed',
                'note': 'Optional tool - system will continue without it'
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'nmap timeout (timeout after 30s)'}
        except Exception as e:
            logger.warning(f"Nmap scan skipped: {str(e)}")
            return {'success': False, 'error': str(e), 'note': 'nmap is optional'}
    
    def _get_socket_info(self, hostname: str) -> Dict[str, Any]:
        """
        Get socket-level information
        
        Args:
            hostname: Target hostname or IP
        
        Returns:
            Socket information
        """
        try:
            socket_info = {
                'hostname_canonical': None,
                'aliases': [],
                'all_addresses': []
            }
            
            try:
                h_name, h_aliases, h_addresses = socket.gethostbyname_ex(hostname)
                socket_info['hostname_canonical'] = h_name
                socket_info['aliases'] = h_aliases
                socket_info['all_addresses'] = h_addresses
            except socket.gaierror:
                pass
            
            socket_info['success'] = len(socket_info['all_addresses']) > 0
            return socket_info
            
        except Exception as e:
            logger.error(f"Socket info error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _generate_summary(self, scan_results: Dict) -> Dict[str, Any]:
        """
        Generate summary of scan results for other modules
        
        Args:
            scan_results: Complete scan results
        
        Returns:
            Summarized data for vulnerability scanners
        """
        summary = {
            'target_info': {
                'hostname': scan_results.get('hostname', ''),
                'reachable': scan_results.get('ping_results', {}).get('host_reachable', False),
                'ip_addresses': (
                    scan_results.get('dns_results', {}).get('ipv4_addresses', []) +
                    scan_results.get('dns_results', {}).get('ipv6_addresses', [])
                )
            },
            'open_ports': self._extract_open_ports(scan_results),
            'services': self._map_services(scan_results),
            'hop_count': scan_results.get('traceroute_results', {}).get('total_hops', 0),
            'network_accessible': bool(
                scan_results.get('ping_results', {}).get('host_reachable') and
                scan_results.get('dns_results', {}).get('ipv4_addresses')
            )
        }
        return summary
    
    def _extract_open_ports(self, scan_results: Dict) -> List[int]:
        """Extract open ports from nmap results"""
        ports = []
        nmap_results = scan_results.get('nmap_results', {})
        
        if nmap_results.get('success') and nmap_results.get('open_ports'):
            for line in nmap_results.get('open_ports', []):
                match = re.search(r'(\d+)/', line)
                if match:
                    ports.append(int(match.group(1)))
        
        return sorted(list(set(ports)))
    
    def _map_services(self, scan_results: Dict) -> Dict[int, str]:
        """Map common ports to services"""
        port_services = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            53: 'DNS',
            3306: 'MySQL',
            5432: 'PostgreSQL'
        }
        
        open_ports = self._extract_open_ports(scan_results)
        return {port: port_services.get(port, 'Unknown') for port in open_ports}
    
    def get_module_data(self, scan_results: Dict) -> Dict[str, Any]:
        """
        Extract data in format suitable for other vulnerability modules
        
        Args:
            scan_results: Complete scan results
        
        Returns:
            Formatted data for vulnerability scanners
        """
        return {
            'targets': scan_results.get('summary', {}).get('target_info', {}),
            'open_ports': scan_results.get('summary', {}).get('open_ports', []),
            'services': scan_results.get('summary', {}).get('services', {}),
            'network_accessible': scan_results.get('summary', {}).get('network_accessible', False),
            'ip_addresses': scan_results.get('summary', {}).get('target_info', {}).get('ip_addresses', [])
        }