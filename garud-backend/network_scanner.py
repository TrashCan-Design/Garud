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

    
    def __init__(self):
        self.os_type = platform.system()
    
    def scan_target(self, url: str) -> Dict[str, Any]:

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
            
            
            scan_results['summary'] = self._generate_summary(scan_results)
            
            logger.info(f"Network scan completed for: {hostname}")
            return scan_results
            
        except Exception as e:
            logger.error(f"Network scan error: {str(e)}")
            return {'error': str(e), 'success': False}
    
    def _extract_hostname(self, url: str) -> str:

        if url.startswith(('http://', 'https://')):
            parsed = urlparse(url)
            return parsed.netloc.split(':')[0]
        return url.split(':')[0]
    
    def _ping_host(self, hostname: str) -> Dict[str, Any]:

        try:
            logger.info(f"Pinging: {hostname}")
            
           
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

        try:
            logger.info(f"Performing DNS lookup: {hostname}")
            
            results = {
                'hostname': hostname,
                'ipv4_addresses': [],
                'ipv6_addresses': [],
                'cname': None,
                'mx_records': []
            }
            
            
            try:
                ipv4 = socket.gethostbyname(hostname)
                results['ipv4_addresses'].append(ipv4)
            except socket.gaierror:
                pass
            
            
            try:
                ipv6_info = socket.getaddrinfo(hostname, None, socket.AF_INET6)
                for info in ipv6_info:
                    ipv6 = info[4][0]
                    if ipv6 not in results['ipv6_addresses']:
                        results['ipv6_addresses'].append(ipv6)
            except socket.gaierror:
                pass
            
            
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
                    'hops': hops[:15],  
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

        try:
            logger.info(f"Performing nmap scan: {hostname}")
            
            result = subprocess.run(
                ['nmap', '-V'],
                capture_output=True,
                timeout=2
            )
            
            if result.returncode != 0:
                logger.warning("nmap found but returned non-zero — falling back to socket scan")
                return self._socket_port_scan(hostname)
            
            # Fast full port scan
            cmd = [
                'nmap',
                '-p-',                  # All ports
                '-T5',                  # Speed template 5
                '--min-rate', '5000',   # Minimum packet rate
                '--max-retries', '1',   # Retries
                '--open',               # Open only
                hostname
            ]
            logger.info(f"Running: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120              # 2 minute timeout
            )
            
            if result.returncode == 0:
                open_ports = []
                for line in result.stdout.split('\n'):
                    if 'open' in line.lower() and '/tcp' in line.lower():
                        open_ports.append(line.strip())
                
                logger.info(f"nmap found {len(open_ports)} open ports on {hostname}")
                return {
                    'success': True,
                    'open_ports': open_ports,
                    'scan_data': result.stdout[:2000],
                    'method': 'nmap'
                }
            else:
                logger.warning(f"nmap failed — falling back to socket scan")
                return self._socket_port_scan(hostname)
                
        except FileNotFoundError:
            logger.info("nmap not installed — using socket-based port scan")
            return self._socket_port_scan(hostname)
        except subprocess.TimeoutExpired:
            logger.warning("nmap timed out — falling back to socket scan")
            return self._socket_port_scan(hostname)
        except Exception as e:
            logger.warning(f"Nmap scan failed ({e}) — falling back to socket scan")
            return self._socket_port_scan(hostname)

    def _socket_port_scan(self, hostname: str) -> Dict[str, Any]:
        """
        Fast parallel TCP connect scan — fallback when nmap is unavailable.
        Scans ~200 high-value ports using thread pool for speed.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        # Target ports
        ports_to_scan = sorted(set(
            [20, 21, 22, 23, 25, 53, 69, 80, 81, 110, 111, 119, 135, 139, 143,
             161, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995, 1080,
             1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2096,
             3306, 5432, 5433, 6379, 6380, 9042, 9200, 9300, 27017, 27018, 28017,
             3000, 3001, 3443, 4200, 4280, 4443, 4848, 5000, 5001, 5013, 5044,
             5601, 7001, 7002, 7443, 8000, 8001, 8008, 8080, 8081, 8082, 8083,
             8088, 8443, 8444, 8880, 8888, 8889, 9000, 9001, 9043, 9060, 9080,
             9090, 9091, 9443, 10000, 10443,
             25, 465, 587, 993, 995, 1883, 5222, 5672, 15672, 61613, 61616,
             500, 1194, 1701, 1723, 3389, 5900, 5901, 5938, 8291,
             8834, 9100, 9999, 11211, 50000, 50070, 50075]
        ))

        service_map = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'domain', 69: 'tftp', 80: 'http', 81: 'http', 110: 'pop3',
            111: 'rpcbind', 119: 'nntp', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 161: 'snmp', 389: 'ldap', 443: 'https', 445: 'smb',
            465: 'smtps', 500: 'isakmp', 514: 'syslog', 587: 'submission',
            631: 'ipp', 636: 'ldaps', 993: 'imaps', 995: 'pop3s',
            1080: 'socks', 1194: 'openvpn', 1433: 'ms-sql', 1434: 'ms-sql-m',
            1521: 'oracle', 1701: 'l2tp', 1723: 'pptp', 1883: 'mqtt',
            2049: 'nfs', 3000: 'http-node', 3306: 'mysql', 3389: 'rdp',
            4280: 'http-app', 4848: 'glassfish', 5000: 'http-flask',
            5013: 'http-app', 5222: 'xmpp', 5432: 'postgresql',
            5672: 'amqp', 5900: 'vnc', 6379: 'redis', 7001: 'weblogic',
            8000: 'http-alt', 8001: 'http-alt', 8080: 'http-proxy',
            8081: 'http-alt', 8088: 'http-alt', 8443: 'https-alt',
            8834: 'nessus', 8888: 'http-alt', 9000: 'http-alt',
            9042: 'cassandra', 9090: 'http-alt', 9200: 'elasticsearch',
            9443: 'https-alt', 10000: 'webmin', 11211: 'memcached',
            15672: 'rabbitmq-mgmt', 27017: 'mongodb', 50000: 'sap',
        }

        open_ports = []
        logger.info(f"Socket port scan on {hostname} ({len(ports_to_scan)} ports, threaded)")

        def _check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((hostname, port))
                sock.close()
                return port if result == 0 else None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=100) as pool:
            futures = {pool.submit(_check_port, p): p for p in ports_to_scan}
            for future in as_completed(futures):
                port = future.result()
                if port is not None:
                    service = service_map.get(port, 'unknown')
                    open_ports.append(f"{port}/tcp   open  {service}")
                    logger.info(f"  Port {port}/{service} — OPEN")

        # Sort ports
        open_ports.sort(key=lambda x: int(x.split('/')[0]))

        scan_summary = f"Socket scan on {hostname}: {len(open_ports)} open ports found (scanned {len(ports_to_scan)} ports)"
        logger.info(scan_summary)

        return {
            'success': True,
            'open_ports': open_ports,
            'scan_data': scan_summary,
            'method': 'socket'
        }
    
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
        """Map open ports to service names using scan output + fallback dict"""
        port_services = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 81: 'HTTP', 110: 'POP3', 135: 'MSRPC',
            139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            465: 'SMTPS', 587: 'Submission', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MS-SQL', 1521: 'Oracle', 3000: 'Node.js', 3306: 'MySQL',
            3389: 'RDP', 4280: 'Web-App', 5013: 'Web-App', 5432: 'PostgreSQL',
            5672: 'AMQP', 5900: 'VNC', 6379: 'Redis', 7001: 'WebLogic',
            8000: 'HTTP-Alt', 8001: 'HTTP-Alt', 8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9000: 'HTTP-Alt',
            9042: 'Cassandra', 9090: 'HTTP-Alt', 9200: 'Elasticsearch',
            10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB',
        }

        # Extract service names from output
        nmap_results = scan_results.get('nmap_results', {})
        services = {}
        for line in nmap_results.get('open_ports', []):
            match = re.search(r'(\d+)/', line)
            if match:
                port = int(match.group(1))
                # Parse service name
                parts = line.split()
                svc = parts[-1].upper() if len(parts) >= 3 else port_services.get(port, 'Unknown')
                services[port] = svc

        # Fallback for missing services
        for port in self._extract_open_ports(scan_results):
            if port not in services:
                services[port] = port_services.get(port, 'Unknown')

        return services
    
    def get_module_data(self, scan_results: Dict) -> Dict[str, Any]:

        return {
            'targets': scan_results.get('summary', {}).get('target_info', {}),
            'open_ports': scan_results.get('summary', {}).get('open_ports', []),
            'services': scan_results.get('summary', {}).get('services', {}),
            'network_accessible': scan_results.get('summary', {}).get('network_accessible', False),
            'ip_addresses': scan_results.get('summary', {}).get('target_info', {}).get('ip_addresses', [])
        }