import logging
from typing import Dict, List, Any
from network_scanner import NetworkScanner

logger = logging.getLogger(__name__)


class DataProcessor:

    
    def __init__(self):
        
        self.network_scanner = NetworkScanner()
    
    def process_crawl_data(self, crawl_result: Dict, network_data: Dict = None) -> Dict[str, Any]:

        try:
            if not crawl_result.get('success'):
                return {'success': False, 'error': crawl_result.get('error')}
            
            data = crawl_result.get('data', {})
            engine = data.get('engine', 'unknown')
            
            logger.info(f"Processing data from {engine} engine")
            
            processed = {
                'source_engine': engine,
                'target_url': data.get('url', ''),
                'crawl_data': self._process_engine_data(data, engine),
                'network_data': network_data if network_data else {},
                'enriched_data': self._enrich_data(data, network_data),
                'vulnerability_scan_ready': self._prepare_for_vulnerability_scan(data, network_data)
            }
            
            return processed
            
        except Exception as e:
            logger.error(f"Data processing error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def integrate_network_scan(self, crawl_result: Dict, url: str) -> Dict[str, Any]:
 
        try:
            logger.info(f"Integrating network scan for: {url}")
            
            
            network_result = self.network_scanner.scan_target(url)
            
            
            processed = self.process_crawl_data(crawl_result, network_result)
            
            return processed
            
        except Exception as e:
            logger.error(f"Integration error: {str(e)}")
            return crawl_result
    
    def _process_engine_data(self, data: Dict, engine: str) -> Dict[str, Any]:

        if engine == 'scrapy':
            return self._process_scrapy_data(data)
        elif engine == 'beautifulsoup':
            return self._process_beautifulsoup_data(data)
        elif engine in ['selenium', 'playwright']:
            return self._process_browser_data(data)
        else:
            return data
    
    def _process_scrapy_data(self, data: Dict) -> Dict[str, Any]:
        
        return {
            'pages_crawled': len(data.get('pages_crawled', [])),
            'total_links': data.get('total_links_found', 0),
            'total_forms': data.get('total_forms_found', 0),
            'total_inputs': data.get('total_inputs_found', 0),
            'structured_data': data.get('structured_data', {}),
            'depth': data.get('depth', 1),
            'pages': data.get('pages_crawled', [])[:10]
        }
    
    def _process_beautifulsoup_data(self, data: Dict) -> Dict[str, Any]:
        
        links_info = data.get('links', {})
        return {
            'status_code': data.get('status_code', 0),
            'total_links': links_info.get('total', 0),
            'internal_links': links_info.get('internal', 0),
            'external_links': links_info.get('external', 0),
            'email_links': links_info.get('email', 0),
            'forms_count': len(data.get('forms', [])),
            'inputs_count': len(data.get('inputs', [])),
            'page_size_kb': data.get('page_size', 0) / 1024,
            'has_javascript': data.get('javascript_enabled', False)
        }
    
    def _process_browser_data(self, data: Dict) -> Dict[str, Any]:
        """Process Selenium/Playwright results"""
        return {
            'title': data.get('title', ''),
            'current_url': data.get('current_url', ''),
            'redirected': data.get('url') != data.get('current_url'),
            'forms_count': len(data.get('forms', [])),
            'inputs_count': len(data.get('inputs', [])),
            'links_count': len(data.get('links', [])),
            'cookies_count': len(data.get('cookies', {})),
            'page_size_kb': data.get('page_size', 0) / 1024,
            'javascript_enabled': data.get('javascript_enabled', False),
            'authenticated': data.get('authenticated', False)
        }
    
    def _enrich_data(self, crawl_data: Dict, network_data: Dict = None) -> Dict[str, Any]:
        """Enrich crawl data with additional context"""
        enrichment = {
            'form_count': len(crawl_data.get('forms', [])),
            'input_types': self._categorize_inputs(crawl_data.get('inputs', [])),
            'sensitive_fields': self._identify_sensitive_fields(crawl_data),
            'network_info': {}
        }
        
        if network_data:
            enrichment['network_info'] = {
                'ip_addresses': network_data.get('summary', {}).get('target_info', {}).get('ip_addresses', []),
                'reachable': network_data.get('summary', {}).get('target_info', {}).get('reachable', False),
                'open_ports': network_data.get('summary', {}).get('open_ports', []),
                'services': network_data.get('summary', {}).get('services', {})
            }
        
        return enrichment
    
    def _prepare_for_vulnerability_scan(self, crawl_data: Dict, network_data: Dict = None) -> Dict[str, Any]:
        """

        
        Returns:
            Formatted data for vulnerability scanners
        """
        vuln_data = {
            'target': {
                'url': crawl_data.get('url', ''),
                'title': crawl_data.get('title', ''),
                'forms': crawl_data.get('forms', []),
                'inputs': crawl_data.get('inputs', []),
                'links': crawl_data.get('links', []),
            },
            'network_context': {},
            'injectable_parameters': [],
            'authentication_required': crawl_data.get('authenticated', False)
        }
        
        
        if network_data:
            summary = network_data.get('summary', {})
            vuln_data['network_context'] = {
                'ip_addresses': summary.get('target_info', {}).get('ip_addresses', []),
                'open_ports': summary.get('open_ports', []),
                'services': summary.get('services', {}),
                'network_accessible': summary.get('network_accessible', False)
            }
        
        
        for inp in crawl_data.get('inputs', []):
            if inp.get('type') in ['text', 'email', 'number', 'search', 'url']:
                vuln_data['injectable_parameters'].append(inp.get('name', ''))
        
        return vuln_data
    
    def _categorize_inputs(self, inputs: List[Dict]) -> Dict[str, int]:
        
        categorized = {}
        for inp in inputs:
            inp_type = inp.get('type', 'unknown').lower()
            categorized[inp_type] = categorized.get(inp_type, 0) + 1
        return categorized
    
    def _identify_sensitive_fields(self, crawl_data: Dict) -> List[Dict]:
        
        sensitive_keywords = [
            'password', 'pin', 'secret', 'token', 'key', 'api',
            'credit', 'card', 'cvv', 'ssn', 'auth'
        ]
        
        sensitive = []
        for inp in crawl_data.get('inputs', []):
            name = inp.get('name', '').lower()
            inp_type = inp.get('type', '').lower()
            
            if any(kw in name or kw in inp_type for kw in sensitive_keywords):
                sensitive.append(inp)
        
        return sensitive
    
    def get_scanner_context(self, processed_data: Dict) -> Dict[str, Any]:

        return {
            'sql_injection_context': {
                'forms': processed_data.get('vulnerability_scan_ready', {}).get('target', {}).get('forms', []),
                'inputs': processed_data.get('vulnerability_scan_ready', {}).get('target', {}).get('inputs', []),
                'network': processed_data.get('vulnerability_scan_ready', {}).get('network_context', {})
            },
            'xss_context': {
                'forms': processed_data.get('vulnerability_scan_ready', {}).get('target', {}).get('forms', []),
                'inputs': processed_data.get('vulnerability_scan_ready', {}).get('target', {}).get('inputs', []),
            },
            'network_context': {
                'open_ports': processed_data.get('vulnerability_scan_ready', {}).get('network_context', {}).get('open_ports', []),
                'services': processed_data.get('vulnerability_scan_ready', {}).get('network_context', {}).get('services', {}),
                'ip_addresses': processed_data.get('vulnerability_scan_ready', {}).get('network_context', {}).get('ip_addresses', [])
            }
        }