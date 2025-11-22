import logging
from typing import Dict, List, Any
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

logger = logging.getLogger(__name__)


class BeautifulSoupCrawler:
    """
    BeautifulSoup-based crawler for static HTML sites
    Lightweight alternative to Selenium for non-JavaScript heavy sites
    """
    
    def __init__(self, timeout: int = 10):
        """Initialize BeautifulSoup crawler"""
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def crawl(self, url: str) -> Dict[str, Any]:
        """
        Crawl static HTML site
        
        Args:
            url: Target URL
        
        Returns:
            Crawl results
        """
        try:
            logger.info(f"BeautifulSoup crawling: {url}")
            
            # Fetch page
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.raise_for_status()
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'lxml')
            
            # Extract data
            data = {
                'engine': 'beautifulsoup',
                'url': url,
                'status_code': response.status_code,
                'title': self._extract_title(soup),
                'links': self._extract_links(soup, url),
                'forms': self._extract_forms(soup),
                'inputs': self._extract_inputs(soup),
                'headers': dict(response.headers),
                'page_size': len(response.content),
                'javascript_enabled': False,
                'meta_tags': self._extract_meta_tags(soup),
                'text_content': self._extract_text(soup)
            }
            
            return {'success': True, 'data': data}
            
        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': 'Connection failed'}
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Request timeout'}
        except requests.exceptions.HTTPError as e:
            return {'success': False, 'error': f'HTTP {e.response.status_code}'}
        except Exception as e:
            logger.error(f"BeautifulSoup crawl error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def crawl_with_login(self, url: str, login_url: str,
                        username_field: str, password_field: str,
                        username: str, password: str) -> Dict[str, Any]:
        """
        Crawl with form-based login
        
        Args:
            url: Target URL after login
            login_url: Login page URL
            username_field: Name attribute of username field
            password_field: Name attribute of password field
            username: Login credentials
            password: Login credentials
        
        Returns:
            Crawl results after authentication
        """
        try:
            logger.info(f"BeautifulSoup login crawl: {login_url}")
            
            # Prepare login data
            login_data = {
                username_field: username,
                password_field: password
            }
            
            # Post login
            response = self.session.post(
                login_url,
                data=login_data,
                timeout=self.timeout,
                verify=False
            )
            
            # Follow redirects if needed
            if response.status_code in [301, 302, 303]:
                redirect_url = response.headers.get('Location')
                if redirect_url:
                    response = self.session.get(redirect_url, timeout=self.timeout, verify=False)
            
            # Fetch target page
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'lxml')
            
            data = {
                'engine': 'beautifulsoup',
                'authenticated': True,
                'login_url': login_url,
                'target_url': url,
                'status_code': response.status_code,
                'title': self._extract_title(soup),
                'forms': self._extract_forms(soup),
                'page_size': len(response.content)
            }
            
            return {'success': True, 'data': data}
            
        except Exception as e:
            logger.error(f"BeautifulSoup login error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract page title"""
        try:
            title_tag = soup.find('title')
            return title_tag.string if title_tag else 'No title'
        except:
            return ''
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Dict[str, Any]:
        """
        Extract and categorize links
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving relative links
        
        Returns:
            Categorized links
        """
        try:
            internal_links = []
            external_links = []
            email_links = []
            
            base_domain = urlparse(base_url).netloc
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                if href.startswith('mailto:'):
                    email_links.append(href)
                elif href.startswith('javascript:'):
                    continue
                elif href.startswith('http'):
                    if base_domain in href:
                        internal_links.append(href)
                    else:
                        external_links.append(href)
                else:
                    # Resolve relative URL
                    resolved = urljoin(base_url, href)
                    internal_links.append(resolved)
            
            return {
                'total': len(internal_links) + len(external_links),
                'internal': len(set(internal_links)),
                'external': len(set(external_links)),
                'email': len(email_links),
                'internal_links': list(set(internal_links))[:50],
                'external_links': list(set(external_links))[:50],
                'email_links': email_links
            }
        except Exception as e:
            logger.error(f"Link extraction error: {str(e)}")
            return {'total': 0, 'internal': 0, 'external': 0}
    
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract all forms"""
        try:
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'name': form.get('name', ''),
                    'id': form.get('id', ''),
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'fields': []
                }
                
                # Extract input fields
                for inp in form.find_all('input'):
                    form_data['fields'].append({
                        'type': inp.get('type', 'text'),
                        'name': inp.get('name', ''),
                        'id': inp.get('id', ''),
                        'value': inp.get('value', ''),
                        'required': 'required' in inp.attrs
                    })
                
                # Extract textarea fields
                for ta in form.find_all('textarea'):
                    form_data['fields'].append({
                        'type': 'textarea',
                        'name': ta.get('name', ''),
                        'id': ta.get('id', ''),
                        'required': 'required' in ta.attrs
                    })
                
                forms.append(form_data)
            
            return forms
        except Exception as e:
            logger.error(f"Form extraction error: {str(e)}")
            return []
    
    def _extract_inputs(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract all input fields"""
        try:
            inputs = []
            for inp in soup.find_all('input'):
                inputs.append({
                    'type': inp.get('type', 'text'),
                    'name': inp.get('name', ''),
                    'id': inp.get('id', ''),
                    'value': inp.get('value', '')
                })
            return inputs
        except:
            return []
    
    def _extract_meta_tags(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract meta tags"""
        try:
            meta_tags = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property')
                content = meta.get('content')
                if name and content:
                    meta_tags[name] = content
            return meta_tags
        except:
            return {}
    
    def _extract_text(self, soup: BeautifulSoup) -> str:
        """Extract readable text content"""
        try:
            # Remove script and style elements
            for script in soup(['script', 'style']):
                script.decompose()
            
            text = soup.get_text()
            # Clean up whitespace
            text = ' '.join(text.split())
            return text[:1000]  # First 1000 characters
        except:
            return ''
    
    def check_response_headers(self, url: str) -> Dict[str, Any]:
        """Check security-related response headers"""
        try:
            response = self.session.head(url, timeout=self.timeout, verify=False)
            
            headers_to_check = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'Server'
            ]
            
            found_headers = {}
            missing_headers = []
            
            for header in headers_to_check:
                if header in response.headers:
                    found_headers[header] = response.headers[header]
                else:
                    missing_headers.append(header)
            
            return {
                'success': True,
                'headers_found': found_headers,
                'headers_missing': missing_headers,
                'status_code': response.status_code
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def extract_sensitive_fields(self, url: str) -> List[Dict]:
        """Identify sensitive input fields on page"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.content, 'lxml')
            
            sensitive_keywords = [
                'password', 'pin', 'secret', 'token', 'key',
                'credit', 'card', 'cvv', 'ssn', 'api', 'auth'
            ]
            
            sensitive_fields = []
            for inp in soup.find_all('input'):
                name = inp.get('name', '').lower()
                inp_type = inp.get('type', '').lower()
                
                if any(kw in name or kw in inp_type for kw in sensitive_keywords):
                    sensitive_fields.append({
                        'type': inp.get('type', ''),
                        'name': inp.get('name', ''),
                        'id': inp.get('id', '')
                    })
            
            return sensitive_fields
        except Exception as e:
            logger.error(f"Sensitive field extraction error: {str(e)}")
            return []