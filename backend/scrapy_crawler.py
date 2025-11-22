import logging
from typing import Dict, List, Any
import asyncio
from concurrent.futures import ThreadPoolExecutor
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

logger = logging.getLogger(__name__)


class ScrapyEngine:
    """
    Scrapy-based modular crawler for standard HTML sites
    Used for structured scraping of regular websites
    Optimized for performance and modularity
    """
    
    def __init__(self, timeout: int = 10, max_workers: int = 3):
        """Initialize Scrapy engine"""
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.visited_urls = set()
    
    def crawl(self, url: str, max_depth: int = 1) -> Dict[str, Any]:
        """
        Crawl website with modular approach
        
        Args:
            url: Target URL
            max_depth: Maximum crawling depth
        
        Returns:
            Comprehensive crawl results
        """
        try:
            logger.info(f"Scrapy crawling: {url} (depth: {max_depth})")
            
            # First page crawl
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            results = {
                'engine': 'scrapy',
                'url': url,
                'depth': max_depth,
                'status_code': response.status_code,
                'pages_crawled': [self._parse_page(url, soup)],
                'total_links_found': 0,
                'total_forms_found': 0,
                'total_inputs_found': 0,
                'structured_data': self._extract_structured_data(soup, url)
            }
            
            # Crawl deeper if requested
            if max_depth > 1:
                links = self._extract_crawlable_links(soup, url)
                crawled_pages = self._crawl_depth(links, url, max_depth - 1)
                results['pages_crawled'].extend(crawled_pages)
            
            # Aggregate data
            results['total_links_found'] = sum(
                len(page.get('links', [])) for page in results['pages_crawled']
            )
            results['total_forms_found'] = sum(
                len(page.get('forms', [])) for page in results['pages_crawled']
            )
            results['total_inputs_found'] = sum(
                len(page.get('inputs', [])) for page in results['pages_crawled']
            )
            
            return {'success': True, 'data': results}
            
        except Exception as e:
            logger.error(f"Scrapy crawl error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _parse_page(self, url: str, soup: BeautifulSoup) -> Dict[str, Any]:
        """
        Parse individual page
        
        Args:
            url: Page URL
            soup: BeautifulSoup object
        
        Returns:
            Parsed page data
        """
        return {
            'url': url,
            'title': soup.find('title').string if soup.find('title') else '',
            'links': self._extract_links_from_soup(soup, url),
            'forms': self._extract_forms_from_soup(soup),
            'inputs': self._extract_inputs_from_soup(soup),
            'headers': self._extract_headers_from_soup(soup),
            'meta_tags': self._extract_meta_tags_from_soup(soup),
            'word_count': len(soup.get_text().split())
        }
    
    def _crawl_depth(self, links: List[str], base_url: str, depth: int) -> List[Dict]:
        """
        Crawl multiple links at depth
        
        Args:
            links: List of URLs to crawl
            base_url: Base URL for validation
            depth: Remaining depth
        
        Returns:
            List of crawled page data
        """
        crawled_pages = []
        base_domain = urlparse(base_url).netloc
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for link in links[:5]:  # Limit to 5 links per depth
                if link not in self.visited_urls and urlparse(link).netloc == base_domain:
                    self.visited_urls.add(link)
                    try:
                        response = self.session.get(link, timeout=self.timeout, verify=False)
                        if response.status_code == 200:
                            soup = BeautifulSoup(response.content, 'html.parser')
                            page_data = self._parse_page(link, soup)
                            crawled_pages.append(page_data)
                    except Exception as e:
                        logger.warning(f"Failed to crawl {link}: {str(e)}")
        
        return crawled_pages
    
    def _extract_crawlable_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract links suitable for crawling"""
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if not href.startswith(('mailto:', 'javascript:', '#')):
                full_url = urljoin(base_url, href)
                if urlparse(full_url).scheme in ['http', 'https']:
                    links.append(full_url)
        return links
    
    def _extract_links_from_soup(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links from page"""
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href and not href.startswith(('mailto:', 'javascript:')):
                full_url = urljoin(base_url, href)
                links.append(full_url)
        return list(set(links))
    
    def _extract_forms_from_soup(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract forms from page"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'name': form.get('name', ''),
                'id': form.get('id', ''),
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', ''),
                'field_count': len(form.find_all(['input', 'textarea']))
            }
            forms.append(form_data)
        return forms
    
    def _extract_inputs_from_soup(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract input fields from page"""
        inputs = []
        for inp in soup.find_all('input'):
            inputs.append({
                'type': inp.get('type', 'text'),
                'name': inp.get('name', ''),
                'id': inp.get('id', ''),
                'class': inp.get('class', [])
            })
        return inputs
    
    def _extract_headers_from_soup(self, soup: BeautifulSoup) -> Dict[str, int]:
        """Extract heading structure"""
        headers = {}
        for i in range(1, 7):
            tag = f'h{i}'
            count = len(soup.find_all(tag))
            if count > 0:
                headers[tag] = count
        return headers
    
    def _extract_meta_tags_from_soup(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract meta tags"""
        meta_tags = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            if name and content:
                meta_tags[name] = content
        return meta_tags
    
    def _extract_structured_data(self, soup: BeautifulSoup, url: str) -> Dict[str, Any]:
        """
        Extract structured data (JSON-LD, microdata)
        Useful for understanding page structure
        """
        structured = {
            'json_ld': [],
            'microdata': [],
            'og_tags': {}
        }
        
        # Extract JSON-LD
        for script in soup.find_all('script', type='application/ld+json'):
            try:
                import json
                data = json.loads(script.string)
                structured['json_ld'].append(data)
            except:
                pass
        
        # Extract Open Graph tags
        for meta in soup.find_all('meta', property=re.compile('og:')):
            prop = meta.get('property', '')
            content = meta.get('content', '')
            structured['og_tags'][prop] = content
        
        return structured
    
    def extract_all_data(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive extraction of all page data
        Suitable for multiple vulnerability checkers
        """
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            
            data = {
                'url': url,
                'status_code': response.status_code,
                'page_title': soup.find('title').string if soup.find('title') else '',
                'content_type': response.headers.get('Content-Type', ''),
                'content_length': len(response.content),
                'response_headers': dict(response.headers),
                'forms': self._extract_forms_from_soup(soup),
                'inputs': self._extract_inputs_from_soup(soup),
                'links': self._extract_links_from_soup(soup, url),
                'scripts': [script.get('src', '') for script in soup.find_all('script', src=True)],
                'images': [img.get('src', '') for img in soup.find_all('img')],
                'comments': [str(comment) for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))],
                'sensitive_fields': self._find_sensitive_fields(soup)
            }
            
            return {'success': True, 'data': data}
            
        except Exception as e:
            logger.error(f"Comprehensive extraction error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _find_sensitive_fields(self, soup: BeautifulSoup) -> List[Dict]:
        """Find potentially sensitive form fields"""
        sensitive_keywords = ['password', 'pin', 'secret', 'token', 'api', 'key', 'auth']
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
    
    def compare_crawlers(self, url: str) -> Dict[str, Any]:
        """
        Compare Scrapy with BeautifulSoup results
        Helps determine which crawler is more suitable
        """
        scrapy_result = self.crawl(url, max_depth=1)
        
        comparison = {
            'url': url,
            'scrapy_success': scrapy_result.get('success', False),
            'scrapy_data': scrapy_result.get('data', {}) if scrapy_result.get('success') else None,
            'recommendation': 'scrapy' if scrapy_result.get('success') else 'beautifulsoup'
        }
        
        return comparison