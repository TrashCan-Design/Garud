import logging
import asyncio
import re
from typing import Dict, Any, Set
from urllib.parse import urlparse, urldefrag, urljoin
from playwright_crawler import PlaywrightCrawler
from beautifulsoup_crawler import BeautifulSoupCrawler

logger = logging.getLogger(__name__)

# File extensions to skip
_NON_HTML_EXT = re.compile(
    r'\.(docx?|xlsx?|pptx?|pdf|zip|rar|7z|tar|gz|bz2|csv|tsv|'
    r'png|jpe?g|gif|svg|ico|webp|bmp|tiff?|'
    r'mp[34]|avi|mov|wmv|flv|mkv|webm|'
    r'woff2?|ttf|eot|otf|'
    r'exe|dll|bin|iso|dmg|msi|deb|rpm)$',
    re.I,
)

class HybridCrawlerManager:

    
    def __init__(self, max_depth: int = 2):
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.graph_nodes = []
        self.graph_links = []
        self.all_forms = []
        self.all_internal_links: Set[str] = set()  # All raw links including query strings
        self.all_js_files: Set[str] = set()        # External JS files for DOM XSS
        self.base_domain = ""
        self.base_hostname = ""   # Hostname without port
        
        self.pw_crawler = PlaywrightCrawler()
        self.bs_crawler = BeautifulSoupCrawler()

    def normalize_url(self, url: str) -> str:
        """Strips fragments and normalizes trailing slashes to prevent duplicate loops."""
        url, _ = urldefrag(url)
        if url.endswith('/') and len(url) > 8:
            url = url[:-1]
        return url

    def is_valid_internal(self, url: str) -> bool:
        """Checks if URL belongs to the target domain (any port)."""
        try:
            return urlparse(url).hostname == self.base_hostname
        except:
            return False

    async def async_crawl_recursive(self, url: str, depth: int, parent_url: str = None):
        """Recursive async crawler with loop prevention."""
        normalized_url = self.normalize_url(url)
        
        if depth > self.max_depth or normalized_url in self.visited_urls:
            return
            
        if not self.is_valid_internal(normalized_url):
            return

        self.visited_urls.add(normalized_url)
        
        # Map URL in link graph
        if not any(n['id'] == normalized_url for n in self.graph_nodes):
            self.graph_nodes.append({'id': normalized_url, 'group': depth})
            
        if parent_url:
            self.graph_links.append({'source': parent_url, 'target': normalized_url})

        # Skip parsing non-HTML files
        if _NON_HTML_EXT.search(urlparse(normalized_url).path):
            logger.info(f"Mapped non-HTML file (skipping parse): {normalized_url}")
            return

        # Try BS4 first, fallback to Playwright if needed
        bs4_res = self.bs_crawler.crawl(normalized_url)
        
        extracted_data = None
        needs_playwright = False
        
        if bs4_res.get('success'):
            data = bs4_res['data']
            # Heuristic for Single Page Apps
            if len(data.get('links', {}).get('internal_links', [])) < 2 and data.get('page_size', 0) > 1000:
                needs_playwright = True
            else:
                extracted_data = data
                links_to_visit = data.get('links', {}).get('internal_links', [])
                # Collect raw links
                for raw_link in links_to_visit:
                    self.all_internal_links.add(raw_link)
                # Collect JS files for DOM XSS
                for js_url in data.get('js_files', []):
                    self.all_js_files.add(js_url)
                # Resolve relative form actions
                for form in data.get('forms', []):
                    action = form.get('action', '')
                    form['action'] = urljoin(normalized_url, action) if action else normalized_url
                self.all_forms.extend(data.get('forms', []))
        else:
            needs_playwright = True

        if needs_playwright:
            pw_res = await self.pw_crawler.crawl(normalized_url)
            if pw_res.get('success'):
                extracted_data = pw_res['data']
                links_to_visit = extracted_data.get('links', [])
                # Collect raw links
                for raw_link in links_to_visit:
                    if isinstance(raw_link, str):
                        self.all_internal_links.add(raw_link)
                # Collect JS files for DOM XSS
                for js_url in extracted_data.get('js_files', []):
                    self.all_js_files.add(js_url)
                # Resolve relative form actions
                for form in extracted_data.get('forms', []):
                    action = form.get('action', '')
                    form['action'] = urljoin(normalized_url, action) if action else normalized_url
                self.all_forms.extend(extracted_data.get('forms', []))
            else:
                links_to_visit = []

        if not extracted_data:
            return

        # Recurse child links
        tasks = []
        for link in links_to_visit:
            tasks.append(self.async_crawl_recursive(link, depth + 1, normalized_url))
            
        if tasks:
            await asyncio.gather(*tasks)

    def run_hybrid_crawl(self, start_url: str) -> Dict[str, Any]:
        """Entry point for the backend orchestrator."""
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc
        self.base_hostname = parsed.hostname   # Hostname without port
        self.visited_urls.clear()
        self.graph_nodes.clear()
        self.graph_links.clear()
        self.all_forms.clear()
        self.all_internal_links.clear()
        self.all_js_files.clear()
        
        # Run crawl loop
        asyncio.run(self.async_crawl_recursive(start_url, 0))

        # Log crawl summary
        qs_links = [l for l in self.all_internal_links if '?' in l]
        logger.info(f"Crawl complete: {len(self.visited_urls)} pages, "
                    f"{len(self.all_forms)} forms, "
                    f"{len(self.all_internal_links)} raw links "
                    f"({len(qs_links)} with query strings)")
        for ql in qs_links:
            logger.info(f"  QS link: {ql}")
        
        return {
            'success': True,
            'total_pages_crawled': len(self.visited_urls),
            'forms': self.all_forms,
            'all_internal_links': list(self.all_internal_links),
            'js_files': list(self.all_js_files),
            'graph': {
                'nodes': self.graph_nodes,
                'links': self.graph_links
            }
        }