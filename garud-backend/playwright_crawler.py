import logging
import asyncio
import re
from typing import Dict, List, Any
from urllib.parse import urlparse, urljoin
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup

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

class PlaywrightCrawler:
    # Playwright crawler for dynamic, JavaScript-heavy sites.
    
    def __init__(self, timeout: int = 15000):
        self.timeout = timeout
        
    async def extract_page_data(self, page, url: str) -> Dict[str, Any]:
        """Extracts links, forms, and inputs from the fully rendered DOM."""
        content = await page.content()
        soup = BeautifulSoup(content, 'html.parser')
        
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if not href.startswith(('mailto:', 'javascript:', '#')):
                links.append(urljoin(url, href))
                
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'fields': [{'name': inp.get('name', ''), 'type': inp.get('type', 'text')} for inp in form.find_all('input')]
            }
            forms.append(form_data)

        # Extract JS URLs for DOM XSS
        js_files = []
        for script in soup.find_all('script', src=True):
            js_files.append(urljoin(url, script['src']))
            
        return {
            'url': url,
            'title': await page.title(),
            'links': list(set(links)),
            'forms': forms,
            'js_files': js_files,
        }

    async def crawl(self, url: str) -> Dict[str, Any]:
        """Crawls a single URL using a headless browser."""
        # Skip binary files
        if _NON_HTML_EXT.search(urlparse(url).path):
            return {'success': False, 'error': f'Skipped non-HTML file: {url}'}

        try:
            logger.info(f"Playwright crawling (Dynamic): {url}")
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                
                response = await page.goto(url, wait_until="networkidle", timeout=self.timeout)
                
                if not response:
                    await browser.close()
                    return {'success': False, 'error': 'No response from server'}
                    
                data = await self.extract_page_data(page, url)
                data['status_code'] = response.status
                data['engine'] = 'playwright'
                
                await browser.close()
                return {'success': True, 'data': data}
                
        except Exception as e:
            logger.error(f"Playwright crawl error on {url}: {str(e)}")
            return {'success': False, 'error': str(e)}