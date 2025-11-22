import logging
from typing import Dict, List, Any
import asyncio
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import time
from selenium.webdriver.edge.service import Service


try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger(__name__)


class SeleniumEngine:
    """
    Selenium-based crawler for dynamic content
    Uses Edge browser for modern web standards
    """
    
    def __init__(self, timeout: int = 10, headless: bool = True):
        """Initialize Selenium engine"""
        self.timeout = timeout
        self.headless = headless
        self.driver = None
        self.wait = None
    
    def _setup_driver(self):
        """Setup Edge WebDriver"""
        try:
            options = EdgeOptions()
            if self.headless:
                options.add_argument('--headless=new')

            options.add_argument('--start-maximized')
            options.add_argument('--no-sandbox')
            
            service = Service("C:\\Users\\jshah\\Downloads\\edgedriver_win32\\msedgedriver.exe")
            self.driver = webdriver.Edge(service=service, options=options)
    
            self.wait = WebDriverWait(self.driver, self.timeout)
            logger.info("Selenium WebDriver initialized")
            return True
        except Exception as e:
            logger.error(f"Selenium setup failed: {str(e)}")
            return False
    
    def _cleanup(self):
        """Cleanup WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
    
    def crawl(self, url: str) -> Dict[str, Any]:
        """Basic crawl with Selenium"""
        if not self._setup_driver():
            return {'success': False, 'error': 'Failed to initialize WebDriver'}
        
        try:
            logger.info(f"Selenium crawling: {url}")
            self.driver.get(url)
            time.sleep(2)
            
            data = {
                'engine': 'selenium',
                'url': url,
                'title': self.driver.title,
                'current_url': self.driver.current_url,
                'links': self._extract_links(),
                'forms': self._extract_forms(),
                'inputs': self._extract_inputs(),
                'cookies': self._extract_cookies(),
                'page_size': len(self.driver.page_source),
                'javascript_enabled': True
            }
            
            return {'success': True, 'data': data}
        except TimeoutException:
            return {'success': False, 'error': 'Page load timeout'}
        except Exception as e:
            logger.error(f"Selenium crawl error: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            self._cleanup()
    
    def crawl_with_login(self, url: str, username_selector: str, 
                        password_selector: str, submit_selector: str,
                        username: str, password: str) -> Dict[str, Any]:
        """Crawl with login (based on LoginTest.java)"""
        if not self._setup_driver():
            return {'success': False, 'error': 'Failed to initialize WebDriver'}
        
        try:
            logger.info(f"Selenium login crawl: {url}")
            self.driver.get(url)
            time.sleep(2)
            
            # Fill username
            username_field = self.wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, username_selector))
            )
            username_field.clear()
            username_field.send_keys(username)
            
            # Fill password
            password_field = self.driver.find_element(By.CSS_SELECTOR, password_selector)
            password_field.clear()
            password_field.send_keys(password)
            
            # Click submit
            submit_btn = self.driver.find_element(By.CSS_SELECTOR, submit_selector)
            submit_btn.click()
            
            time.sleep(3)
            
            data = {
                'engine': 'selenium',
                'authenticated': True,
                'redirected_url': self.driver.current_url,
                'title': self.driver.title,
                'forms': self._extract_forms(),
                'page_size': len(self.driver.page_source)
            }
            
            return {'success': True, 'data': data}
        except Exception as e:
            logger.error(f"Selenium login error: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            self._cleanup()
    
    def _extract_links(self) -> List[str]:
        """Extract all links"""
        try:
            links = self.driver.find_elements(By.TAG_NAME, 'a')
            return [link.get_attribute('href') for link in links if link.get_attribute('href')]
        except:
            return []
    
    def _extract_forms(self) -> List[Dict]:
        """Extract all forms"""
        try:
            forms = []
            form_elements = self.driver.find_elements(By.TAG_NAME, 'form')
            for form in form_elements:
                forms.append({
                    'name': form.get_attribute('name'),
                    'action': form.get_attribute('action'),
                    'method': form.get_attribute('method')
                })
            return forms
        except:
            return []
    
    def _extract_inputs(self) -> List[Dict]:
        """Extract all inputs"""
        try:
            inputs = self.driver.find_elements(By.TAG_NAME, 'input')
            return [{
                'type': inp.get_attribute('type'),
                'name': inp.get_attribute('name'),
                'id': inp.get_attribute('id')
            } for inp in inputs]
        except:
            return []
    
    def _extract_cookies(self) -> Dict[str, str]:
        """Extract cookies"""
        try:
            cookies = self.driver.get_cookies()
            return {cookie['name']: cookie['value'] for cookie in cookies}
        except:
            return {}


class PlaywrightEngine:
    """
    Playwright-based crawler for advanced JavaScript handling
    Used when Selenium lacks support for certain scenarios
    """
    
    def __init__(self, headless: bool = True, timeout: int = 10000):
        """Initialize Playwright engine"""
        self.headless = headless
        self.timeout = timeout
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright not installed")
    
    async def crawl(self, url: str) -> Dict[str, Any]:
        """Crawl with Playwright"""
        if not PLAYWRIGHT_AVAILABLE:
            return {'success': False, 'error': 'Playwright not installed'}
        
        try:
            logger.info(f"Playwright crawling: {url}")
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                page = await browser.new_page()
                
                await page.goto(url, wait_until='networkidle')
                await page.wait_for_timeout(2000)
                
                data = {
                    'engine': 'playwright',
                    'url': url,
                    'title': await page.title(),
                    'current_url': page.url,
                    'links': await page.eval_on_selector_all('a', '[el => el.href]'),
                    'forms': await self._extract_playwright_forms(page),
                    'page_size': len(await page.content()),
                    'javascript_enabled': True
                }
                
                await browser.close()
                return {'success': True, 'data': data}
                
        except Exception as e:
            logger.error(f"Playwright crawl error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    async def _extract_playwright_forms(self, page) -> List[Dict]:
        """Extract forms using Playwright"""
        try:
            forms = await page.query_selector_all('form')
            form_data = []
            for form in forms:
                name = await form.get_attribute('name')
                action = await form.get_attribute('action')
                method = await form.get_attribute('method')
                form_data.append({
                    'name': name,
                    'action': action,
                    'method': method
                })
            return form_data
        except:
            return []


class CrawlerFactory:
    """
    Factory to select appropriate crawler based on needs
    """
    
    @staticmethod
    def get_crawler(url: str, engine: str = 'auto') -> Any:
        """
        Get appropriate crawler
        
        Args:
            url: Target URL
            engine: 'selenium', 'playwright', or 'auto' (default)
        
        Returns:
            Appropriate crawler engine
        """
        if engine == 'playwright' and PLAYWRIGHT_AVAILABLE:
            logger.info("Using Playwright engine")
            return PlaywrightEngine()
        else:
            logger.info("Using Selenium engine")
            return SeleniumEngine()
    
    @staticmethod
    def crawl(url: str, engine: str = 'auto', method: str = 'basic', **kwargs) -> Dict[str, Any]:
        """
        Perform crawl with selected engine
        
        Args:
            url: Target URL
            engine: Browser engine to use
            method: 'basic' or 'login'
            **kwargs: Additional parameters for login
        
        Returns:
            Crawl results
        """
        if engine == 'playwright' and PLAYWRIGHT_AVAILABLE:
            crawler = PlaywrightEngine()
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            return loop.run_until_complete(crawler.crawl(url))
        else:
            crawler = SeleniumEngine()
            
            if method == 'login':
                return crawler.crawl_with_login(
                    url,
                    username_selector=kwargs.get('username_selector', '#username'),
                    password_selector=kwargs.get('password_selector', '#password'),
                    submit_selector=kwargs.get('submit_selector', '#submit'),
                    username=kwargs.get('username', ''),
                    password=kwargs.get('password', '')
                )
            else:
                return crawler.crawl(url)