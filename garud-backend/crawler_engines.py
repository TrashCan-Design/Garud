import logging
from typing import Dict, List, Any
import asyncio
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.common.exceptions import TimeoutException
import time

from webdriver_manager.microsoft import EdgeChromiumDriverManager
from selenium.webdriver.edge.service import Service

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger(__name__)

class SeleniumEngine:
    def __init__(self, timeout: int = 10, headless: bool = True):
        self.timeout = timeout
        self.headless = headless
        self.driver = None
        self.wait = None
    
    def _setup_driver(self):
        try:
            options = EdgeOptions()
            if self.headless:
                options.add_argument('--headless=new')
            options.add_argument('--start-maximized')
            options.add_argument('--no-sandbox')
            
            
            service = Service(EdgeChromiumDriverManager().install())
            self.driver = webdriver.Edge(service=service, options=options)
    
            self.wait = WebDriverWait(self.driver, self.timeout)
            logger.info("Selenium WebDriver initialized")
            return True
        except Exception as e:
            logger.error(f"Selenium setup failed: {str(e)}")
            return False
    
    def _cleanup(self):
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass

    