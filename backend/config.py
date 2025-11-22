import os


class Config:
    """Base configuration"""
    
    # Server Configuration
    HOST = '127.0.0.1'
    PORT = 7000
    DEBUG = True
    
    # Flask Configuration
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = True
    
    # CORS Configuration
    CORS_ORIGINS = [
        'http://localhost:3000',
        'http://127.0.0.1:3000'
    ]
    
    # Crawler Configuration
    REQUEST_TIMEOUT = 10
    MAX_DEPTH = 2
    MAX_WORKERS = 3
    
    # Selenium Configuration
    SELENIUM_TIMEOUT = 10
    SELENIUM_HEADLESS = True
    
    # Playwright Configuration
    PLAYWRIGHT_HEADLESS = True
    PLAYWRIGHT_TIMEOUT = 10000
    
    # BeautifulSoup Configuration
    BS_TIMEOUT = 10
    
    # Scrapy Configuration
    SCRAPY_TIMEOUT = 10
    SCRAPY_MAX_DEPTH = 2
    
    # Network Scanning Configuration
    PING_TIMEOUT = 10
    TRACEROUTE_TIMEOUT = 15
    NMAP_TIMEOUT = 30
    DNS_TIMEOUT = 5
    
    # Paths
    LOGS_DIR = os.path.join(os.path.dirname(__file__), 'logs')
    REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'reports')
    
    # Logging
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SELENIUM_HEADLESS = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SELENIUM_HEADLESS = True
    LOG_LEVEL = 'WARNING'


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SELENIUM_TIMEOUT = 5


# Load environment
ENV = os.getenv('FLASK_ENV', 'development').lower()

if ENV == 'production':
    config = ProductionConfig
elif ENV == 'testing':
    config = TestingConfig
else:
    config = DevelopmentConfig