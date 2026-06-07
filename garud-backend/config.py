import os


class Config:
    """Base configuration"""
    
   
    HOST = '0.0.0.0'
    PORT = 7000
    DEBUG = True
    
    
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = True
    
   
    CORS_ORIGINS = [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:8001'
    ]
    
   
    REQUEST_TIMEOUT = 10
    MAX_DEPTH = 2
    MAX_WORKERS = 3
    
    
    SELENIUM_TIMEOUT = 10
    SELENIUM_HEADLESS = True
    
    
    PLAYWRIGHT_HEADLESS = True
    PLAYWRIGHT_TIMEOUT = 10000
    
    
    BS_TIMEOUT = 10
    
    
    SCRAPY_TIMEOUT = 10
    SCRAPY_MAX_DEPTH = 2
    
    
    PING_TIMEOUT = 10
    TRACEROUTE_TIMEOUT = 15
    NMAP_TIMEOUT = 30
    DNS_TIMEOUT = 5
    
    
    LOGS_DIR = os.path.join(os.path.dirname(__file__), 'logs')
    REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'reports')
    
   
    LOG_LEVEL = 'INFO'
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


class DevelopmentConfig(Config):
    DEBUG = True
    SELENIUM_HEADLESS = False


class ProductionConfig(Config):
    DEBUG = False
    SELENIUM_HEADLESS = True
    LOG_LEVEL = 'WARNING'


class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    SELENIUM_TIMEOUT = 5



ENV = os.getenv('FLASK_ENV', 'development').lower()

if ENV == 'production':
    config = ProductionConfig
elif ENV == 'testing':
    config = TestingConfig
else:
    config = DevelopmentConfig