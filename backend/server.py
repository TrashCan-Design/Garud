from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from middleware import DataProcessor
from crawler_engines import CrawlerFactory
from beautifulsoup_crawler import BeautifulSoupCrawler
from scrapy_crawler import ScrapyEngine
from network_scanner import NetworkScanner
from config import Config

# Initialize Flask
app = Flask(__name__)
CORS(app)
app.config.from_object(Config)

# Initialize components
processor = DataProcessor()
bs_crawler = BeautifulSoupCrawler()
scrapy_engine = ScrapyEngine()
network_scanner = NetworkScanner()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== HEALTH ENDPOINTS ====================

@app.route('/health', methods=['GET'])
def health_check():
    """Server health check"""
    return jsonify({
        'status': 'online',
        'port': Config.PORT,
        'available_engines': ['selenium', 'playwright', 'beautifulsoup', 'scrapy']
    }), 200


# ==================== CRAWLING ENDPOINTS ====================

@app.route('/api/crawl', methods=['POST'])
def crawl_basic():
    """
    Basic crawl with auto engine selection
    Body: {"url": "https://example.com", "engine": "auto"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL required'}), 400
        
        url = data.get('url')
        engine = data.get('engine', 'auto')
        
        logger.info(f"Basic crawl: {url} (engine: {engine})")
        
        # Crawl with selected engine
        crawl_result = CrawlerFactory.crawl(url, engine=engine, method='basic')
        
        # Process results
        processed = processor.process_crawl_data(crawl_result)
        
        return jsonify({
            'success': True,
            'url': url,
            'engine': engine,
            'raw_data': crawl_result.get('data', {}),
            'processed_data': processed
        }), 200
        
    except Exception as e:
        logger.error(f"Crawl error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/crawl/with-network', methods=['POST'])
def crawl_with_network():
    """
    Crawl website WITH network reconnaissance
    Body: {"url": "https://example.com", "engine": "auto"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL required'}), 400
        
        url = data.get('url')
        engine = data.get('engine', 'auto')
        
        logger.info(f"Crawl with network scan: {url}")
        
        # Perform network scan
        network_result = network_scanner.scan_target(url)
        
        # Crawl website
        crawl_result = CrawlerFactory.crawl(url, engine=engine, method='basic')
        
        # Integrate results
        processed = processor.integrate_network_scan(crawl_result, url)
        
        # Get scanner context
        scanner_context = processor.get_scanner_context(processed)
        
        return jsonify({
            'success': True,
            'url': url,
            'engine': engine,
            'network_scan': network_result,
            'crawl_data': crawl_result.get('data', {}),
            'processed_data': processed,
            'scanner_context': scanner_context
        }), 200
        
    except Exception as e:
        logger.error(f"Network crawl error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/crawl/login', methods=['POST'])
def crawl_with_login():
    """
    Crawl with login authentication
    Body: {
      "url": "https://example.com",
      "username_selector": "#username",
      "password_selector": "#password",
      "submit_selector": "#submit",
      "username": "user",
      "password": "pass",
      "engine": "selenium"
    }
    """
    try:
        data = request.get_json()
        required = ['url', 'username_selector', 'password_selector', 
                   'submit_selector', 'username', 'password']
        
        if not all(f in data for f in required):
            return jsonify({'error': f'Required fields: {required}'}), 400
        
        logger.info(f"Login crawl: {data['url']}")
        
        # Use Selenium for login (more reliable)
        crawl_result = CrawlerFactory.crawl(
            data['url'],
            engine='selenium',
            method='login',
            username_selector=data['username_selector'],
            password_selector=data['password_selector'],
            submit_selector=data['submit_selector'],
            username=data['username'],
            password=data['password']
        )
        
        # Process results
        processed = processor.process_crawl_data(crawl_result)
        
        return jsonify({
            'success': crawl_result.get('success', False),
            'url': data['url'],
            'authenticated': True,
            'raw_data': crawl_result.get('data', {}),
            'processed_data': processed
        }), 200
        
    except Exception as e:
        logger.error(f"Login crawl error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/crawl/beautifulsoup', methods=['POST'])
def crawl_beautifulsoup():
    """
    Crawl with BeautifulSoup (static HTML)
    Body: {"url": "https://example.com"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL required'}), 400
        
        url = data.get('url')
        logger.info(f"BeautifulSoup crawl: {url}")
        
        result = bs_crawler.crawl(url)
        
        if result.get('success'):
            processed = processor.process_crawl_data(result)
            return jsonify({
                'success': True,
                'engine': 'beautifulsoup',
                'url': url,
                'raw_data': result.get('data', {}),
                'processed_data': processed
            }), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"BeautifulSoup error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/crawl/scrapy', methods=['POST'])
def crawl_scrapy():
    """
    Crawl with Scrapy (modular HTML scraping)
    Body: {"url": "https://example.com", "depth": 1}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL required'}), 400
        
        url = data.get('url')
        depth = data.get('depth', 1)
        
        logger.info(f"Scrapy crawl: {url} (depth: {depth})")
        
        result = scrapy_engine.crawl(url, max_depth=depth)
        
        if result.get('success'):
            processed = processor.process_crawl_data(result)
            return jsonify({
                'success': True,
                'engine': 'scrapy',
                'url': url,
                'depth': depth,
                'raw_data': result.get('data', {}),
                'processed_data': processed
            }), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Scrapy error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== NETWORK SCANNING ENDPOINTS ====================

@app.route('/api/scan/network', methods=['POST'])
def network_scan():
    """
    Perform network reconnaissance
    Body: {"url": "https://example.com" or "hostname"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL required'}), 400
        
        url = data.get('url')
        logger.info(f"Network scan: {url}")
        
        result = network_scanner.scan_target(url)
        
        if 'error' not in result:
            return jsonify({
                'success': True,
                'url': url,
                'network_data': result,
                'summary': result.get('summary', {})
            }), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Network scan error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/ping', methods=['POST'])
def ping_scan():
    """
    Ping target host
    Body: {"url": "https://example.com" or "hostname"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL required'}), 400
        
        url = data.get('url')
        logger.info(f"Ping: {url}")
        
        ping_result = network_scanner._ping_host(network_scanner._extract_hostname(url))
        
        return jsonify({
            'success': ping_result.get('success', False),
            'url': url,
            'ping_result': ping_result
        }), 200
        
    except Exception as e:
        logger.error(f"Ping error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/dns', methods=['POST'])
def dns_scan():
    """
    DNS lookup
    Body: {"url": "example.com" or "hostname"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL required'}), 400
        
        url = data.get('url')
        logger.info(f"DNS lookup: {url}")
        
        dns_result = network_scanner._nslookup(network_scanner._extract_hostname(url))
        
        return jsonify({
            'success': dns_result.get('success', False),
            'url': url,
            'dns_result': dns_result
        }), 200
        
    except Exception as e:
        logger.error(f"DNS error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/traceroute', methods=['POST'])
def traceroute_scan():
    """
    Traceroute to target
    Body: {"url": "example.com" or "hostname"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL required'}), 400
        
        url = data.get('url')
        logger.info(f"Traceroute: {url}")
        
        tr_result = network_scanner._traceroute(network_scanner._extract_hostname(url))
        
        return jsonify({
            'success': tr_result.get('success', False),
            'url': url,
            'traceroute_result': tr_result
        }), 200
        
    except Exception as e:
        logger.error(f"Traceroute error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== EXTRACTION ENDPOINTS ====================

@app.route('/api/extract/forms', methods=['POST'])
def extract_forms():
    """Extract forms from page"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL required'}), 400
        
        url = data.get('url')
        logger.info(f"Extracting forms: {url}")
        
        result = bs_crawler.crawl(url)
        forms = result.get('data', {}).get('forms', []) if result.get('success') else []
        
        return jsonify({
            'success': result.get('success', False),
            'url': url,
            'form_count': len(forms),
            'forms': forms
        }), 200
        
    except Exception as e:
        logger.error(f"Form extraction error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/extract/sensitive-fields', methods=['POST'])
def extract_sensitive():
    """Extract sensitive form fields"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'URL required'}), 400
        
        url = data.get('url')
        logger.info(f"Extracting sensitive fields: {url}")
        
        sensitive = bs_crawler.extract_sensitive_fields(url)
        
        return jsonify({
            'success': True,
            'url': url,
            'sensitive_count': len(sensitive),
            'sensitive_fields': sensitive
        }), 200
        
    except Exception as e:
        logger.error(f"Sensitive extraction error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


# ==================== MAIN ====================

if __name__ == '__main__':
    logger.info(f"Starting Flask server on {Config.HOST}:{Config.PORT}")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)