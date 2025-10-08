import sys
import os
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.rss_feeds import RSSCollector
from storage.database import db

def test_collector():
    """Test RSS collection"""
    
    # Initialize database
    db.init_db()
    
    # Load sources from project root
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    config_path = os.path.join(project_root, 'config', 'sources.yaml')
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Collect from first feed only (for testing)
    collector = RSSCollector()
    test_feed = config['rss_feeds'][0]
    
    print(f"Testing collection from {test_feed['name']}...")
    count = collector.collect_feed(test_feed['url'], test_feed['name'])
    print(f"\nCollected {count} items")

if __name__ == "__main__":
    test_collector()