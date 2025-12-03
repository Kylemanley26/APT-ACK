import feedparser
import requests
from datetime import datetime, UTC
from time import struct_time
from typing import Any, Optional
from storage.database import db
from storage.models import FeedItem, SeverityLevel
from bs4 import BeautifulSoup
import hashlib

def parse_feed_date(parsed_time: Any) -> Optional[datetime]:
    """Convert feedparser's parsed time struct to datetime"""
    if parsed_time is None:
        return None
    try:
        # feedparser returns time.struct_time or similar tuple
        t: struct_time = parsed_time
        return datetime(t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, tzinfo=UTC)
    except (TypeError, AttributeError):
        return None


class RSSCollector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'APT-ACK/1.0 Threat Intelligence Aggregator'
        })
    
    def fetch_feed(self, feed_url, feed_name):
        """Fetch and parse RSS feed"""
        try:
            response = self.session.get(feed_url, timeout=30)
            response.raise_for_status()
            feed = feedparser.parse(response.content)
            
            if feed.bozo:
                print(f"Warning: Feed parsing issue for {feed_name}: {feed.bozo_exception}")
            
            return feed
        except Exception as e:
            print(f"Error fetching {feed_name}: {e}")
            return None
    
    def clean_html(self, html_content):
        """Strip HTML tags and return plain text"""
        if not html_content:
            return ""
        soup = BeautifulSoup(html_content, 'html.parser')
        return soup.get_text(separator=' ', strip=True)
    
    def generate_link_hash(self, link):
        """Generate unique hash for deduplication"""
        return hashlib.sha256(link.encode()).hexdigest()[:16]
    
    def collect_feed(self, feed_url, feed_name):
        """Collect items from a single feed"""
        feed = self.fetch_feed(feed_url, feed_name)
        if not feed:
            return 0
        
        db_session = db.get_session()
        new_items = 0
        
        try:
            for entry in feed.entries:
                link = entry.get('link', '')
                if not link:
                    continue
                
                # Check if already exists
                existing = db_session.query(FeedItem).filter_by(link=link).first()
                if existing:
                    continue
                
                # Extract content
                title = entry.get('title', 'No title')
                content = entry.get('summary', entry.get('description', ''))
                raw_content = content
                content = self.clean_html(content)
                
                # Parse published date
                published_date = None
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    published_date = parse_feed_date(entry.published_parsed)
                elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    published_date = parse_feed_date(entry.updated_parsed)
                
                # Create feed item
                feed_item = FeedItem(
                    source_name=feed_name,
                    source_url=feed_url,
                    title=title,
                    content=content,
                    link=link,
                    published_date=published_date,
                    raw_content=raw_content,
                    severity=SeverityLevel.INFO,
                    processed=False
                )
                
                db_session.add(feed_item)
                new_items += 1
            
            db_session.commit()
            print(f"Collected {new_items} new items from {feed_name}")
            return new_items
            
        except Exception as e:
            print(f"Error saving items from {feed_name}: {e}")
            db_session.rollback()
            return 0
        finally:
            db_session.close()
    
    def collect_all(self, sources):
        """Collect from all configured sources"""
        total = 0
        for source in sources:
            count = self.collect_feed(source['url'], source['name'])
            total += count
        return total