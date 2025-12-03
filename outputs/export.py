import json
import csv
import os
from datetime import datetime
from storage.database import db
from storage.models import FeedItem, IOC, SeverityLevel

class DataExporter:
    def __init__(self, export_dir='exports'):
        self.export_dir = export_dir
        # Create directory if it doesn't exist
        os.makedirs(self.export_dir, exist_ok=True)
    
    def export_to_json(self, filename='apt_ack_export.json', severity_filter=None):
        """Export feed items to JSON"""
        session = db.get_session()
        filepath = os.path.join(self.export_dir, filename)
        
        try:
            query = session.query(FeedItem)
            if severity_filter:
                query = query.filter(FeedItem.severity.in_(severity_filter))
            
            items = query.all()
            
            export_data = {
                'export_date': datetime.utcnow().isoformat(),
                'total_items': len(items),
                'items': []
            }
            
            for item in items:
                item_data = {
                    'id': item.id,
                    'source': item.source_name,
                    'title': item.title,
                    'content': item.content,
                    'link': item.link,
                    'published_date': item.published_date.isoformat() if item.published_date else None,
                    'collected_date': item.collected_date.isoformat() if item.collected_date else None,
                    'severity': item.severity.value,
                    'relevance_score': item.relevance_score,
                    'tags': [{'name': t.name, 'category': t.category} for t in item.tags],
                    'iocs': [
                        {
                            'type': ioc.ioc_type.value,
                            'value': ioc.value,
                            'confidence': ioc.confidence,
                            'context': ioc.context
                        } for ioc in item.iocs
                    ]
                }
                export_data['items'].append(item_data)
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"Exported {len(items)} items to {filepath}")
            return filepath
            
        finally:
            session.close()
    
    def export_to_csv(self, filename='apt_ack_export.csv', severity_filter=None):
        """Export feed items to CSV"""
        session = db.get_session()
        filepath = os.path.join(self.export_dir, filename)
        
        try:
            query = session.query(FeedItem)
            if severity_filter:
                query = query.filter(FeedItem.severity.in_(severity_filter))
            
            items = query.all()
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'ID', 'Source', 'Title', 'Link', 'Published Date',
                    'Severity', 'Relevance Score', 'Tags', 'IOC Count'
                ])
                
                for item in items:
                    tags_str = '; '.join([t.name for t in item.tags])
                    writer.writerow([
                        item.id,
                        item.source_name,
                        item.title,
                        item.link,
                        item.published_date.isoformat() if item.published_date else '',
                        item.severity.value,
                        item.relevance_score,
                        tags_str,
                        len(item.iocs)
                    ])
            
            print(f"Exported {len(items)} items to {filepath}")
            return filepath
            
        finally:
            session.close()
    
    def export_iocs_csv(self, filename='apt_ack_iocs.csv', min_confidence=0.5):
        """Export IOCs to CSV"""
        session = db.get_session()
        filepath = os.path.join(self.export_dir, filename)
        
        try:
            iocs = session.query(IOC).filter(IOC.confidence >= min_confidence).all()
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'IOC Type', 'Value', 'Confidence', 'First Seen',
                    'Feed Item ID', 'Context'
                ])
                
                for ioc in iocs:
                    writer.writerow([
                        ioc.ioc_type.value,
                        ioc.value,
                        ioc.confidence,
                        ioc.first_seen.isoformat() if ioc.first_seen else '',
                        ioc.feed_item_id,
                        ioc.context[:100] if ioc.context else ''
                    ])
            
            print(f"Exported {len(iocs)} IOCs to {filepath}")
            return filepath
            
        finally:
            session.close()