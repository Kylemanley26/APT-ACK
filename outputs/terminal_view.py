from storage.database import db
from storage.models import FeedItem, SeverityLevel, IOC, Tag
from datetime import datetime, timedelta, UTC
from collections import Counter

class TerminalDashboard:
    def __init__(self):
        self.severity_colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
            'LOW': '\033[92m',       # Green
            'INFO': '\033[90m'       # Gray
        }
        self.reset_color = '\033[0m'
    
    def colorize(self, text, severity):
        """Add color to severity text"""
        color = self.severity_colors.get(severity.upper(), '')
        return f"{color}{text}{self.reset_color}"
    
    def show_summary(self):
        """Display overall summary statistics"""
        session = db.get_session()
        
        try:
            total_items = session.query(FeedItem).count()
            total_iocs = session.query(IOC).count()
            
            # Count by severity
            severity_counts = {}
            for severity in SeverityLevel:
                count = session.query(FeedItem).filter_by(severity=severity).count()
                severity_counts[severity.value] = count
            
            # Recent items (last 24 hours)
            day_ago = datetime.now(UTC) - timedelta(days=1)
            recent_count = session.query(FeedItem).filter(
                FeedItem.collected_date >= day_ago
            ).count()
            
            # Top tags
            all_items = session.query(FeedItem).all()
            tag_counter = Counter()
            for item in all_items:
                for tag in item.tags:
                    tag_counter[tag.name] += 1
            
            print("\n" + "="*80)
            print("APT-ACK THREAT INTELLIGENCE DASHBOARD".center(80))
            print("="*80)
            
            print(f"\nTotal Feed Items: {total_items}")
            print(f"Total IOCs Extracted: {total_iocs}")
            print(f"New Items (24h): {recent_count}")
            
            print("\nSeverity Breakdown:")
            for severity, count in severity_counts.items():
                if count > 0:
                    colored_sev = self.colorize(f"  {severity.upper()}: {count}", severity)
                    print(colored_sev)
            
            if tag_counter:
                print("\nTop Tags:")
                for tag, count in tag_counter.most_common(10):
                    print(f"  {tag}: {count}")
            
            print("\n" + "="*80 + "\n")
            
        finally:
            session.close()
    
    def show_critical_alerts(self, limit=10):
        """Display critical and high severity items"""
        session = db.get_session()
        
        try:
            critical_items = session.query(FeedItem).filter(
                FeedItem.severity.in_([SeverityLevel.CRITICAL, SeverityLevel.HIGH])
            ).order_by(FeedItem.relevance_score.desc()).limit(limit).all()
            
            if not critical_items:
                print("No critical or high severity items found.")
                return
            
            print("\nCRITICAL & HIGH PRIORITY ALERTS:")
            print("-" * 80)
            
            for item in critical_items:
                severity_colored = self.colorize(f"[{item.severity.value.upper()}]", item.severity.value)
                print(f"\n{severity_colored} {item.title}")
                print(f"Score: {item.relevance_score:.2f} | Source: {item.source_name}")
                
                if item.tags:
                    tags_str = ', '.join([t.name for t in item.tags[:5]])
                    print(f"Tags: {tags_str}")
                
                if item.iocs:
                    print(f"IOCs: {len(item.iocs)}")
                
                print(f"Link: {item.link}")
            
            print("\n" + "-" * 80 + "\n")
            
        finally:
            session.close()
    
    def show_by_severity(self, severity_level, limit=20):
        """Show items filtered by severity"""
        session = db.get_session()
        
        try:
            items = session.query(FeedItem).filter_by(
                severity=severity_level
            ).order_by(FeedItem.collected_date.desc()).limit(limit).all()
            
            if not items:
                print(f"No items found with severity: {severity_level.value}")
                return
            
            print(f"\n{severity_level.value.upper()} SEVERITY ITEMS:")
            print("-" * 80)
            
            for item in items:
                print(f"\n{item.title}")
                print(f"Score: {item.relevance_score:.2f} | Source: {item.source_name}")
                if item.tags:
                    tags_str = ', '.join([t.name for t in item.tags[:5]])
                    print(f"Tags: {tags_str}")
                print(f"Link: {item.link}")
            
            print("\n" + "-" * 80 + "\n")
            
        finally:
            session.close()
    
    def show_by_tag(self, tag_name, limit=20):
        """Show items filtered by tag"""
        session = db.get_session()
        
        try:
            items = session.query(FeedItem).join(FeedItem.tags).filter(
                Tag.name == tag_name.lower()
            ).order_by(FeedItem.relevance_score.desc()).limit(limit).all()
            
            if not items:
                print(f"No items found with tag: {tag_name}")
                return
            
            print(f"\nITEMS TAGGED WITH '{tag_name.upper()}':")
            print("-" * 80)
            
            for item in items:
                severity_colored = self.colorize(f"[{item.severity.value.upper()}]", item.severity.value)
                print(f"\n{severity_colored} {item.title}")
                print(f"Score: {item.relevance_score:.2f} | Source: {item.source_name}")
                print(f"Link: {item.link}")
            
            print("\n" + "-" * 80 + "\n")
            
        finally:
            session.close()
    
    def show_recent(self, hours=24, limit=20):
        """Show recent items"""
        session = db.get_session()
        
        try:
            time_ago = datetime.now(UTC) - timedelta(hours=hours)
            items = session.query(FeedItem).filter(
                FeedItem.collected_date >= time_ago
            ).order_by(FeedItem.collected_date.desc()).limit(limit).all()
            
            if not items:
                print(f"No items found in the last {hours} hours")
                return
            
            print(f"\nRECENT ITEMS (Last {hours} hours):")
            print("-" * 80)
            
            for item in items:
                severity_colored = self.colorize(f"[{item.severity.value.upper()}]", item.severity.value)
                print(f"\n{severity_colored} {item.title}")
                print(f"Score: {item.relevance_score:.2f} | Source: {item.source_name}")
                if item.tags:
                    tags_str = ', '.join([t.name for t in item.tags[:5]])
                    print(f"Tags: {tags_str}")
                print(f"Published: {item.published_date}")
            
            print("\n" + "-" * 80 + "\n")
            
        finally:
            session.close()