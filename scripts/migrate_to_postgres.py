import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from storage.models import Base, FeedItem, IOC, Tag, Alert, DigestLog

def migrate_to_postgres():
    """Migrate data from SQLite to PostgreSQL"""
    
    # Check for DATABASE_URL
    postgres_url = os.environ.get('DATABASE_URL')
    if not postgres_url:
        print("ERROR: DATABASE_URL not set in .env file")
        print("Add your Supabase connection string to .env:")
        print("DATABASE_URL=postgresql://postgres:password@db.xxx.supabase.co:5432/postgres")
        return False
    
    # SQLite source
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    sqlite_path = os.path.join(project_root, 'apt_ack.db')
    sqlite_url = f'sqlite:///{sqlite_path}'
    
    if not os.path.exists(sqlite_path):
        print(f"ERROR: SQLite database not found at {sqlite_path}")
        return False
    
    print("="*80)
    print("APT-ACK DATABASE MIGRATION")
    print("="*80)
    print(f"\nSource: SQLite ({sqlite_path})")
    print(f"Target: PostgreSQL (Supabase)")
    print("\nThis will:")
    print("1. Create tables in PostgreSQL")
    print("2. Copy all data from SQLite to PostgreSQL")
    print("3. Preserve all relationships and metadata")
    print("\n" + "="*80)
    
    response = input("\nProceed with migration? (yes/no): ")
    if response.lower() != 'yes':
        print("Migration cancelled.")
        return False
    
    try:
        # Connect to both databases
        print("\nConnecting to databases...")
        sqlite_engine = create_engine(sqlite_url)
        postgres_engine = create_engine(postgres_url, pool_pre_ping=True)
        
        SqliteSession = sessionmaker(bind=sqlite_engine)
        PostgresSession = sessionmaker(bind=postgres_engine)
        
        # Create tables in PostgreSQL
        print("Creating tables in PostgreSQL...")
        Base.metadata.create_all(postgres_engine)
        
        sqlite_session = SqliteSession()
        postgres_session = PostgresSession()
        
        # Migrate Tags first (no dependencies)
        print("\nMigrating Tags...")
        tags = sqlite_session.query(Tag).all()
        tag_map = {}
        
        for old_tag in tags:
            new_tag = Tag(
                name=old_tag.name,
                category=old_tag.category,
                auto_generated=old_tag.auto_generated,
                created_date=old_tag.created_date
            )
            postgres_session.add(new_tag)
            postgres_session.flush()
            tag_map[old_tag.id] = new_tag
        
        postgres_session.commit()
        print(f"  Migrated {len(tags)} tags")
        
        # Migrate FeedItems
        print("\nMigrating Feed Items...")
        feed_items = sqlite_session.query(FeedItem).all()
        feed_map = {}
        
        for old_item in feed_items:
            new_item = FeedItem(
                source_name=old_item.source_name,
                source_url=old_item.source_url,
                title=old_item.title,
                content=old_item.content,
                link=old_item.link,
                published_date=old_item.published_date,
                collected_date=old_item.collected_date,
                severity=old_item.severity,
                relevance_score=old_item.relevance_score,
                raw_content=old_item.raw_content,
                processed=old_item.processed
            )
            
            # Map tags
            for old_tag in old_item.tags:
                if old_tag.id in tag_map:
                    new_item.tags.append(tag_map[old_tag.id])
            
            postgres_session.add(new_item)
            postgres_session.flush()
            feed_map[old_item.id] = new_item
        
        postgres_session.commit()
        print(f"  Migrated {len(feed_items)} feed items")
        
        # Migrate IOCs
        print("\nMigrating IOCs...")
        iocs = sqlite_session.query(IOC).all()
        
        for old_ioc in iocs:
            new_ioc = IOC(
                feed_item_id=feed_map[old_ioc.feed_item_id].id if old_ioc.feed_item_id in feed_map else None,
                ioc_type=old_ioc.ioc_type,
                value=old_ioc.value,
                context=old_ioc.context,
                confidence=old_ioc.confidence,
                verified=old_ioc.verified,
                first_seen=old_ioc.first_seen,
                last_seen=old_ioc.last_seen,
                threat_actor=old_ioc.threat_actor,
                malware_family=old_ioc.malware_family,
                mitre_techniques=old_ioc.mitre_techniques
            )
            
            # Map tags
            for old_tag in old_ioc.tags:
                if old_tag.id in tag_map:
                    new_ioc.tags.append(tag_map[old_tag.id])
            
            postgres_session.add(new_ioc)
        
        postgres_session.commit()
        print(f"  Migrated {len(iocs)} IOCs")
        
        # Migrate Alerts
        print("\nMigrating Alerts...")
        alerts = sqlite_session.query(Alert).all()
        
        for old_alert in alerts:
            new_alert = Alert(
                feed_item_id=feed_map[old_alert.feed_item_id].id if old_alert.feed_item_id in feed_map else None,
                title=old_alert.title,
                description=old_alert.description,
                severity=old_alert.severity,
                created_date=old_alert.created_date,
                acknowledged=old_alert.acknowledged,
                dismissed=old_alert.dismissed,
                included_in_digest=old_alert.included_in_digest,
                digest_date=old_alert.digest_date
            )
            postgres_session.add(new_alert)
        
        postgres_session.commit()
        print(f"  Migrated {len(alerts)} alerts")
        
        # Migrate DigestLogs
        print("\nMigrating Digest Logs...")
        digest_logs = sqlite_session.query(DigestLog).all()
        
        for old_log in digest_logs:
            new_log = DigestLog(
                digest_type=old_log.digest_type,
                generated_date=old_log.generated_date,
                item_count=old_log.item_count,
                sent_successfully=old_log.sent_successfully,
                recipients=old_log.recipients
            )
            postgres_session.add(new_log)
        
        postgres_session.commit()
        print(f"  Migrated {len(digest_logs)} digest logs")
        
        # Verify migration
        print("\n" + "="*80)
        print("MIGRATION SUMMARY")
        print("="*80)
        
        pg_tags = postgres_session.query(Tag).count()
        pg_feeds = postgres_session.query(FeedItem).count()
        pg_iocs = postgres_session.query(IOC).count()
        pg_alerts = postgres_session.query(Alert).count()
        pg_logs = postgres_session.query(DigestLog).count()
        
        print(f"Tags:        {pg_tags}")
        print(f"Feed Items:  {pg_feeds}")
        print(f"IOCs:        {pg_iocs}")
        print(f"Alerts:      {pg_alerts}")
        print(f"Digest Logs: {pg_logs}")
        
        print("\n✓ Migration completed successfully!")
        print("\nNext steps:")
        print("1. Test the application with PostgreSQL")
        print("2. Update systemd service to use DATABASE_URL")
        print("3. Keep SQLite backup until confirmed working")
        
        sqlite_session.close()
        postgres_session.close()
        
        return True
        
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    migrate_to_postgres()