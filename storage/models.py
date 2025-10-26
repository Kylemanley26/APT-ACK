from datetime import datetime, UTC
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey, Table, Boolean, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()

# Association table for many-to-many relationship between FeedItems and Tags
feed_tags = Table(
    'feed_tags',
    Base.metadata,
    Column('feed_item_id', Integer, ForeignKey('feed_items.id')),
    Column('tag_id', Integer, ForeignKey('tags.id'))
)

# Association table for IOCs and Tags
ioc_tags = Table(
    'ioc_tags',
    Base.metadata,
    Column('ioc_id', Integer, ForeignKey('iocs.id')),
    Column('tag_id', Integer, ForeignKey('tags.id'))
)

class SeverityLevel(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IOCType(enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    CVE = "cve"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    FILE_PATH = "file_path"

class FeedItem(Base):
    __tablename__ = 'feed_items'
    
    id = Column(Integer, primary_key=True)
    source_name = Column(String(255), nullable=False, index=True)
    source_url = Column(String(512))
    title = Column(String(512), nullable=False)
    content = Column(Text)
    link = Column(String(512), unique=True, index=True)
    published_date = Column(DateTime, index=True)
    collected_date = Column(DateTime, default=lambda: datetime.now(UTC), index=True)
    
    # Scoring and classification
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.INFO, index=True)
    relevance_score = Column(Float, default=0.0)
    
    # Metadata
    raw_content = Column(Text)
    processed = Column(Boolean, default=False, index=True)
    
    # Relationships
    iocs = relationship('IOC', back_populates='feed_item', cascade='all, delete-orphan')
    tags = relationship('Tag', secondary=feed_tags, back_populates='feed_items')
    
    def __repr__(self):
        return f"<FeedItem(id={self.id}, source={self.source_name}, title={self.title[:50]})>"

class IOC(Base):
    __tablename__ = 'iocs'
    
    id = Column(Integer, primary_key=True)
    feed_item_id = Column(Integer, ForeignKey('feed_items.id'), nullable=False, index=True)
    
    ioc_type = Column(Enum(IOCType), nullable=False, index=True)
    value = Column(String(512), nullable=False, index=True)
    context = Column(Text)
    
    # Confidence and validation
    confidence = Column(Float, default=0.5)
    verified = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=lambda: datetime.now(UTC), index=True)
    last_seen = Column(DateTime, default=lambda: datetime.now(UTC))
    
    # Enrichment data
    threat_actor = Column(String(255))
    malware_family = Column(String(255))
    mitre_techniques = Column(Text)

    # CVSS Scoring (from NVD enrichment)
    cvss_v3_score = Column(Float, index=True)              # 0.0-10.0 base score
    cvss_v3_severity = Column(String(20))                  # CRITICAL/HIGH/MEDIUM/LOW
    cvss_v3_vector = Column(String(100))                   # Full CVSS v3 vector string
    cvss_v2_score = Column(Float)                          # Legacy CVSS v2 (fallback)
    cvss_v2_severity = Column(String(20))                  # Legacy severity

    # Relationships
    feed_item = relationship('FeedItem', back_populates='iocs')
    tags = relationship('Tag', secondary=ioc_tags, back_populates='iocs')
    
    def __repr__(self):
        return f"<IOC(type={self.ioc_type.value}, value={self.value})>"

class Tag(Base):
    __tablename__ = 'tags'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    category = Column(String(100))
    auto_generated = Column(Boolean, default=True)
    created_date = Column(DateTime, default=lambda: datetime.now(UTC))
    
    # Relationships
    feed_items = relationship('FeedItem', secondary=feed_tags, back_populates='tags')
    iocs = relationship('IOC', secondary=ioc_tags, back_populates='tags')
    
    def __repr__(self):
        return f"<Tag(name={self.name}, category={self.category})>"

class Alert(Base):
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    feed_item_id = Column(Integer, ForeignKey('feed_items.id'), index=True)
    
    title = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(Enum(SeverityLevel), nullable=False, index=True)
    
    created_date = Column(DateTime, default=lambda: datetime.now(UTC), index=True)
    acknowledged = Column(Boolean, default=False, index=True)
    dismissed = Column(Boolean, default=False)
    
    # Digest tracking
    included_in_digest = Column(Boolean, default=False)
    digest_date = Column(DateTime)
    
    def __repr__(self):
        return f"<Alert(id={self.id}, severity={self.severity.value}, title={self.title[:50]})>"

class DigestLog(Base):
    __tablename__ = 'digest_logs'
    
    id = Column(Integer, primary_key=True)
    digest_type = Column(String(50))
    generated_date = Column(DateTime, default=lambda: datetime.now(UTC), index=True)
    item_count = Column(Integer)
    sent_successfully = Column(Boolean, default=False)
    recipients = Column(Text)
    
    def __repr__(self):
        return f"<DigestLog(type={self.digest_type}, date={self.generated_date})>"