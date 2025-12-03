from datetime import datetime, UTC
from typing import List, Optional
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey, Table, Boolean, Enum
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
import enum


class Base(DeclarativeBase):
    pass

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

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    link: Mapped[Optional[str]] = mapped_column(String(512), unique=True, index=True, nullable=True)
    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime, index=True, nullable=True)
    collected_date: Mapped[Optional[datetime]] = mapped_column(DateTime, default=lambda: datetime.now(UTC), index=True)

    # Scoring and classification
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), default=SeverityLevel.INFO, index=True)
    relevance_score: Mapped[Optional[float]] = mapped_column(Float, default=0.0)

    # Metadata
    raw_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    processed: Mapped[Optional[bool]] = mapped_column(Boolean, default=False, index=True)

    # Relationships
    iocs = relationship('IOC', back_populates='feed_item', cascade='all, delete-orphan')
    tags = relationship('Tag', secondary=feed_tags, back_populates='feed_items')
    
    def __repr__(self):
        return f"<FeedItem(id={self.id}, source={self.source_name}, title={self.title[:50]})>"

class IOC(Base):
    __tablename__ = 'iocs'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feed_item_id: Mapped[int] = mapped_column(Integer, ForeignKey('feed_items.id'), nullable=False, index=True)

    ioc_type: Mapped[IOCType] = mapped_column(Enum(IOCType), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Confidence and validation
    confidence: Mapped[Optional[float]] = mapped_column(Float, default=0.5)
    verified: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, default=lambda: datetime.now(UTC), index=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Enrichment data
    threat_actor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    malware_family: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mitre_techniques: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # CVSS Scoring (from NVD enrichment)
    cvss_v3_score: Mapped[Optional[float]] = mapped_column(Float, index=True, nullable=True)
    cvss_v3_severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cvss_v3_vector: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cvss_v2_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_v2_severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Relationships
    feed_item = relationship('FeedItem', back_populates='iocs')
    tags = relationship('Tag', secondary=ioc_tags, back_populates='iocs')
    
    def __repr__(self):
        return f"<IOC(type={self.ioc_type.value}, value={self.value})>"

class Tag(Base):
    __tablename__ = 'tags'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    auto_generated: Mapped[Optional[bool]] = mapped_column(Boolean, default=True)
    created_date: Mapped[Optional[datetime]] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Relationships
    feed_items = relationship('FeedItem', secondary=feed_tags, back_populates='tags')
    iocs = relationship('IOC', secondary=ioc_tags, back_populates='tags')

    def __repr__(self):
        return f"<Tag(name={self.name}, category={self.category})>"


class Alert(Base):
    __tablename__ = 'alerts'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feed_item_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('feed_items.id'), index=True, nullable=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), nullable=False, index=True)

    created_date: Mapped[Optional[datetime]] = mapped_column(DateTime, default=lambda: datetime.now(UTC), index=True)
    acknowledged: Mapped[Optional[bool]] = mapped_column(Boolean, default=False, index=True)
    dismissed: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)

    # Digest tracking
    included_in_digest: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    digest_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def __repr__(self):
        return f"<Alert(id={self.id}, severity={self.severity.value}, title={self.title[:50]})>"


class DigestLog(Base):
    __tablename__ = 'digest_logs'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    digest_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    generated_date: Mapped[Optional[datetime]] = mapped_column(DateTime, default=lambda: datetime.now(UTC), index=True)
    item_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    sent_successfully: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    recipients: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self):
        return f"<DigestLog(type={self.digest_type}, date={self.generated_date})>"