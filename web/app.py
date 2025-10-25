from flask import Flask, render_template, jsonify, request
from datetime import datetime, timedelta, UTC
import sys
import os
import atexit

def get_ioc_url_type(ioc_type):
    """Convert IOC type to URL-friendly format"""
    type_map = {
        'ip': 'ip', 'domain': 'domain', 'url': 'url',
        'hash_md5': 'hash-md5', 'hash_sha1': 'hash-sha1', 
        'hash_sha256': 'hash-sha256', 'email': 'email', 
        'file_path': 'file-path'
    }
    return type_map.get(ioc_type, ioc_type)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage.database import db
from storage.models import FeedItem, IOC, Tag, SeverityLevel, IOCType
from sqlalchemy import func, or_

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Initialize database
db.init_db()

# Initialize scheduler (only in production or when explicitly enabled)
if os.environ.get('RAILWAY_ENVIRONMENT') or os.environ.get('ENABLE_SCHEDULER', 'false').lower() == 'true':
    try:
        from scheduler import init_scheduler, shutdown_scheduler
        init_scheduler()
        atexit.register(shutdown_scheduler)
        print("[OK] Collection scheduler initialized")
    except Exception as e:
        print(f"[WARNING] Failed to initialize scheduler: {e}")

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """Get dashboard statistics"""
    session = db.get_session()
    
    try:
        total_items = session.query(FeedItem).count()
        total_iocs = session.query(IOC).count()
        total_cves = session.query(IOC).filter_by(ioc_type=IOCType.CVE).count()
        
        # Severity breakdown
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
        tag_counts = session.query(
            Tag.name,
            Tag.category,
            func.count(FeedItem.id).label('count')
        ).join(FeedItem.tags).group_by(Tag.name, Tag.category).order_by(
            func.count(FeedItem.id).desc()
        ).limit(10).all()
        
        # Top sources
        source_counts = session.query(
            FeedItem.source_name,
            func.count(FeedItem.id).label('count')
        ).group_by(FeedItem.source_name).order_by(
            func.count(FeedItem.id).desc()
        ).all()
        
        return jsonify({
            'total_items': total_items,
            'total_iocs': total_iocs,
            'total_cves': total_cves,
            'recent_count': recent_count,
            'severity_counts': severity_counts,
            'top_tags': [{'name': t[0], 'category': t[1], 'count': t[2]} for t in tag_counts],
            'top_sources': [{'name': s[0], 'count': s[1]} for s in source_counts]
        })
    
    finally:
        session.close()

@app.route('/api/feeds')
def get_feeds():
    """Get feed items with filtering"""
    session = db.get_session()
    
    try:
        # Query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        severity = request.args.get('severity', None)
        tag = request.args.get('tag', None)
        source = request.args.get('source', None)
        search = request.args.get('search', None)
        hours = request.args.get('hours', None, type=int)
        
        # Build query
        query = session.query(FeedItem)
        
        # Apply filters
        if severity:
            query = query.filter(FeedItem.severity == SeverityLevel[severity.upper()])
        
        if tag:
            query = query.join(FeedItem.tags).filter(Tag.name == tag.lower())
        
        if source:
            query = query.filter(FeedItem.source_name == source)
        
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    FeedItem.title.ilike(search_term),
                    FeedItem.content.ilike(search_term)
                )
            )
        
        if hours:
            time_ago = datetime.now(UTC) - timedelta(hours=hours)
            query = query.filter(FeedItem.collected_date >= time_ago)
        
        # Order by relevance score and date
        query = query.order_by(
            FeedItem.relevance_score.desc(),
            FeedItem.collected_date.desc()
        )
        
        # Paginate
        total = query.count()
        items = query.limit(per_page).offset((page - 1) * per_page).all()
        
        # Serialize items
        items_data = []
        for item in items:
            items_data.append({
                'id': item.id,
                'title': item.title,
                'source_name': item.source_name,
                'link': item.link,
                'published_date': item.published_date.isoformat() if item.published_date else None,
                'collected_date': item.collected_date.isoformat(),
                'severity': item.severity.value,
                'relevance_score': item.relevance_score,
                'content_preview': item.content[:200] if item.content else '',
                'tags': [{'name': t.name, 'category': t.category} for t in item.tags[:5]],
                'ioc_count': len(item.iocs)
            })
        
        return jsonify({
            'items': items_data,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })
    
    finally:
        session.close()

@app.route('/api/feed/<int:feed_id>')
def get_feed_detail(feed_id):
    """Get detailed feed item with IOCs"""
    session = db.get_session()
    
    try:
        item = session.query(FeedItem).filter_by(id=feed_id).first()
        
        if not item:
            return jsonify({'error': 'Feed item not found'}), 404
        
        # Serialize full item with IOCs
        item_data = {
            'id': item.id,
            'title': item.title,
            'source_name': item.source_name,
            'source_url': item.source_url,
            'link': item.link,
            'content': item.content,
            'published_date': item.published_date.isoformat() if item.published_date else None,
            'collected_date': item.collected_date.isoformat(),
            'severity': item.severity.value,
            'relevance_score': item.relevance_score,
            'tags': [{'name': t.name, 'category': t.category} for t in item.tags],
            'iocs': [
                {
                    'id': ioc.id,
                    'type': ioc.ioc_type.value,
                    'type_url': get_ioc_url_type(ioc.ioc_type.value),
                    'value': ioc.value,
                    'confidence': ioc.confidence,
                    'context': ioc.context,
                    'verified': ioc.verified,
                    'threat_actor': ioc.threat_actor,
                    'malware_family': ioc.malware_family,
                    'mitre_techniques': ioc.mitre_techniques
                } for ioc in item.iocs
            ]
        }
        
        return jsonify(item_data)
    
    finally:
        session.close()

@app.route('/api/cve/<cve_id>')
def get_cve_detail(cve_id):
    """Get CVE details"""
    
    session = db.get_session()
    
    try:
        ioc = session.query(IOC).filter_by(
            ioc_type=IOCType.CVE,
            value=cve_id.upper()
        ).first()
        
        if not ioc:
            return jsonify({'error': 'CVE not found'}), 404
        
        cve_data = {
            'cve_id': ioc.value,
            'confidence': ioc.confidence,
            'context': ioc.context,
            'verified': ioc.verified,
            'first_seen': ioc.first_seen.isoformat(),
            'threat_actor': ioc.threat_actor,
            'malware_family': ioc.malware_family,
            'cwe_ids': ioc.mitre_techniques,
            'feed_item': {
                'id': ioc.feed_item.id,
                'title': ioc.feed_item.title,
                'source': ioc.feed_item.source_name,
                'link': ioc.feed_item.link,
                'severity': ioc.feed_item.severity.value
            } if ioc.feed_item else None,
            'tags': [{'name': t.name, 'category': t.category} for t in ioc.tags]
        }
        
        return jsonify(cve_data)
    
    finally:
        session.close()

@app.route('/api/ioc/<ioc_type>/<path:value>')
def get_ioc_detail(ioc_type, value):
    session = db.get_session()
    try:
        type_map = {
            'ip': IOCType.IP, 'domain': IOCType.DOMAIN, 'url': IOCType.URL,
            'hash-md5': IOCType.HASH_MD5, 'hash-sha1': IOCType.HASH_SHA1,
            'hash-sha256': IOCType.HASH_SHA256, 'email': IOCType.EMAIL,
            'file-path': IOCType.FILE_PATH
        }
        
        ioc_enum = type_map.get(ioc_type.lower())
        if not ioc_enum:
            return jsonify({'error': 'Invalid IOC type'}), 400
        
        iocs = session.query(IOC).filter_by(ioc_type=ioc_enum, value=value).all()
        if not iocs:
            return jsonify({'error': 'IOC not found'}), 404
        
        primary_ioc = max(iocs, key=lambda x: x.confidence)
        
        feed_items = []
        seen_ids = set()
        for ioc in iocs:
            if ioc.feed_item and ioc.feed_item.id not in seen_ids:
                seen_ids.add(ioc.feed_item.id)
                feed_items.append({
                    'id': ioc.feed_item.id,
                    'title': ioc.feed_item.title,
                    'source': ioc.feed_item.source_name,
                    'link': ioc.feed_item.link,
                    'severity': ioc.feed_item.severity.value,
                    'published_date': ioc.feed_item.published_date.isoformat() if ioc.feed_item.published_date else None,
                    'relevance_score': ioc.feed_item.relevance_score
                })
        
        related_ioc_ids = set()
        for ioc in iocs:
            if ioc.feed_item:
                for related in ioc.feed_item.iocs:
                    if related.value != value:
                        related_ioc_ids.add(related.id)
        
        related_iocs = session.query(IOC).filter(IOC.id.in_(related_ioc_ids)).limit(20).all()
        
        all_tags = set()
        for ioc in iocs:
            for tag in ioc.tags:
                all_tags.add((tag.name, tag.category))
        
        return jsonify({
            'ioc_type': ioc_type,
            'value': value,
            'confidence': primary_ioc.confidence,
            'context': primary_ioc.context,
            'verified': primary_ioc.verified,
            'first_seen': min(i.first_seen for i in iocs).isoformat(),
            'last_seen': max(i.last_seen for i in iocs).isoformat(),
            'threat_actor': primary_ioc.threat_actor,
            'malware_family': primary_ioc.malware_family,
            'mitre_techniques': primary_ioc.mitre_techniques,
            'occurrence_count': len(iocs),
            'feed_items': sorted(feed_items, key=lambda x: x['relevance_score'], reverse=True),
            'related_iocs': [{'type': r.ioc_type.value, 'value': r.value, 'confidence': r.confidence} for r in related_iocs],
            'tags': [{'name': t[0], 'category': t[1]} for t in all_tags]
        })
    finally:
        session.close()

@app.route('/api/tags')
def get_tags():
    """Get all tags with counts"""
    session = db.get_session()
    
    try:
        tags = session.query(
            Tag.name,
            Tag.category,
            func.count(FeedItem.id).label('count')
        ).join(FeedItem.tags).group_by(
            Tag.name, Tag.category
        ).order_by(
            func.count(FeedItem.id).desc()
        ).all()
        
        tags_by_category = {}
        for tag_name, category, count in tags:
            if category not in tags_by_category:
                tags_by_category[category] = []
            tags_by_category[category].append({
                'name': tag_name,
                'count': count
            })
        
        return jsonify(tags_by_category)
    
    finally:
        session.close()

@app.route('/api/timeline')
def get_timeline():
    """Get timeline data for visualization"""
    session = db.get_session()
    
    try:
        days = request.args.get('days', 30, type=int)
        start_date = datetime.now(UTC) - timedelta(days=days)
        
        # Group by date and severity
        timeline_data = session.query(
            func.date(FeedItem.collected_date).label('date'),
            FeedItem.severity,
            func.count(FeedItem.id).label('count')
        ).filter(
            FeedItem.collected_date >= start_date
        ).group_by(
            func.date(FeedItem.collected_date),
            FeedItem.severity
        ).order_by(
            func.date(FeedItem.collected_date)
        ).all()
        
        # Format for frontend
        timeline = {}
        for date, severity, count in timeline_data:
            date_str = str(date)
            if date_str not in timeline:
                timeline[date_str] = {}
            timeline[date_str][severity.value] = count
        
        return jsonify(timeline)
    finally:
        session.close()
    
@app.route('/cve/<cve_id>')
def cve_page(cve_id):
        """CVE detail page"""
        return render_template('cve_detail.html', cve_id=cve_id)

@app.route('/ioc/<ioc_type>/<path:value>')
def ioc_page(ioc_type, value):
    return render_template('ioc_detail.html', ioc_type=ioc_type, value=value)

@app.route('/timeline')
def timeline_page():
    """Timeline page"""
    return render_template('timeline.html')

@app.route('/feeds')
def feeds_page():
    """Feeds page"""
    return render_template('feeds.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)