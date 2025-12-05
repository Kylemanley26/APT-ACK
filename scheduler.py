"""
APT-ACK Scheduled Task Runner
Runs collection tasks at regular intervals within the web application
"""
import os
import logging
from datetime import datetime, UTC
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

# Import collection orchestrator
from scripts.run_collection import ThreatIntelOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

class CollectionScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.orchestrator = ThreatIntelOrchestrator()
    
    def run_collection_job(self):
        """Run the full collection pipeline"""
        try:
            logger.info("Starting scheduled collection job...")
            
            # Run collection (skip NVD by default to avoid rate limits)
            skip_nvd = os.environ.get('SKIP_NVD', 'true').lower() == 'true'
            skip_claude = os.environ.get('SKIP_CLAUDE', 'false').lower() == 'true'
            claude_limit = int(os.environ.get('CLAUDE_LIMIT', '50'))
            
            self.orchestrator.run_full_pipeline(
                skip_nvd=skip_nvd,
                skip_claude=skip_claude,
                claude_limit=claude_limit
            )
            
            logger.info("Scheduled collection job completed successfully")
            
        except Exception as e:
            logger.error(f"Scheduled collection job failed: {e}")
    
    def start(self):
        """Start the scheduler with configured jobs"""
        
        # Get schedule from environment (default: every 6 hours)
        schedule = os.environ.get('COLLECTION_SCHEDULE', '0 */6 * * *')  # Cron format
        
        logger.info(f"Starting collection scheduler with schedule: {schedule}")
        
        # Add job with cron trigger
        self.scheduler.add_job(
            self.run_collection_job,
            trigger=CronTrigger.from_crontab(schedule),
            id='collection_job',
            name='Threat Intelligence Collection',
            replace_existing=True
        )
        
        # Also run immediately on startup (optional)
        if os.environ.get('RUN_ON_STARTUP', 'false').lower() == 'true':
            logger.info("Running collection on startup...")
            self.run_collection_job()
        
        self.scheduler.start()
        logger.info("Collection scheduler started successfully")
    
    def shutdown(self):
        """Gracefully shutdown the scheduler"""
        logger.info("Shutting down scheduler...")
        self.scheduler.shutdown()

# Global scheduler instance
scheduler_instance = None

def init_scheduler():
    """Initialize and start the scheduler"""
    global scheduler_instance
    
    if scheduler_instance is None:
        scheduler_instance = CollectionScheduler()
        scheduler_instance.start()
    
    return scheduler_instance

def shutdown_scheduler():
    """Shutdown the scheduler"""
    global scheduler_instance
    
    if scheduler_instance:
        scheduler_instance.shutdown()
        scheduler_instance = None
