"""CVE Fetch Agent - Responsible for harvesting vulnerability data."""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

from scripts.agents.base_agent import BaseAgent
from scripts.harvest.orchestrator import HarvestOrchestrator
from scripts.processing.cache_manager import CacheManager


class CVEFetchAgent(BaseAgent):
    """Agent responsible for fetching and processing CVE data."""
    
    def __init__(self, cache_dir: Path = None):
        super().__init__("cve_fetch", cache_dir)
        self.orchestrator = None
        self.cache_manager = None
        
        # Configuration
        self.config = {
            'days_back': 30,
            'adaptive': True,
            'min_risk_score': 70,
            'sources': ['cvelist', 'github_advisory'],
            'max_cves_per_run': 1000,
            'cache_ttl_days': 10
        }
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute CVE fetching and processing.
        
        Returns:
            Results from CVE fetch operation
        """
        # Initialize components if needed
        if not self.orchestrator:
            self.orchestrator = HarvestOrchestrator()
        
        if not self.cache_manager:
            cache_db_path = self.cache_dir / "vulns.db"
            self.cache_manager = CacheManager(db_path=str(cache_db_path))
        
        # Override config with kwargs
        config = {**self.config, **kwargs}
        
        results = {
            'started_at': datetime.now(timezone.utc).isoformat(),
            'config': config,
            'sources': {},
            'metrics': {},
            'success': True,
            'errors': []
        }
        
        try:
            # Determine date range for harvesting
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=config['days_back'])
            
            if config.get('adaptive'):
                # Check recent harvest metrics to optimize date range
                recent_metrics = self.cache_manager.get_recent_harvest_metrics(days=7)
                if recent_metrics:
                    # Estimate CVE rate and adjust date range
                    avg_cves_per_day = sum(m['vulnerability_count'] / m['days_covered'] 
                                         for m in recent_metrics) / len(recent_metrics)
                    
                    # If rate is high, reduce days back to stay under max_cves_per_run
                    if avg_cves_per_day * config['days_back'] > config['max_cves_per_run']:
                        optimal_days = int(config['max_cves_per_run'] / avg_cves_per_day)
                        config['days_back'] = max(7, optimal_days)  # At least 7 days
                        start_date = end_date - timedelta(days=config['days_back'])
                        
                        self.logger.info(
                            "Adjusted date range based on CVE rate",
                            avg_cves_per_day=avg_cves_per_day,
                            adjusted_days_back=config['days_back']
                        )
            
            self.logger.info(
                "Starting CVE harvest",
                date_range=f"{start_date.date()} to {end_date.date()}",
                days_back=config['days_back']
            )
            
            # Execute harvest
            harvest_results = await asyncio.to_thread(
                self.orchestrator.harvest_vulnerabilities,
                from_date=start_date,
                to_date=end_date,
                cache_dir=self.cache_dir
            )
            
            # Process and filter results
            vulnerabilities = harvest_results.vulnerabilities
            
            # Apply risk score filtering
            if config.get('min_risk_score'):
                filtered_vulns = [
                    v for v in vulnerabilities 
                    if v.risk_score >= config['min_risk_score']
                ]
                
                self.logger.info(
                    "Applied risk score filtering",
                    original_count=len(vulnerabilities),
                    filtered_count=len(filtered_vulns),
                    min_risk_score=config['min_risk_score']
                )
                
                vulnerabilities = filtered_vulns
            
            # Cache results
            from scripts.models import VulnerabilityBatch
            
            batch = VulnerabilityBatch(
                vulnerabilities=vulnerabilities,
                metadata={
                    'date_range': f"{start_date.date()} to {end_date.date()}",
                    'sources': config['sources'],
                    'config': config,
                    'harvest_timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            
            await asyncio.to_thread(self.cache_manager.cache_batch, batch)
            
            # Calculate metrics
            results['metrics'] = {
                'vulnerabilities_fetched': len(vulnerabilities),
                'date_range_days': config['days_back'],
                'risk_score_threshold': config.get('min_risk_score', 0),
                'cache_size_mb': self.cache_manager.get_cache_stats()['cache_size_mb'],
                'sources_used': len(config['sources'])
            }
            
            # Log severity distribution
            from collections import Counter
            severity_dist = Counter(v.severity.value for v in vulnerabilities)
            results['metrics']['severity_distribution'] = dict(severity_dist)
            
            self.logger.info(
                "CVE fetch completed successfully",
                vulnerabilities_count=len(vulnerabilities),
                severity_distribution=dict(severity_dist)
            )
            
            results['completed_at'] = datetime.now(timezone.utc).isoformat()
            return results
            
        except Exception as e:
            results['success'] = False
            results['errors'].append(str(e))
            results['completed_at'] = datetime.now(timezone.utc).isoformat()
            
            self.logger.error("CVE fetch failed", error=str(e))
            raise
    
    def get_dependencies(self) -> Set[str]:
        """Get dependencies for change detection."""
        return {
            'scripts/harvest/',
            'scripts/processing/cache_manager.py',
            'scripts/models.py',
            '.cache/vulns.db',
            'scripts/main.py'
        }
    
    async def get_fetch_stats(self) -> Dict[str, Any]:
        """Get detailed fetch statistics.
        
        Returns:
            Detailed statistics about CVE fetching
        """
        if not self.cache_manager:
            cache_db_path = self.cache_dir / "vulns.db"
            self.cache_manager = CacheManager(db_path=str(cache_db_path))
        
        stats = await asyncio.to_thread(self.cache_manager.get_cache_stats)
        harvest_history = await asyncio.to_thread(self.cache_manager.get_harvest_history, 10)
        
        return {
            'cache_stats': stats,
            'recent_harvests': harvest_history,
            'agent_status': self.get_status(),
            'config': self.config
        }
    
    async def cleanup_cache(self) -> Dict[str, Any]:
        """Clean up expired cache entries.
        
        Returns:
            Cleanup results
        """
        if not self.cache_manager:
            cache_db_path = self.cache_dir / "vulns.db"
            self.cache_manager = CacheManager(db_path=str(cache_db_path))
        
        try:
            expired_count = await asyncio.to_thread(self.cache_manager.cleanup_expired)
            
            self.logger.info("Cache cleanup completed", expired_entries=expired_count)
            
            return {
                'success': True,
                'expired_entries_removed': expired_count,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self.logger.error("Cache cleanup failed", error=str(e))
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }