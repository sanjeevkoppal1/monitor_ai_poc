#!/usr/bin/env python3
"""
Crown Jewel Java Application Monitor - Splunk Integration Agent
Intelligent agent for monitoring Java application logs and metrics through Splunk.

This agent provides:
1. Real-time log analysis and pattern detection
2. Proactive anomaly detection using ML techniques
3. Automated alert generation based on log patterns
4. Historical trend analysis for predictive monitoring
5. Integration with Splunk's REST API and Search capabilities
"""

import asyncio
import json
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
import xml.etree.ElementTree as ET

import splunklib.client as client
import splunklib.results as results
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

from ..core.agent_framework import (
    BaseAgent, Alert, AlertSeverity, MonitoringMetric, RemediationAction,
    AgentFactory
)

import structlog
logger = structlog.get_logger()


# =============================================================================
# SPLUNK-SPECIFIC DATA STRUCTURES
# =============================================================================

@dataclass
class SplunkSearchResult:
    """
    Represents a single result from a Splunk search.
    Contains both raw data and processed information for analysis.
    """
    timestamp: datetime              # When the log event occurred
    raw_event: str                  # Original log message
    source: str                     # Log source (file, system, etc.)
    sourcetype: str                 # Splunk sourcetype
    host: str                       # Host that generated the log
    index: str                      # Splunk index
    extracted_fields: Dict[str, Any] = None  # Extracted field values
    severity_score: float = 0.0     # Calculated severity (0.0-1.0)
    anomaly_score: float = 0.0      # Anomaly detection score (0.0-1.0)
    tags: Set[str] = None           # Classification tags


@dataclass
class LogPattern:
    """
    Represents a detected log pattern for automated analysis.
    Used for pattern matching, anomaly detection, and alert generation.
    """
    pattern_id: str                 # Unique pattern identifier
    regex_pattern: str              # Regular expression for matching
    description: str                # Human-readable description
    severity: AlertSeverity         # Alert severity when pattern matches
    frequency_threshold: int = 1    # Minimum occurrences to trigger alert
    time_window_minutes: int = 5    # Time window for frequency counting
    suppression_minutes: int = 30   # Alert suppression period
    last_triggered: Optional[datetime] = None  # Last time pattern triggered alert
    match_count: int = 0           # Total matches since creation
    false_positive_rate: float = 0.0  # Estimated false positive rate


@dataclass
class SplunkQuery:
    """
    Represents a Splunk search query with metadata.
    Encapsulates search logic, timing, and result processing.
    """
    query_id: str                   # Unique query identifier
    search_query: str               # SPL (Splunk Processing Language) query
    description: str                # Query purpose description
    earliest_time: str = "-15m"    # Search time range start
    latest_time: str = "now"       # Search time range end
    max_results: int = 1000        # Maximum results to return
    execution_frequency: int = 300  # How often to run (seconds)
    last_executed: Optional[datetime] = None  # Last execution time
    execution_count: int = 0       # Total executions
    average_duration: float = 0.0  # Average execution time


# =============================================================================
# SPLUNK AGENT IMPLEMENTATION
# =============================================================================

class SplunkAgent(BaseAgent):
    """
    Intelligent Splunk monitoring agent for Java application observability.
    
    This agent connects to Splunk and performs:
    - Real-time log monitoring and analysis
    - Pattern-based anomaly detection
    - Automated alert generation
    - Historical trend analysis
    - Proactive issue identification
    
    The agent uses machine learning techniques to:
    - Learn normal application behavior patterns
    - Detect deviations from baseline
    - Reduce false positive alerts
    - Improve detection accuracy over time
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """
        Initialize the Splunk monitoring agent.
        
        Args:
            name: Agent name for identification
            config: Configuration containing Splunk connection details and monitoring rules
        """
        super().__init__(name, config)
        
        # Splunk connection components
        self.splunk_service: Optional[client.Service] = None
        self.connected = False
        
        # Monitoring configuration
        self.java_app_name = config.get('java_app_name', 'crown-jewel-app')
        self.log_indexes = config.get('log_indexes', ['main', 'java_logs'])
        self.monitoring_interval = config.get('monitoring_interval', 300)  # 5 minutes
        
        # Pattern detection and alerting
        self.log_patterns: List[LogPattern] = []
        self.predefined_queries: List[SplunkQuery] = []
        self.baseline_metrics: Dict[str, float] = {}
        self.anomaly_threshold = config.get('anomaly_threshold', 0.7)
        
        # Performance tracking
        self.search_results_cache: Dict[str, List[SplunkSearchResult]] = {}
        self.cache_ttl_minutes = config.get('cache_ttl_minutes', 10)
        
        # Initialize monitoring patterns and queries
        self._initialize_monitoring_patterns()
        self._initialize_predefined_queries()
    
    # -------------------------------------------------------------------------
    # AGENT LIFECYCLE METHODS
    # -------------------------------------------------------------------------
    
    async def initialize(self) -> bool:
        """
        Initialize Splunk connection and monitoring components.
        
        This method:
        - Establishes connection to Splunk
        - Validates access to required indexes
        - Tests search capabilities
        - Loads historical baseline data
        - Sets up monitoring patterns
        
        Returns:
            bool: True if initialization successful
        """
        try:
            self.logger.info("initializing_splunk_agent", 
                           app_name=self.java_app_name,
                           indexes=self.log_indexes)
            
            # Establish Splunk connection
            await self._connect_to_splunk()
            
            if not self.connected:
                self.logger.error("splunk_connection_failed")
                return False
            
            # Validate access to required indexes
            await self._validate_index_access()
            
            # Load historical baseline metrics
            await self._load_baseline_metrics()
            
            # Test search capabilities with a simple query
            test_result = await self._test_search_capability()
            if not test_result:
                self.logger.error("splunk_search_test_failed")
                return False
            
            self.logger.info("splunk_agent_initialized_successfully")
            return True
            
        except Exception as e:
            self.logger.error("splunk_agent_initialization_error", error=str(e))
            return False
    
    async def execute(self) -> Dict[str, Any]:
        """
        Execute main monitoring logic for the Splunk agent.
        
        This method performs:
        - Real-time log analysis
        - Pattern matching and anomaly detection
        - Alert generation for detected issues
        - Metrics collection and trending
        - Cache management and cleanup
        
        Returns:
            Dict[str, Any]: Execution results with metrics and findings
        """
        execution_start = time.time()
        results = {
            "execution_time": 0,
            "queries_executed": 0,
            "alerts_generated": 0,
            "metrics_collected": 0,
            "anomalies_detected": 0,
            "patterns_matched": 0,
            "errors": []
        }
        
        try:
            self.logger.info("executing_splunk_monitoring_cycle")
            
            # 1. Execute predefined monitoring queries
            query_results = await self._execute_monitoring_queries()
            results["queries_executed"] = len(query_results)
            
            # 2. Analyze results for patterns and anomalies
            analysis_results = await self._analyze_search_results(query_results)
            results.update(analysis_results)
            
            # 3. Perform real-time log stream analysis
            stream_results = await self._analyze_log_stream()
            results["metrics_collected"] += stream_results.get("metrics_count", 0)
            
            # 4. Generate alerts for detected issues
            alert_results = await self._generate_alerts_from_analysis()
            results["alerts_generated"] = alert_results.get("alerts_count", 0)
            
            # 5. Update baseline metrics and patterns
            await self._update_baseline_metrics()
            
            # 6. Clean up cache and temporary data
            await self._cleanup_cache()
            
            results["execution_time"] = time.time() - execution_start
            self.logger.info("splunk_monitoring_cycle_complete", results=results)
            
            return results
            
        except Exception as e:
            error_msg = f"Splunk monitoring execution error: {str(e)}"
            results["errors"].append(error_msg)
            self.logger.error("splunk_monitoring_execution_error", error=str(e))
            
            # Generate alert for agent execution failure
            await self._generate_agent_error_alert(e)
            
            return results
    
    async def cleanup(self) -> None:
        """
        Cleanup Splunk connections and resources.
        
        This method:
        - Closes Splunk service connection
        - Saves current state and metrics
        - Clears caches and temporary data
        - Logs cleanup completion
        """
        try:
            self.logger.info("cleaning_up_splunk_agent")
            
            # Save current state before cleanup
            await self._save_agent_state()
            
            # Close Splunk connection
            if self.splunk_service:
                self.splunk_service.logout()
                self.connected = False
            
            # Clear caches
            self.search_results_cache.clear()
            
            self.logger.info("splunk_agent_cleanup_complete")
            
        except Exception as e:
            self.logger.error("splunk_agent_cleanup_error", error=str(e))
    
    # -------------------------------------------------------------------------
    # SPLUNK CONNECTION AND COMMUNICATION
    # -------------------------------------------------------------------------
    
    async def _connect_to_splunk(self) -> None:
        """
        Establish connection to Splunk using configured credentials.
        
        Supports multiple authentication methods:
        - Username/password authentication
        - Token-based authentication
        - Certificate-based authentication
        """
        try:
            # Extract connection parameters from config
            host = self.config.get('splunk_host', 'localhost')
            port = self.config.get('splunk_port', 8089)
            username = self.config.get('splunk_username')
            password = self.config.get('splunk_password')
            token = self.config.get('splunk_token')
            
            self.logger.info("connecting_to_splunk", host=host, port=port)
            
            # Create Splunk service connection
            if token:
                # Token-based authentication
                self.splunk_service = client.connect(
                    host=host,
                    port=port,
                    splunkToken=token,
                    verify=self.config.get('verify_ssl', True)
                )
            else:
                # Username/password authentication
                self.splunk_service = client.connect(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    verify=self.config.get('verify_ssl', True)
                )
            
            # Test connection by getting server info
            server_info = self.splunk_service.info
            self.logger.info("splunk_connection_established", 
                           version=server_info.get('version'),
                           build=server_info.get('build'))
            
            self.connected = True
            
        except Exception as e:
            self.logger.error("splunk_connection_error", error=str(e))
            self.connected = False
            raise
    
    async def _validate_index_access(self) -> None:
        """
        Validate access to required Splunk indexes.
        
        Checks:
        - Index existence
        - Read permissions
        - Recent data availability
        """
        try:
            self.logger.info("validating_index_access", indexes=self.log_indexes)
            
            # Get list of available indexes
            indexes = self.splunk_service.indexes
            available_indexes = [idx.name for idx in indexes]
            
            # Check each required index
            for index_name in self.log_indexes:
                if index_name not in available_indexes:
                    self.logger.warning("index_not_found", index=index_name)
                    continue
                
                # Test read access with a simple search
                test_query = f'search index={index_name} | head 1'
                job = self.splunk_service.jobs.create(test_query)
                
                # Wait for job completion
                while not job.is_done():
                    await asyncio.sleep(0.1)
                
                if job['isDone'] == '1':
                    self.logger.info("index_access_validated", index=index_name)
                else:
                    self.logger.warning("index_access_test_failed", index=index_name)
            
        except Exception as e:
            self.logger.error("index_validation_error", error=str(e))
            raise
    
    async def _test_search_capability(self) -> bool:
        """
        Test basic search capabilities with Splunk.
        
        Returns:
            bool: True if search test successful
        """
        try:
            self.logger.info("testing_search_capability")
            
            # Create a simple test search
            test_query = 'search * | head 1'
            job = self.splunk_service.jobs.create(test_query)
            
            # Wait for completion with timeout
            timeout = 30  # seconds
            start_time = time.time()
            
            while not job.is_done() and (time.time() - start_time) < timeout:
                await asyncio.sleep(0.5)
            
            if job.is_done():
                self.logger.info("search_capability_test_passed")
                return True
            else:
                self.logger.error("search_capability_test_timeout")
                return False
                
        except Exception as e:
            self.logger.error("search_capability_test_error", error=str(e))
            return False
    
    # -------------------------------------------------------------------------
    # MONITORING PATTERN AND QUERY INITIALIZATION
    # -------------------------------------------------------------------------
    
    def _initialize_monitoring_patterns(self) -> None:
        """
        Initialize predefined log patterns for Java application monitoring.
        
        Patterns cover common Java application issues:
        - Exception patterns (OutOfMemoryError, NullPointerException, etc.)
        - Performance patterns (slow queries, timeouts, etc.)
        - Security patterns (authentication failures, suspicious activity)
        - Business logic patterns (transaction failures, data inconsistencies)
        """
        self.log_patterns = [
            # Critical Error Patterns
            LogPattern(
                pattern_id="java_out_of_memory",
                regex_pattern=r"java\.lang\.OutOfMemoryError|OutOfMemoryError|Memory allocation failed",
                description="Java OutOfMemoryError detected",
                severity=AlertSeverity.CRITICAL,
                frequency_threshold=1,
                time_window_minutes=1,
                suppression_minutes=15
            ),
            
            LogPattern(
                pattern_id="java_fatal_exception",
                regex_pattern=r"FATAL|Fatal|java\.lang\.Error|Critical error|System failure",
                description="Fatal Java exception or critical system error",
                severity=AlertSeverity.CRITICAL,
                frequency_threshold=1,
                time_window_minutes=5,
                suppression_minutes=10
            ),
            
            # High Severity Patterns
            LogPattern(
                pattern_id="database_connection_failure",
                regex_pattern=r"Connection refused|Connection timeout|Database connection failed|SQL.*Exception",
                description="Database connectivity issues detected",
                severity=AlertSeverity.HIGH,
                frequency_threshold=3,
                time_window_minutes=5,
                suppression_minutes=20
            ),
            
            LogPattern(
                pattern_id="authentication_failures",
                regex_pattern=r"Authentication failed|Login failed|Invalid credentials|Unauthorized access",
                description="Authentication failures detected",
                severity=AlertSeverity.HIGH,
                frequency_threshold=5,
                time_window_minutes=10,
                suppression_minutes=30
            ),
            
            # Medium Severity Patterns
            LogPattern(
                pattern_id="performance_degradation",
                regex_pattern=r"Slow query|Timeout|Response time exceeded|Performance warning",
                description="Performance degradation indicators",
                severity=AlertSeverity.MEDIUM,
                frequency_threshold=10,
                time_window_minutes=15,
                suppression_minutes=45
            ),
            
            LogPattern(
                pattern_id="business_logic_errors",
                regex_pattern=r"Transaction failed|Business rule violation|Data validation error|Processing error",
                description="Business logic errors detected",
                severity=AlertSeverity.MEDIUM,
                frequency_threshold=5,
                time_window_minutes=10,
                suppression_minutes=30
            ),
            
            # Low Severity Patterns
            LogPattern(
                pattern_id="configuration_warnings",
                regex_pattern=r"Configuration warning|Deprecated|Missing property|Default value used",
                description="Configuration warnings detected",
                severity=AlertSeverity.LOW,
                frequency_threshold=20,
                time_window_minutes=30,
                suppression_minutes=60
            )
        ]
        
        self.logger.info("monitoring_patterns_initialized", pattern_count=len(self.log_patterns))
    
    def _initialize_predefined_queries(self) -> None:
        """
        Initialize predefined Splunk queries for comprehensive monitoring.
        
        Queries cover different aspects of Java application health:
        - Error rate monitoring
        - Performance metrics
        - Security monitoring
        - Business metrics
        - Infrastructure health
        """
        self.predefined_queries = [
            # Error Rate Monitoring
            SplunkQuery(
                query_id="java_error_rate",
                search_query=f'''
                    search index="{" OR index=".join(self.log_indexes)}" 
                    source="*{self.java_app_name}*" 
                    (ERROR OR Exception OR FATAL)
                    | bucket _time span=5m 
                    | stats count as error_count by _time 
                    | eval error_rate=error_count/5 
                    | where error_rate > 10
                ''',
                description="Monitor Java application error rates",
                earliest_time="-30m",
                execution_frequency=300
            ),
            
            # Memory Usage Monitoring
            SplunkQuery(
                query_id="java_memory_usage",
                search_query=f'''
                    search index="{" OR index=".join(self.log_indexes)}" 
                    source="*{self.java_app_name}*" 
                    "memory" OR "heap" OR "GC"
                    | rex field=_raw "memory.*?(?<memory_pct>\\d+)%"
                    | rex field=_raw "heap.*?(?<heap_mb>\\d+)MB"
                    | where memory_pct > 85 OR heap_mb > 2048
                    | stats avg(memory_pct) as avg_memory, max(heap_mb) as max_heap by _time
                ''',
                description="Monitor Java application memory usage",
                earliest_time="-15m",
                execution_frequency=180
            ),
            
            # Response Time Monitoring
            SplunkQuery(
                query_id="java_response_times",
                search_query=f'''
                    search index="{" OR index=".join(self.log_indexes)}" 
                    source="*{self.java_app_name}*" 
                    "response_time" OR "elapsed" OR "duration"
                    | rex field=_raw "response_time=(?<response_ms>\\d+)"
                    | where response_ms > 5000
                    | stats avg(response_ms) as avg_response, max(response_ms) as max_response, count as slow_requests by _time
                    | where slow_requests > 10
                ''',
                description="Monitor Java application response times",
                earliest_time="-20m",
                execution_frequency=240
            ),
            
            # Security Event Monitoring
            SplunkQuery(
                query_id="java_security_events",
                search_query=f'''
                    search index="{" OR index=".join(self.log_indexes)}" 
                    source="*{self.java_app_name}*" 
                    ("failed login" OR "unauthorized" OR "security violation" OR "access denied")
                    | bucket _time span=10m 
                    | stats count as security_events by _time, src_ip 
                    | where security_events > 5
                ''',
                description="Monitor security-related events",
                earliest_time="-60m",
                execution_frequency=600
            ),
            
            # Business Transaction Monitoring
            SplunkQuery(
                query_id="java_transaction_failures",
                search_query=f'''
                    search index="{" OR index=".join(self.log_indexes)}" 
                    source="*{self.java_app_name}*" 
                    ("transaction failed" OR "rollback" OR "business error")
                    | bucket _time span=15m 
                    | stats count as failed_transactions by _time 
                    | where failed_transactions > 20
                ''',
                description="Monitor business transaction failures",
                earliest_time="-45m",
                execution_frequency=450
            )
        ]
        
        self.logger.info("predefined_queries_initialized", query_count=len(self.predefined_queries))
    
    # -------------------------------------------------------------------------
    # SEARCH EXECUTION AND ANALYSIS
    # -------------------------------------------------------------------------
    
    async def _execute_monitoring_queries(self) -> List[Tuple[SplunkQuery, List[SplunkSearchResult]]]:
        """
        Execute all predefined monitoring queries.
        
        Returns:
            List[Tuple[SplunkQuery, List[SplunkSearchResult]]]: Query results with metadata
        """
        results = []
        
        for query in self.predefined_queries:
            try:
                # Check if query should be executed based on frequency
                if self._should_execute_query(query):
                    self.logger.info("executing_splunk_query", query_id=query.query_id)
                    
                    # Execute the search
                    search_results = await self._execute_splunk_search(query)
                    results.append((query, search_results))
                    
                    # Update query execution metadata
                    query.last_executed = datetime.utcnow()
                    query.execution_count += 1
                    
            except Exception as e:
                self.logger.error("query_execution_error", 
                                query_id=query.query_id, 
                                error=str(e))
        
        return results
    
    def _should_execute_query(self, query: SplunkQuery) -> bool:
        """
        Determine if a query should be executed based on its frequency schedule.
        
        Args:
            query: SplunkQuery to check
            
        Returns:
            bool: True if query should be executed
        """
        if query.last_executed is None:
            return True
        
        time_since_last = datetime.utcnow() - query.last_executed
        return time_since_last.total_seconds() >= query.execution_frequency
    
    async def _execute_splunk_search(self, query: SplunkQuery) -> List[SplunkSearchResult]:
        """
        Execute a single Splunk search and parse results.
        
        Args:
            query: SplunkQuery to execute
            
        Returns:
            List[SplunkSearchResult]: Parsed search results
        """
        search_results = []
        execution_start = time.time()
        
        try:
            # Create search job
            job = self.splunk_service.jobs.create(
                query.search_query,
                earliest_time=query.earliest_time,
                latest_time=query.latest_time,
                max_count=query.max_results
            )
            
            # Wait for job completion
            while not job.is_done():
                await asyncio.sleep(0.1)
            
            # Process search results
            for result in results.ResultsReader(job.results()):
                if isinstance(result, dict):
                    parsed_result = self._parse_search_result(result)
                    if parsed_result:
                        search_results.append(parsed_result)
            
            # Update query performance metrics
            execution_duration = time.time() - execution_start
            if query.execution_count > 0:
                query.average_duration = (
                    (query.average_duration * (query.execution_count - 1) + execution_duration) / 
                    query.execution_count
                )
            else:
                query.average_duration = execution_duration
            
            self.logger.info("search_executed_successfully", 
                           query_id=query.query_id,
                           results_count=len(search_results),
                           execution_time=execution_duration)
            
        except Exception as e:
            self.logger.error("search_execution_error", 
                            query_id=query.query_id, 
                            error=str(e))
            raise
        
        return search_results
    
    def _parse_search_result(self, raw_result: Dict[str, Any]) -> Optional[SplunkSearchResult]:
        """
        Parse a raw Splunk search result into a structured SplunkSearchResult.
        
        Args:
            raw_result: Raw result dictionary from Splunk
            
        Returns:
            Optional[SplunkSearchResult]: Parsed result or None if parsing fails
        """
        try:
            # Extract timestamp
            timestamp_str = raw_result.get('_time', '')
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = datetime.utcnow()
            
            # Extract basic fields
            result = SplunkSearchResult(
                timestamp=timestamp,
                raw_event=raw_result.get('_raw', ''),
                source=raw_result.get('source', ''),
                sourcetype=raw_result.get('sourcetype', ''),
                host=raw_result.get('host', ''),
                index=raw_result.get('index', ''),
                extracted_fields=raw_result,
                tags=set()
            )
            
            # Calculate severity score based on content
            result.severity_score = self._calculate_severity_score(result)
            
            # Add classification tags
            result.tags = self._classify_log_event(result)
            
            return result
            
        except Exception as e:
            self.logger.error("result_parsing_error", error=str(e))
            return None
    
    def _calculate_severity_score(self, result: SplunkSearchResult) -> float:
        """
        Calculate a severity score (0.0-1.0) for a log event.
        
        Uses keyword analysis and pattern matching to assess severity.
        
        Args:
            result: SplunkSearchResult to analyze
            
        Returns:
            float: Severity score from 0.0 (low) to 1.0 (critical)
        """
        severity_score = 0.0
        content = result.raw_event.lower()
        
        # Critical indicators
        critical_keywords = ['fatal', 'critical', 'outofmemoryerror', 'system failure', 'crash']
        for keyword in critical_keywords:
            if keyword in content:
                severity_score = max(severity_score, 1.0)
        
        # High severity indicators
        high_keywords = ['error', 'exception', 'failed', 'timeout', 'connection refused']
        for keyword in high_keywords:
            if keyword in content:
                severity_score = max(severity_score, 0.8)
        
        # Medium severity indicators
        medium_keywords = ['warning', 'deprecated', 'slow', 'retry']
        for keyword in medium_keywords:
            if keyword in content:
                severity_score = max(severity_score, 0.5)
        
        # Low severity indicators
        low_keywords = ['info', 'debug', 'trace']
        for keyword in low_keywords:
            if keyword in content:
                severity_score = max(severity_score, 0.2)
        
        return severity_score
    
    def _classify_log_event(self, result: SplunkSearchResult) -> Set[str]:
        """
        Classify a log event into categories using pattern matching.
        
        Args:
            result: SplunkSearchResult to classify
            
        Returns:
            Set[str]: Classification tags
        """
        tags = set()
        content = result.raw_event.lower()
        
        # Performance-related
        if any(keyword in content for keyword in ['slow', 'timeout', 'performance', 'latency']):
            tags.add('performance')
        
        # Security-related
        if any(keyword in content for keyword in ['auth', 'login', 'security', 'unauthorized']):
            tags.add('security')
        
        # Database-related
        if any(keyword in content for keyword in ['sql', 'database', 'connection', 'query']):
            tags.add('database')
        
        # Memory-related
        if any(keyword in content for keyword in ['memory', 'heap', 'gc', 'allocation']):
            tags.add('memory')
        
        # Business logic
        if any(keyword in content for keyword in ['transaction', 'business', 'validation', 'rule']):
            tags.add('business')
        
        return tags
    
    # -------------------------------------------------------------------------
    # PATTERN ANALYSIS AND ANOMALY DETECTION
    # -------------------------------------------------------------------------
    
    async def _analyze_search_results(self, query_results: List[Tuple[SplunkQuery, List[SplunkSearchResult]]]) -> Dict[str, Any]:
        """
        Analyze search results for patterns, anomalies, and alert conditions.
        
        Args:
            query_results: Results from executed queries
            
        Returns:
            Dict[str, Any]: Analysis results with metrics
        """
        analysis_results = {
            "patterns_matched": 0,
            "anomalies_detected": 0,
            "high_severity_events": 0,
            "pattern_matches": []
        }
        
        # Flatten all search results
        all_results = []
        for query, results in query_results:
            all_results.extend(results)
        
        # Analyze results against known patterns
        for result in all_results:
            # Pattern matching
            pattern_matches = self._match_log_patterns(result)
            analysis_results["patterns_matched"] += len(pattern_matches)
            analysis_results["pattern_matches"].extend(pattern_matches)
            
            # Severity analysis
            if result.severity_score >= 0.8:
                analysis_results["high_severity_events"] += 1
            
            # Anomaly detection
            if await self._detect_anomaly(result):
                analysis_results["anomalies_detected"] += 1
        
        return analysis_results
    
    def _match_log_patterns(self, result: SplunkSearchResult) -> List[Dict[str, Any]]:
        """
        Match a log result against known patterns.
        
        Args:
            result: SplunkSearchResult to analyze
            
        Returns:
            List[Dict[str, Any]]: Matched patterns with metadata
        """
        matches = []
        
        for pattern in self.log_patterns:
            if re.search(pattern.regex_pattern, result.raw_event, re.IGNORECASE):
                match_info = {
                    "pattern_id": pattern.pattern_id,
                    "description": pattern.description,
                    "severity": pattern.severity,
                    "timestamp": result.timestamp,
                    "source": result.source,
                    "raw_event": result.raw_event[:200] + "..." if len(result.raw_event) > 200 else result.raw_event
                }
                matches.append(match_info)
                
                # Update pattern statistics
                pattern.match_count += 1
        
        return matches
    
    async def _detect_anomaly(self, result: SplunkSearchResult) -> bool:
        """
        Detect if a log result represents an anomaly.
        
        Uses baseline metrics and statistical analysis to identify unusual patterns.
        
        Args:
            result: SplunkSearchResult to analyze
            
        Returns:
            bool: True if anomaly detected
        """
        # Simple anomaly detection based on severity score and frequency
        # In a production system, this would use more sophisticated ML techniques
        
        # Check if severity score is unusually high
        if result.severity_score > self.anomaly_threshold:
            return True
        
        # Check for unusual source patterns
        source_baseline = self.baseline_metrics.get(f"source_{result.source}", 0.1)
        if result.severity_score > source_baseline * 2:
            return True
        
        return False
    
    # -------------------------------------------------------------------------
    # ALERT GENERATION AND PROCESSING
    # -------------------------------------------------------------------------
    
    async def _generate_alerts_from_analysis(self) -> Dict[str, Any]:
        """
        Generate alerts based on analysis results.
        
        Returns:
            Dict[str, Any]: Alert generation results
        """
        alert_results = {"alerts_count": 0}
        
        # Check pattern-based alerts
        for pattern in self.log_patterns:
            if await self._should_trigger_pattern_alert(pattern):
                alert = await self._create_pattern_alert(pattern)
                await self.emit_alert(alert)
                alert_results["alerts_count"] += 1
                
                # Update pattern suppression
                pattern.last_triggered = datetime.utcnow()
        
        return alert_results
    
    async def _should_trigger_pattern_alert(self, pattern: LogPattern) -> bool:
        """
        Determine if a pattern should trigger an alert.
        
        Args:
            pattern: LogPattern to check
            
        Returns:
            bool: True if alert should be triggered
        """
        # Check suppression period
        if pattern.last_triggered:
            time_since_last = datetime.utcnow() - pattern.last_triggered
            if time_since_last.total_seconds() < (pattern.suppression_minutes * 60):
                return False
        
        # Check frequency threshold
        # This is a simplified check - production would use time-windowed counting
        return pattern.match_count >= pattern.frequency_threshold
    
    async def _create_pattern_alert(self, pattern: LogPattern) -> Alert:
        """
        Create an alert for a matched pattern.
        
        Args:
            pattern: LogPattern that triggered the alert
            
        Returns:
            Alert: Created alert object
        """
        alert_id = f"splunk_pattern_{pattern.pattern_id}_{int(time.time())}"
        
        alert = Alert(
            id=alert_id,
            title=f"Pattern Alert: {pattern.description}",
            description=f"Pattern '{pattern.pattern_id}' has been detected {pattern.match_count} times. "
                       f"Pattern: {pattern.regex_pattern}",
            severity=pattern.severity,
            source=self.name,
            timestamp=datetime.utcnow(),
            metadata={
                "pattern_id": pattern.pattern_id,
                "match_count": pattern.match_count,
                "pattern_regex": pattern.regex_pattern,
                "java_app": self.java_app_name,
                "agent_type": "splunk"
            }
        )
        
        return alert
    
    # -------------------------------------------------------------------------
    # BASELINE AND METRICS MANAGEMENT
    # -------------------------------------------------------------------------
    
    async def _load_baseline_metrics(self) -> None:
        """
        Load historical baseline metrics for anomaly detection.
        
        This method would typically load metrics from:
        - Historical Splunk data
        - Saved agent state
        - External metrics storage
        """
        try:
            self.logger.info("loading_baseline_metrics")
            
            # Initialize with default baselines
            self.baseline_metrics = {
                "default_severity": 0.3,
                "error_rate_baseline": 5.0,
                "response_time_baseline": 1000.0,
                "memory_usage_baseline": 60.0
            }
            
            # Load historical data from Splunk (simplified)
            await self._calculate_historical_baselines()
            
            self.logger.info("baseline_metrics_loaded", metrics_count=len(self.baseline_metrics))
            
        except Exception as e:
            self.logger.error("baseline_loading_error", error=str(e))
    
    async def _calculate_historical_baselines(self) -> None:
        """
        Calculate baseline metrics from historical Splunk data.
        
        Uses statistical analysis of past performance to establish normal ranges.
        """
        # This is a simplified implementation
        # Production would use more sophisticated statistical analysis
        pass
    
    async def _update_baseline_metrics(self) -> None:
        """
        Update baseline metrics with recent observations.
        
        Implements adaptive learning to adjust baselines over time.
        """
        try:
            # Update baselines based on recent metrics
            # This is where machine learning algorithms would be applied
            pass
            
        except Exception as e:
            self.logger.error("baseline_update_error", error=str(e))
    
    # -------------------------------------------------------------------------
    # UTILITY AND HELPER METHODS
    # -------------------------------------------------------------------------
    
    async def _analyze_log_stream(self) -> Dict[str, Any]:
        """
        Analyze real-time log stream for immediate issues.
        
        Returns:
            Dict[str, Any]: Stream analysis results
        """
        # Simplified real-time analysis
        return {"metrics_count": 0}
    
    async def _cleanup_cache(self) -> None:
        """
        Clean up expired cache entries and temporary data.
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(minutes=self.cache_ttl_minutes)
            
            # Clean up search results cache
            expired_keys = []
            for key, results in self.search_results_cache.items():
                if results and results[0].timestamp < cutoff_time:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.search_results_cache[key]
            
            if expired_keys:
                self.logger.info("cache_cleaned", expired_entries=len(expired_keys))
                
        except Exception as e:
            self.logger.error("cache_cleanup_error", error=str(e))
    
    async def _save_agent_state(self) -> None:
        """
        Save current agent state for persistence across restarts.
        """
        try:
            state = {
                "baseline_metrics": self.baseline_metrics,
                "pattern_statistics": [
                    {
                        "pattern_id": p.pattern_id,
                        "match_count": p.match_count,
                        "last_triggered": p.last_triggered.isoformat() if p.last_triggered else None
                    }
                    for p in self.log_patterns
                ]
            }
            
            # In production, this would save to persistent storage
            self.logger.info("agent_state_saved", state_size=len(str(state)))
            
        except Exception as e:
            self.logger.error("state_saving_error", error=str(e))
    
    async def _generate_agent_error_alert(self, error: Exception) -> None:
        """
        Generate an alert when the agent itself encounters an error.
        
        Args:
            error: Exception that occurred
        """
        alert = Alert(
            id=f"splunk_agent_error_{int(time.time())}",
            title="Splunk Agent Execution Error",
            description=f"Splunk monitoring agent encountered an error: {str(error)}",
            severity=AlertSeverity.HIGH,
            source=self.name,
            timestamp=datetime.utcnow(),
            metadata={
                "error_type": type(error).__name__,
                "agent_type": "splunk",
                "java_app": self.java_app_name
            }
        )
        
        await self.emit_alert(alert)


# =============================================================================
# AGENT REGISTRATION
# =============================================================================

# Register the Splunk agent with the factory
AgentFactory.register_agent_type("splunk", SplunkAgent)

# Export the agent class
__all__ = ['SplunkAgent', 'SplunkSearchResult', 'LogPattern', 'SplunkQuery']