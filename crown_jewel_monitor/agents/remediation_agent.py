#!/usr/bin/env python3
"""
Crown Jewel Java Application Monitor - Automated Remediation Agent
Intelligent agent for automated issue remediation and self-healing capabilities.

This agent provides:
1. Automated remediation actions for common Java application issues
2. Safe execution framework with rollback capabilities
3. Approval workflows for high-risk actions
4. Learning from remediation success/failure rates
5. Integration with external systems for automated healing
6. Comprehensive audit trail of all remediation activities
"""

import asyncio
import json
import time
import subprocess
import shlex
import signal
import os
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set, Callable
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
import uuid

# Process and system management
import psutil
import requests
import aiohttp
import aiofiles

from ..core.agent_framework import (
    BaseAgent, Alert, AlertSeverity, MonitoringMetric, RemediationAction,
    AgentFactory
)

import structlog
logger = structlog.get_logger()


# =============================================================================
# REMEDIATION DATA STRUCTURES
# =============================================================================

class RemediationRisk(Enum):
    """Risk levels for remediation actions."""
    LOW = "low"             # No service impact, reversible
    MEDIUM = "medium"       # Minor service impact, mostly reversible
    HIGH = "high"          # Significant service impact, requires approval
    CRITICAL = "critical"   # Major service impact, requires manual approval


class RemediationStatus(Enum):
    """Status of remediation execution."""
    PENDING = "pending"           # Waiting to execute
    APPROVED = "approved"         # Approved for execution
    EXECUTING = "executing"       # Currently executing
    COMPLETED = "completed"       # Successfully completed
    FAILED = "failed"            # Failed to execute
    ROLLED_BACK = "rolled_back"  # Successfully rolled back
    REQUIRES_APPROVAL = "requires_approval"  # Waiting for manual approval


class ActionType(Enum):
    """Types of remediation actions."""
    RESTART_SERVICE = "restart_service"
    CLEAR_CACHE = "clear_cache"
    SCALE_RESOURCES = "scale_resources"
    RESTART_APPLICATION = "restart_application"
    KILL_HUNG_PROCESSES = "kill_hung_processes"
    CLEAR_TEMP_FILES = "clear_temp_files"
    ROTATE_LOGS = "rotate_logs"
    ADJUST_CONFIGURATION = "adjust_configuration"
    TRIGGER_GC = "trigger_gc"
    RESTART_DATABASE_CONNECTION = "restart_database_connection"
    FAILOVER_TO_BACKUP = "failover_to_backup"
    CUSTOM_SCRIPT = "custom_script"


@dataclass
class RemediationPlan:
    """
    Represents a complete remediation plan for addressing an issue.
    Contains multiple steps and safety mechanisms.
    """
    plan_id: str                          # Unique plan identifier
    issue_description: str                # Description of the issue being addressed
    target_components: List[str]          # Components affected by remediation
    
    # Remediation steps
    primary_actions: List['RemediationStep']     # Main remediation steps
    fallback_actions: List['RemediationStep']    # Fallback if primary fails
    rollback_actions: List['RemediationStep']    # Steps to undo changes
    
    # Risk and approval
    overall_risk: RemediationRisk         # Overall risk level
    requires_approval: bool               # Whether manual approval is needed
    approved_by: Optional[str] = None     # Who approved the plan
    approval_time: Optional[datetime] = None
    
    # Execution tracking
    status: RemediationStatus = RemediationStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_log: List[str] = field(default_factory=list)
    
    # Success criteria
    success_criteria: List[str] = field(default_factory=list)
    validation_checks: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = "automated_remediation"
    estimated_duration_minutes: int = 5
    estimated_downtime_seconds: int = 0


@dataclass
class RemediationStep:
    """
    Represents a single step in a remediation plan.
    Contains all information needed to execute and validate the step.
    """
    step_id: str                          # Unique step identifier
    action_type: ActionType               # Type of action to perform
    description: str                      # Human-readable description
    
    # Execution parameters
    command: Optional[str] = None         # Command to execute
    script_path: Optional[str] = None     # Path to script file
    api_endpoint: Optional[str] = None    # API endpoint to call
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Safety and validation
    risk_level: RemediationRisk = RemediationRisk.LOW
    timeout_seconds: int = 30
    retry_attempts: int = 1
    retry_delay_seconds: int = 5
    
    # Prerequisites and validation
    prerequisites: List[str] = field(default_factory=list)
    pre_checks: List[str] = field(default_factory=list)
    post_checks: List[str] = field(default_factory=list)
    success_indicators: List[str] = field(default_factory=list)
    
    # Rollback information
    rollback_command: Optional[str] = None
    rollback_script: Optional[str] = None
    rollback_parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Execution tracking
    status: RemediationStatus = RemediationStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_output: str = ""
    exit_code: Optional[int] = None
    error_message: Optional[str] = None


@dataclass
class RemediationHistory:
    """
    Historical record of remediation execution and outcomes.
    Used for learning and improving remediation strategies.
    """
    execution_id: str                     # Unique execution identifier
    plan_id: str                         # Associated remediation plan
    trigger_alert_id: str                # Alert that triggered remediation
    
    # Execution details
    executed_at: datetime
    executed_by: str                     # User or system that executed
    duration_seconds: float
    
    # Outcome
    success: bool                        # Whether remediation was successful
    steps_completed: int                 # Number of steps completed
    steps_failed: int                    # Number of steps that failed
    
    # Impact assessment
    service_impact: str                  # Description of service impact
    downtime_seconds: int = 0            # Actual downtime caused
    users_affected: int = 0              # Number of users affected
    
    # Learning data
    effectiveness_score: float = 0.0     # How effective was the remediation (0-1)
    side_effects: List[str] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)
    
    # Follow-up
    requires_follow_up: bool = False
    follow_up_actions: List[str] = field(default_factory=list)


# =============================================================================
# REMEDIATION AGENT IMPLEMENTATION
# =============================================================================

class RemediationAgent(BaseAgent):
    """
    Automated remediation agent that provides self-healing capabilities
    for Java applications and infrastructure.
    
    Core capabilities:
    - Automated execution of remediation plans
    - Risk-based approval workflows
    - Safe execution with rollback capabilities
    - Learning from remediation outcomes
    - Integration with monitoring and alerting systems
    """
    
    def __init__(self, agent_id: str, config: Dict[str, Any]):
        """
        Initialize the remediation agent with configuration.
        
        Args:
            agent_id: Unique identifier for this agent instance
            config: Configuration dictionary with remediation parameters
        """
        super().__init__(agent_id, config)
        
        # Configuration
        self.auto_approve_low_risk = config.get('auto_approve_low_risk', True)
        self.auto_approve_medium_risk = config.get('auto_approve_medium_risk', False)
        self.max_concurrent_remediations = config.get('max_concurrent_remediations', 3)
        self.default_timeout = config.get('default_timeout_seconds', 300)
        self.enable_rollback = config.get('enable_rollback', True)
        
        # Application configuration
        self.java_app_config = config.get('java_application', {})
        self.app_restart_command = self.java_app_config.get('restart_command')
        self.app_health_check_url = self.java_app_config.get('health_check_url')
        self.jmx_host = self.java_app_config.get('jmx_host', 'localhost')
        self.jmx_port = self.java_app_config.get('jmx_port', 9999)
        
        # State tracking
        self.active_remediations: Dict[str, RemediationPlan] = {}
        self.remediation_history: List[RemediationHistory] = []
        self.pending_approvals: Dict[str, RemediationPlan] = {}
        
        # Performance tracking
        self.success_rates: Dict[ActionType, float] = {}
        self.average_execution_times: Dict[ActionType, float] = {}
        
        # Safety mechanisms
        self.cooldown_periods: Dict[str, datetime] = {}
        self.max_remediations_per_hour = config.get('max_remediations_per_hour', 10)
        self.recent_remediations: List[datetime] = []
        
        logger.info("RemediationAgent initialized", 
                   agent_id=self.agent_id,
                   auto_approve_low_risk=self.auto_approve_low_risk)
    
    async def initialize(self) -> bool:
        """
        Initialize the remediation agent.
        Load remediation templates and validate configuration.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            logger.info("Initializing RemediationAgent", agent_id=self.agent_id)
            
            # Create necessary directories
            self.data_dir = Path(self.config.get('data_directory', '/tmp/crown-jewel-remediation'))
            self.data_dir.mkdir(parents=True, exist_ok=True)
            
            self.scripts_dir = self.data_dir / 'scripts'
            self.scripts_dir.mkdir(exist_ok=True)
            
            self.logs_dir = self.data_dir / 'logs'
            self.logs_dir.mkdir(exist_ok=True)
            
            # Load remediation templates
            await self._load_remediation_templates()
            
            # Load historical data
            await self._load_remediation_history()
            
            # Validate configuration
            await self._validate_configuration()
            
            # Register for alerts that might trigger remediation
            if hasattr(self, 'register_alert_handler'):
                self.register_alert_handler(self._handle_alert_for_remediation)
            
            logger.info("RemediationAgent initialized successfully", agent_id=self.agent_id)
            return True
            
        except Exception as e:
            logger.error("Failed to initialize RemediationAgent",
                        agent_id=self.agent_id, error=str(e))
            return False
    
    async def execute(self) -> Dict[str, Any]:
        """
        Execute remediation agent tasks.
        
        Main execution flow:
        1. Process pending approvals
        2. Monitor active remediations
        3. Execute approved remediations
        4. Update success rates and learning
        5. Clean up completed remediations
        
        Returns:
            Dictionary containing execution results
        """
        start_time = time.time()
        results = {
            'remediations_executed': 0,
            'remediations_completed': 0,
            'remediations_failed': 0,
            'pending_approvals': len(self.pending_approvals),
            'active_remediations': len(self.active_remediations),
            'execution_time_ms': 0
        }
        
        try:
            logger.info("Starting remediation agent execution", agent_id=self.agent_id)
            
            # Step 1: Process auto-approvals
            auto_approved = await self._process_auto_approvals()
            
            # Step 2: Execute approved remediations
            executed_count = await self._execute_pending_remediations()
            results['remediations_executed'] = executed_count
            
            # Step 3: Monitor active remediations
            completed, failed = await self._monitor_active_remediations()
            results['remediations_completed'] = completed
            results['remediations_failed'] = failed
            
            # Step 4: Update learning and statistics
            await self._update_learning_data()
            
            # Step 5: Clean up old data
            await self._cleanup_old_remediations()
            
            # Step 6: Emit metrics
            await self._emit_remediation_metrics(results)
            
        except Exception as e:
            logger.error("Error during remediation agent execution",
                        agent_id=self.agent_id, error=str(e))
            await self.emit_alert(Alert(
                id=f"remediation_agent_error_{int(time.time())}",
                title="Remediation Agent Error",
                description=f"Error during remediation execution: {str(e)}",
                severity=AlertSeverity.MEDIUM,
                source=self.agent_id,
                timestamp=datetime.utcnow(),
                tags=['remediation', 'agent_error']
            ))
        
        finally:
            results['execution_time_ms'] = (time.time() - start_time) * 1000
            logger.info("Remediation agent execution completed",
                       agent_id=self.agent_id, **results)
        
        return results
    
    async def cleanup(self) -> None:
        """
        Clean up resources and save remediation history.
        """
        try:
            logger.info("Cleaning up RemediationAgent", agent_id=self.agent_id)
            
            # Cancel any active remediations
            for plan_id, plan in self.active_remediations.items():
                if plan.status == RemediationStatus.EXECUTING:
                    logger.info("Cancelling active remediation", plan_id=plan_id)
                    plan.status = RemediationStatus.FAILED
                    plan.execution_log.append("Cancelled due to agent shutdown")
            
            # Save remediation history
            await self._save_remediation_history()
            
            logger.info("RemediationAgent cleanup completed", agent_id=self.agent_id)
            
        except Exception as e:
            logger.error("Error during RemediationAgent cleanup",
                        agent_id=self.agent_id, error=str(e))
    
    # =========================================================================
    # ALERT HANDLING AND REMEDIATION TRIGGERING
    # =========================================================================
    
    async def _handle_alert_for_remediation(self, alert: Alert) -> None:
        """
        Handle incoming alerts and determine if remediation is needed.
        
        Args:
            alert: Alert that might trigger remediation
        """
        try:
            logger.info("Evaluating alert for remediation",
                       alert_id=alert.id, severity=alert.severity.value)
            
            # Check if remediation is appropriate for this alert
            remediation_plan = await self._create_remediation_plan_for_alert(alert)
            
            if remediation_plan:
                logger.info("Remediation plan created for alert",
                           alert_id=alert.id, plan_id=remediation_plan.plan_id)
                
                # Add to appropriate queue based on approval requirements
                if remediation_plan.requires_approval:
                    self.pending_approvals[remediation_plan.plan_id] = remediation_plan
                    await self._request_approval(remediation_plan)
                else:
                    self.active_remediations[remediation_plan.plan_id] = remediation_plan
                    await self._execute_remediation_plan(remediation_plan)
            
        except Exception as e:
            logger.error("Error handling alert for remediation",
                        alert_id=alert.id, error=str(e))
    
    async def _create_remediation_plan_for_alert(self, alert: Alert) -> Optional[RemediationPlan]:
        """
        Create a remediation plan based on an alert.
        
        Args:
            alert: Alert to create remediation plan for
            
        Returns:
            RemediationPlan or None if no remediation is appropriate
        """
        # Check rate limiting
        if not await self._check_rate_limits():
            logger.info("Rate limit exceeded, skipping remediation",
                       alert_id=alert.id)
            return None
        
        # Determine remediation based on alert type and content
        if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            
            # Memory-related issues
            if any(keyword in alert.description.lower() 
                   for keyword in ['memory', 'heap', 'outofmemoryerror']):
                return await self._create_memory_remediation_plan(alert)
            
            # Performance issues
            if any(keyword in alert.description.lower() 
                   for keyword in ['performance', 'slow', 'timeout', 'response time']):
                return await self._create_performance_remediation_plan(alert)
            
            # Application unresponsive
            if any(keyword in alert.description.lower() 
                   for keyword in ['unresponsive', 'hung', 'deadlock']):
                return await self._create_restart_remediation_plan(alert)
            
            # Database connection issues
            if any(keyword in alert.description.lower() 
                   for keyword in ['database', 'connection', 'sql']):
                return await self._create_database_remediation_plan(alert)
        
        return None
    
    async def _create_memory_remediation_plan(self, alert: Alert) -> RemediationPlan:
        """
        Create remediation plan for memory-related issues.
        
        Args:
            alert: Memory-related alert
            
        Returns:
            RemediationPlan for memory issues
        """
        plan_id = f"memory_remediation_{int(time.time())}"
        
        # Primary actions: GC first, then restart if needed
        primary_actions = [
            RemediationStep(
                step_id=f"{plan_id}_gc",
                action_type=ActionType.TRIGGER_GC,
                description="Trigger garbage collection to free memory",
                api_endpoint=f"http://{self.jmx_host}:{self.jmx_port}/jmx/gc",
                risk_level=RemediationRisk.LOW,
                timeout_seconds=60,
                success_indicators=["Heap usage decreased by at least 10%"],
                post_checks=["Check heap usage after GC"]
            ),
            RemediationStep(
                step_id=f"{plan_id}_restart",
                action_type=ActionType.RESTART_APPLICATION,
                description="Restart Java application to resolve memory issues",
                command=self.app_restart_command,
                risk_level=RemediationRisk.HIGH,
                timeout_seconds=120,
                requires_approval=True,
                success_indicators=["Application health check passes"],
                post_checks=[f"GET {self.app_health_check_url}"]
            )
        ]
        
        # Fallback: Clear temp files and caches
        fallback_actions = [
            RemediationStep(
                step_id=f"{plan_id}_clear_temp",
                action_type=ActionType.CLEAR_TEMP_FILES,
                description="Clear temporary files to free disk space",
                command="find /tmp -name '*.tmp' -mtime +1 -delete",
                risk_level=RemediationRisk.LOW,
                timeout_seconds=30
            )
        ]
        
        # Rollback: Restart application if GC caused issues
        rollback_actions = [
            RemediationStep(
                step_id=f"{plan_id}_rollback_restart",
                action_type=ActionType.RESTART_APPLICATION,
                description="Restart application to recover from failed remediation",
                command=self.app_restart_command,
                risk_level=RemediationRisk.HIGH,
                timeout_seconds=120
            )
        ]
        
        return RemediationPlan(
            plan_id=plan_id,
            issue_description=f"Memory issue: {alert.description}",
            target_components=["java_application"],
            primary_actions=primary_actions,
            fallback_actions=fallback_actions,
            rollback_actions=rollback_actions,
            overall_risk=RemediationRisk.MEDIUM,
            requires_approval=not self.auto_approve_medium_risk,
            success_criteria=[
                "Heap usage below 80%",
                "Application responsive",
                "No memory-related errors in logs"
            ],
            validation_checks=[
                f"Health check at {self.app_health_check_url} returns 200",
                "JVM memory metrics within normal range"
            ],
            estimated_duration_minutes=5,
            estimated_downtime_seconds=30
        )
    
    async def _create_performance_remediation_plan(self, alert: Alert) -> RemediationPlan:
        """
        Create remediation plan for performance issues.
        
        Args:
            alert: Performance-related alert
            
        Returns:
            RemediationPlan for performance issues
        """
        plan_id = f"performance_remediation_{int(time.time())}"
        
        primary_actions = [
            RemediationStep(
                step_id=f"{plan_id}_clear_cache",
                action_type=ActionType.CLEAR_CACHE,
                description="Clear application caches to improve performance",
                api_endpoint=f"http://{self.jmx_host}:8080/actuator/caches",
                parameters={"action": "clear"},
                risk_level=RemediationRisk.LOW,
                timeout_seconds=30,
                success_indicators=["Cache cleared successfully"],
                post_checks=["Verify cache metrics reset"]
            ),
            RemediationStep(
                step_id=f"{plan_id}_gc",
                action_type=ActionType.TRIGGER_GC,
                description="Trigger garbage collection to improve performance",
                api_endpoint=f"http://{self.jmx_host}:{self.jmx_port}/jmx/gc",
                risk_level=RemediationRisk.LOW,
                timeout_seconds=60
            )
        ]
        
        return RemediationPlan(
            plan_id=plan_id,
            issue_description=f"Performance issue: {alert.description}",
            target_components=["java_application"],
            primary_actions=primary_actions,
            fallback_actions=[],
            rollback_actions=[],
            overall_risk=RemediationRisk.LOW,
            requires_approval=False,  # Low risk, auto-approve
            success_criteria=[
                "Response time improved by at least 20%",
                "CPU usage decreased"
            ],
            validation_checks=[
                "Application health check passes",
                "Performance metrics within acceptable range"
            ],
            estimated_duration_minutes=2,
            estimated_downtime_seconds=0
        )
    
    async def _create_restart_remediation_plan(self, alert: Alert) -> RemediationPlan:
        """
        Create remediation plan for application restart.
        
        Args:
            alert: Alert indicating restart is needed
            
        Returns:
            RemediationPlan for application restart
        """
        plan_id = f"restart_remediation_{int(time.time())}"
        
        primary_actions = [
            RemediationStep(
                step_id=f"{plan_id}_restart",
                action_type=ActionType.RESTART_APPLICATION,
                description="Restart Java application to resolve issues",
                command=self.app_restart_command,
                risk_level=RemediationRisk.HIGH,
                timeout_seconds=180,
                success_indicators=[
                    "Application process started successfully",
                    "Health check endpoint returns 200"
                ],
                post_checks=[
                    f"GET {self.app_health_check_url}",
                    "Verify JMX connectivity"
                ]
            )
        ]
        
        return RemediationPlan(
            plan_id=plan_id,
            issue_description=f"Application restart needed: {alert.description}",
            target_components=["java_application"],
            primary_actions=primary_actions,
            fallback_actions=[],
            rollback_actions=[],
            overall_risk=RemediationRisk.HIGH,
            requires_approval=True,  # High risk, requires approval
            success_criteria=[
                "Application started successfully",
                "All health checks pass",
                "No startup errors in logs"
            ],
            validation_checks=[
                f"Health check at {self.app_health_check_url} returns 200",
                "JMX metrics available",
                "Application logs show successful startup"
            ],
            estimated_duration_minutes=3,
            estimated_downtime_seconds=60
        )
    
    async def _create_database_remediation_plan(self, alert: Alert) -> RemediationPlan:
        """
        Create remediation plan for database connection issues.
        
        Args:
            alert: Database-related alert
            
        Returns:
            RemediationPlan for database issues
        """
        plan_id = f"database_remediation_{int(time.time())}"
        
        primary_actions = [
            RemediationStep(
                step_id=f"{plan_id}_restart_connections",
                action_type=ActionType.RESTART_DATABASE_CONNECTION,
                description="Restart database connection pool",
                api_endpoint=f"http://{self.jmx_host}:8080/actuator/database/restart",
                risk_level=RemediationRisk.MEDIUM,
                timeout_seconds=60,
                success_indicators=["Connection pool restarted successfully"],
                post_checks=["Verify database connectivity"]
            )
        ]
        
        return RemediationPlan(
            plan_id=plan_id,
            issue_description=f"Database issue: {alert.description}",
            target_components=["database_connections"],
            primary_actions=primary_actions,
            fallback_actions=[],
            rollback_actions=[],
            overall_risk=RemediationRisk.MEDIUM,
            requires_approval=not self.auto_approve_medium_risk,
            success_criteria=[
                "Database connections restored",
                "Connection pool metrics healthy"
            ],
            validation_checks=[
                "Database connectivity test passes",
                "Connection pool metrics within normal range"
            ],
            estimated_duration_minutes=2,
            estimated_downtime_seconds=10
        )
    
    # =========================================================================
    # REMEDIATION EXECUTION
    # =========================================================================
    
    async def _process_auto_approvals(self) -> int:
        """
        Process auto-approvals for low and medium risk remediations.
        
        Returns:
            Number of remediations auto-approved
        """
        auto_approved = 0
        
        to_approve = []
        for plan_id, plan in self.pending_approvals.items():
            should_approve = False
            
            if plan.overall_risk == RemediationRisk.LOW and self.auto_approve_low_risk:
                should_approve = True
            elif plan.overall_risk == RemediationRisk.MEDIUM and self.auto_approve_medium_risk:
                should_approve = True
            
            if should_approve:
                to_approve.append(plan_id)
        
        for plan_id in to_approve:
            plan = self.pending_approvals.pop(plan_id)
            plan.status = RemediationStatus.APPROVED
            plan.approved_by = "auto_approval"
            plan.approval_time = datetime.utcnow()
            self.active_remediations[plan_id] = plan
            auto_approved += 1
            
            logger.info("Auto-approved remediation plan",
                       plan_id=plan_id, risk=plan.overall_risk.value)
        
        return auto_approved
    
    async def _execute_pending_remediations(self) -> int:
        """
        Execute all approved remediations.
        
        Returns:
            Number of remediations started
        """
        executed_count = 0
        
        for plan_id, plan in list(self.active_remediations.items()):
            if plan.status == RemediationStatus.APPROVED:
                if len([p for p in self.active_remediations.values() 
                       if p.status == RemediationStatus.EXECUTING]) < self.max_concurrent_remediations:
                    
                    asyncio.create_task(self._execute_remediation_plan(plan))
                    executed_count += 1
        
        return executed_count
    
    async def _execute_remediation_plan(self, plan: RemediationPlan) -> None:
        """
        Execute a complete remediation plan.
        
        Args:
            plan: RemediationPlan to execute
        """
        plan.status = RemediationStatus.EXECUTING
        plan.started_at = datetime.utcnow()
        
        logger.info("Starting remediation plan execution",
                   plan_id=plan.plan_id, risk=plan.overall_risk.value)
        
        try:
            # Execute primary actions
            success = await self._execute_action_sequence(plan.primary_actions, plan)
            
            if not success and plan.fallback_actions:
                logger.info("Primary actions failed, executing fallback",
                           plan_id=plan.plan_id)
                plan.execution_log.append("Primary actions failed, executing fallback actions")
                success = await self._execute_action_sequence(plan.fallback_actions, plan)
            
            # Validate success
            if success:
                validation_success = await self._validate_remediation_success(plan)
                if validation_success:
                    plan.status = RemediationStatus.COMPLETED
                    logger.info("Remediation plan completed successfully",
                               plan_id=plan.plan_id)
                else:
                    plan.status = RemediationStatus.FAILED
                    plan.execution_log.append("Validation checks failed")
                    logger.warning("Remediation validation failed",
                                  plan_id=plan.plan_id)
            else:
                plan.status = RemediationStatus.FAILED
                logger.error("Remediation plan failed",
                            plan_id=plan.plan_id)
                
                # Execute rollback if enabled and available
                if self.enable_rollback and plan.rollback_actions:
                    logger.info("Executing rollback actions",
                               plan_id=plan.plan_id)
                    await self._execute_rollback(plan)
        
        except Exception as e:
            plan.status = RemediationStatus.FAILED
            plan.execution_log.append(f"Exception during execution: {str(e)}")
            logger.error("Exception during remediation execution",
                        plan_id=plan.plan_id, error=str(e))
        
        finally:
            plan.completed_at = datetime.utcnow()
            await self._record_remediation_history(plan)
    
    async def _execute_action_sequence(self, actions: List[RemediationStep],
                                     plan: RemediationPlan) -> bool:
        """
        Execute a sequence of remediation steps.
        
        Args:
            actions: List of RemediationStep to execute
            plan: Parent RemediationPlan
            
        Returns:
            True if all actions succeeded, False otherwise
        """
        for step in actions:
            step.status = RemediationStatus.EXECUTING
            step.started_at = datetime.utcnow()
            
            logger.info("Executing remediation step",
                       plan_id=plan.plan_id, step_id=step.step_id,
                       action_type=step.action_type.value)
            
            try:
                success = await self._execute_remediation_step(step, plan)
                
                if success:
                    step.status = RemediationStatus.COMPLETED
                    logger.info("Remediation step completed",
                               step_id=step.step_id)
                else:
                    step.status = RemediationStatus.FAILED
                    logger.error("Remediation step failed",
                                step_id=step.step_id)
                    
                    if step.risk_level in [RemediationRisk.HIGH, RemediationRisk.CRITICAL]:
                        # Stop execution on high-risk step failure
                        return False
            
            except Exception as e:
                step.status = RemediationStatus.FAILED
                step.error_message = str(e)
                logger.error("Exception executing remediation step",
                            step_id=step.step_id, error=str(e))
                return False
            
            finally:
                step.completed_at = datetime.utcnow()
                
            # If step failed and it's critical, stop execution
            if step.status == RemediationStatus.FAILED:
                if step.risk_level == RemediationRisk.CRITICAL:
                    return False
                # For lower risk steps, continue execution but log failure
                plan.execution_log.append(f"Step {step.step_id} failed but continuing execution")
        
        return True
    
    async def _execute_remediation_step(self, step: RemediationStep,
                                      plan: RemediationPlan) -> bool:
        """
        Execute a single remediation step.
        
        Args:
            step: RemediationStep to execute
            plan: Parent RemediationPlan
            
        Returns:
            True if step succeeded, False otherwise
        """
        try:
            # Execute based on action type
            if step.action_type == ActionType.RESTART_APPLICATION:
                return await self._restart_application(step)
            elif step.action_type == ActionType.TRIGGER_GC:
                return await self._trigger_gc(step)
            elif step.action_type == ActionType.CLEAR_CACHE:
                return await self._clear_cache(step)
            elif step.action_type == ActionType.RESTART_DATABASE_CONNECTION:
                return await self._restart_database_connection(step)
            elif step.action_type == ActionType.CLEAR_TEMP_FILES:
                return await self._clear_temp_files(step)
            elif step.action_type == ActionType.CUSTOM_SCRIPT:
                return await self._execute_custom_script(step)
            else:
                logger.error("Unknown action type", action_type=step.action_type.value)
                return False
        
        except asyncio.TimeoutError:
            step.error_message = f"Step timed out after {step.timeout_seconds} seconds"
            return False
        except Exception as e:
            step.error_message = str(e)
            return False
    
    async def _restart_application(self, step: RemediationStep) -> bool:
        """
        Restart the Java application.
        
        Args:
            step: RemediationStep containing restart configuration
            
        Returns:
            True if restart succeeded, False otherwise
        """
        if not step.command and not self.app_restart_command:
            step.error_message = "No restart command configured"
            return False
        
        command = step.command or self.app_restart_command
        
        try:
            # Execute restart command
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=step.timeout_seconds
            )
            
            step.execution_output = stdout.decode() + stderr.decode()
            step.exit_code = process.returncode
            
            if process.returncode == 0:
                # Wait for application to start and verify health
                await asyncio.sleep(10)  # Give app time to start
                
                if self.app_health_check_url:
                    return await self._check_application_health()
                else:
                    return True
            else:
                step.error_message = f"Restart command failed with exit code {process.returncode}"
                return False
        
        except Exception as e:
            step.error_message = f"Error executing restart: {str(e)}"
            return False
    
    async def _trigger_gc(self, step: RemediationStep) -> bool:
        """
        Trigger garbage collection via JMX.
        
        Args:
            step: RemediationStep containing GC configuration
            
        Returns:
            True if GC triggered successfully, False otherwise
        """
        try:
            if step.api_endpoint:
                # Use API endpoint if provided
                async with aiohttp.ClientSession() as session:
                    async with session.post(step.api_endpoint) as response:
                        if response.status == 200:
                            step.execution_output = await response.text()
                            return True
                        else:
                            step.error_message = f"API call failed with status {response.status}"
                            return False
            else:
                # Fallback to JMX command if available
                jmx_command = f"jcmd $(pgrep -f java) GC.run"
                
                process = await asyncio.create_subprocess_shell(
                    jmx_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=step.timeout_seconds
                )
                
                step.execution_output = stdout.decode() + stderr.decode()
                step.exit_code = process.returncode
                
                return process.returncode == 0
        
        except Exception as e:
            step.error_message = f"Error triggering GC: {str(e)}"
            return False
    
    async def _clear_cache(self, step: RemediationStep) -> bool:
        """
        Clear application caches.
        
        Args:
            step: RemediationStep containing cache configuration
            
        Returns:
            True if cache cleared successfully, False otherwise
        """
        try:
            if step.api_endpoint:
                async with aiohttp.ClientSession() as session:
                    if step.parameters:
                        async with session.post(step.api_endpoint, json=step.parameters) as response:
                            success = response.status == 200
                    else:
                        async with session.delete(step.api_endpoint) as response:
                            success = response.status in [200, 204]
                    
                    if success:
                        step.execution_output = await response.text()
                        return True
                    else:
                        step.error_message = f"Cache clear failed with status {response.status}"
                        return False
            else:
                step.error_message = "No cache clear endpoint configured"
                return False
        
        except Exception as e:
            step.error_message = f"Error clearing cache: {str(e)}"
            return False
    
    async def _restart_database_connection(self, step: RemediationStep) -> bool:
        """
        Restart database connection pool.
        
        Args:
            step: RemediationStep containing database configuration
            
        Returns:
            True if connection restart succeeded, False otherwise
        """
        try:
            if step.api_endpoint:
                async with aiohttp.ClientSession() as session:
                    async with session.post(step.api_endpoint) as response:
                        if response.status == 200:
                            step.execution_output = await response.text()
                            return True
                        else:
                            step.error_message = f"DB restart failed with status {response.status}"
                            return False
            else:
                step.error_message = "No database restart endpoint configured"
                return False
        
        except Exception as e:
            step.error_message = f"Error restarting database connection: {str(e)}"
            return False
    
    async def _clear_temp_files(self, step: RemediationStep) -> bool:
        """
        Clear temporary files.
        
        Args:
            step: RemediationStep containing temp file configuration
            
        Returns:
            True if temp files cleared successfully, False otherwise
        """
        try:
            command = step.command or "find /tmp -name '*.tmp' -mtime +1 -delete"
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=step.timeout_seconds
            )
            
            step.execution_output = stdout.decode() + stderr.decode()
            step.exit_code = process.returncode
            
            return process.returncode == 0
        
        except Exception as e:
            step.error_message = f"Error clearing temp files: {str(e)}"
            return False
    
    async def _execute_custom_script(self, step: RemediationStep) -> bool:
        """
        Execute a custom remediation script.
        
        Args:
            step: RemediationStep containing script configuration
            
        Returns:
            True if script executed successfully, False otherwise
        """
        try:
            if step.script_path:
                script_path = Path(step.script_path)
                if not script_path.exists():
                    step.error_message = f"Script not found: {step.script_path}"
                    return False
                
                command = f"bash {step.script_path}"
            elif step.command:
                command = step.command
            else:
                step.error_message = "No script or command specified"
                return False
            
            # Add parameters if provided
            if step.parameters:
                env = os.environ.copy()
                for key, value in step.parameters.items():
                    env[f"REMEDIATION_{key.upper()}"] = str(value)
            else:
                env = None
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=step.timeout_seconds
            )
            
            step.execution_output = stdout.decode() + stderr.decode()
            step.exit_code = process.returncode
            
            return process.returncode == 0
        
        except Exception as e:
            step.error_message = f"Error executing custom script: {str(e)}"
            return False
    
    # =========================================================================
    # VALIDATION AND MONITORING
    # =========================================================================
    
    async def _validate_remediation_success(self, plan: RemediationPlan) -> bool:
        """
        Validate that remediation was successful.
        
        Args:
            plan: RemediationPlan to validate
            
        Returns:
            True if validation passed, False otherwise
        """
        try:
            for check in plan.validation_checks:
                if check.startswith('GET '):
                    # HTTP health check
                    url = check[4:]  # Remove 'GET ' prefix
                    success = await self._perform_http_check(url)
                    if not success:
                        plan.execution_log.append(f"Validation failed: {check}")
                        return False
                elif check.startswith('CHECK '):
                    # Custom check
                    check_name = check[6:]  # Remove 'CHECK ' prefix
                    success = await self._perform_custom_check(check_name)
                    if not success:
                        plan.execution_log.append(f"Custom validation failed: {check}")
                        return False
            
            plan.execution_log.append("All validation checks passed")
            return True
        
        except Exception as e:
            plan.execution_log.append(f"Validation error: {str(e)}")
            return False
    
    async def _perform_http_check(self, url: str) -> bool:
        """
        Perform HTTP health check.
        
        Args:
            url: URL to check
            
        Returns:
            True if check passed, False otherwise
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    return response.status == 200
        except Exception:
            return False
    
    async def _perform_custom_check(self, check_name: str) -> bool:
        """
        Perform custom validation check.
        
        Args:
            check_name: Name of check to perform
            
        Returns:
            True if check passed, False otherwise
        """
        # Implement custom checks based on check_name
        if check_name == "jmx_connectivity":
            return await self._check_jmx_connectivity()
        elif check_name == "application_health":
            return await self._check_application_health()
        else:
            return True  # Default to pass for unknown checks
    
    async def _check_application_health(self) -> bool:
        """
        Check application health via health endpoint.
        
        Returns:
            True if application is healthy, False otherwise
        """
        if not self.app_health_check_url:
            return True  # No health check configured
        
        return await self._perform_http_check(self.app_health_check_url)
    
    async def _check_jmx_connectivity(self) -> bool:
        """
        Check JMX connectivity.
        
        Returns:
            True if JMX is accessible, False otherwise
        """
        try:
            # Simple socket check for JMX port
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.jmx_host, self.jmx_port),
                timeout=5
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    async def _execute_rollback(self, plan: RemediationPlan) -> None:
        """
        Execute rollback actions for a failed remediation.
        
        Args:
            plan: RemediationPlan to rollback
        """
        plan.execution_log.append("Starting rollback actions")
        
        try:
            success = await self._execute_action_sequence(plan.rollback_actions, plan)
            
            if success:
                plan.status = RemediationStatus.ROLLED_BACK
                plan.execution_log.append("Rollback completed successfully")
                logger.info("Rollback completed successfully", plan_id=plan.plan_id)
            else:
                plan.execution_log.append("Rollback failed")
                logger.error("Rollback failed", plan_id=plan.plan_id)
        
        except Exception as e:
            plan.execution_log.append(f"Rollback error: {str(e)}")
            logger.error("Error during rollback", plan_id=plan.plan_id, error=str(e))
    
    # =========================================================================
    # MONITORING AND LEARNING
    # =========================================================================
    
    async def _monitor_active_remediations(self) -> Tuple[int, int]:
        """
        Monitor active remediations and track completion.
        
        Returns:
            Tuple of (completed_count, failed_count)
        """
        completed = 0
        failed = 0
        
        for plan_id, plan in list(self.active_remediations.items()):
            if plan.status in [RemediationStatus.COMPLETED, RemediationStatus.FAILED, RemediationStatus.ROLLED_BACK]:
                if plan.status == RemediationStatus.COMPLETED:
                    completed += 1
                else:
                    failed += 1
                
                # Move to history
                del self.active_remediations[plan_id]
        
        return completed, failed
    
    async def _record_remediation_history(self, plan: RemediationPlan) -> None:
        """
        Record remediation execution in history for learning.
        
        Args:
            plan: Completed RemediationPlan to record
        """
        duration = 0.0
        if plan.started_at and plan.completed_at:
            duration = (plan.completed_at - plan.started_at).total_seconds()
        
        history = RemediationHistory(
            execution_id=str(uuid.uuid4()),
            plan_id=plan.plan_id,
            trigger_alert_id=plan.plan_id.split('_')[-1],  # Extract from plan ID
            executed_at=plan.started_at or datetime.utcnow(),
            executed_by=plan.approved_by or "automated",
            duration_seconds=duration,
            success=plan.status == RemediationStatus.COMPLETED,
            steps_completed=len([s for s in plan.primary_actions if s.status == RemediationStatus.COMPLETED]),
            steps_failed=len([s for s in plan.primary_actions if s.status == RemediationStatus.FAILED]),
            service_impact=f"Risk level: {plan.overall_risk.value}",
            downtime_seconds=plan.estimated_downtime_seconds,
            effectiveness_score=1.0 if plan.status == RemediationStatus.COMPLETED else 0.0
        )
        
        self.remediation_history.append(history)
    
    async def _update_learning_data(self) -> None:
        """
        Update learning data based on remediation history.
        """
        if not self.remediation_history:
            return
        
        # Calculate success rates by action type
        action_stats = defaultdict(lambda: {'total': 0, 'successful': 0, 'total_time': 0.0})
        
        for history in self.remediation_history[-100:]:  # Last 100 remediations
            for plan in [p for p in self.active_remediations.values() if p.plan_id == history.plan_id]:
                for action in plan.primary_actions:
                    action_stats[action.action_type]['total'] += 1
                    if action.status == RemediationStatus.COMPLETED:
                        action_stats[action.action_type]['successful'] += 1
                    
                    if action.started_at and action.completed_at:
                        duration = (action.completed_at - action.started_at).total_seconds()
                        action_stats[action.action_type]['total_time'] += duration
        
        # Update success rates
        for action_type, stats in action_stats.items():
            if stats['total'] > 0:
                self.success_rates[action_type] = stats['successful'] / stats['total']
                self.average_execution_times[action_type] = stats['total_time'] / stats['total']
    
    # =========================================================================
    # UTILITY AND HELPER METHODS
    # =========================================================================
    
    async def _check_rate_limits(self) -> bool:
        """
        Check if rate limits allow new remediation.
        
        Returns:
            True if within rate limits, False otherwise
        """
        current_time = datetime.utcnow()
        
        # Clean old entries
        self.recent_remediations = [
            timestamp for timestamp in self.recent_remediations
            if current_time - timestamp < timedelta(hours=1)
        ]
        
        # Check hourly limit
        if len(self.recent_remediations) >= self.max_remediations_per_hour:
            logger.warning("Hourly remediation limit exceeded",
                          count=len(self.recent_remediations),
                          limit=self.max_remediations_per_hour)
            return False
        
        # Add current time
        self.recent_remediations.append(current_time)
        return True
    
    async def _request_approval(self, plan: RemediationPlan) -> None:
        """
        Request manual approval for high-risk remediation.
        
        Args:
            plan: RemediationPlan requiring approval
        """
        approval_alert = Alert(
            id=f"remediation_approval_{plan.plan_id}",
            title=f"Remediation Approval Required: {plan.issue_description}",
            description=f"High-risk remediation plan requires manual approval. "
                       f"Risk level: {plan.overall_risk.value}. "
                       f"Estimated downtime: {plan.estimated_downtime_seconds}s.",
            severity=AlertSeverity.HIGH,
            source=self.agent_id,
            timestamp=datetime.utcnow(),
            tags=['remediation', 'approval_required'],
            metadata={
                'plan_id': plan.plan_id,
                'risk_level': plan.overall_risk.value,
                'estimated_downtime': plan.estimated_downtime_seconds,
                'requires_approval': True
            }
        )
        
        await self.emit_alert(approval_alert)
        logger.info("Approval requested for remediation plan",
                   plan_id=plan.plan_id, risk=plan.overall_risk.value)
    
    async def _load_remediation_templates(self) -> None:
        """
        Load remediation templates from configuration.
        """
        # This would load predefined remediation templates
        # For now, we use the built-in templates in the create methods
        pass
    
    async def _load_remediation_history(self) -> None:
        """
        Load historical remediation data.
        """
        try:
            history_file = self.data_dir / 'remediation_history.json'
            if history_file.exists():
                async with aiofiles.open(history_file, 'r') as f:
                    data = await f.read()
                    history_data = json.loads(data)
                    
                    # Convert to RemediationHistory objects
                    for item in history_data:
                        history = RemediationHistory(**item)
                        self.remediation_history.append(history)
                
                logger.info("Loaded remediation history",
                           agent_id=self.agent_id,
                           history_count=len(self.remediation_history))
        
        except Exception as e:
            logger.error("Error loading remediation history",
                        agent_id=self.agent_id, error=str(e))
    
    async def _save_remediation_history(self) -> None:
        """
        Save remediation history to disk.
        """
        try:
            history_file = self.data_dir / 'remediation_history.json'
            
            # Convert to serializable format
            history_data = []
            for history in self.remediation_history[-1000:]:  # Keep last 1000 entries
                history_dict = {
                    'execution_id': history.execution_id,
                    'plan_id': history.plan_id,
                    'trigger_alert_id': history.trigger_alert_id,
                    'executed_at': history.executed_at.isoformat(),
                    'executed_by': history.executed_by,
                    'duration_seconds': history.duration_seconds,
                    'success': history.success,
                    'steps_completed': history.steps_completed,
                    'steps_failed': history.steps_failed,
                    'effectiveness_score': history.effectiveness_score
                }
                history_data.append(history_dict)
            
            async with aiofiles.open(history_file, 'w') as f:
                await f.write(json.dumps(history_data, indent=2))
            
            logger.info("Saved remediation history",
                       agent_id=self.agent_id,
                       history_count=len(history_data))
        
        except Exception as e:
            logger.error("Error saving remediation history",
                        agent_id=self.agent_id, error=str(e))
    
    async def _cleanup_old_remediations(self) -> None:
        """
        Clean up old remediation data.
        """
        try:
            current_time = datetime.utcnow()
            
            # Remove old history entries (keep last 30 days)
            cutoff_time = current_time - timedelta(days=30)
            self.remediation_history = [
                history for history in self.remediation_history
                if history.executed_at > cutoff_time
            ]
            
            # Clean up cooldown periods
            expired_cooldowns = []
            for component, cooldown_until in self.cooldown_periods.items():
                if current_time > cooldown_until:
                    expired_cooldowns.append(component)
            
            for component in expired_cooldowns:
                del self.cooldown_periods[component]
            
        except Exception as e:
            logger.error("Error during remediation cleanup",
                        agent_id=self.agent_id, error=str(e))
    
    async def _validate_configuration(self) -> None:
        """
        Validate remediation agent configuration.
        """
        if not self.app_restart_command:
            logger.warning("No application restart command configured",
                          agent_id=self.agent_id)
        
        if not self.app_health_check_url:
            logger.warning("No application health check URL configured",
                          agent_id=self.agent_id)
        
        if self.max_concurrent_remediations < 1:
            logger.warning("Invalid max_concurrent_remediations setting",
                          agent_id=self.agent_id,
                          value=self.max_concurrent_remediations)
    
    async def _emit_remediation_metrics(self, results: Dict[str, Any]) -> None:
        """
        Emit remediation performance metrics.
        
        Args:
            results: Execution results to emit as metrics
        """
        timestamp = datetime.utcnow()
        
        for metric_name, value in results.items():
            if isinstance(value, (int, float)):
                await self.emit_metric(MonitoringMetric(
                    name=f"remediation_{metric_name}",
                    value=value,
                    timestamp=timestamp,
                    tags={'agent': self.agent_id}
                ))
        
        # Emit success rates
        for action_type, success_rate in self.success_rates.items():
            await self.emit_metric(MonitoringMetric(
                name="remediation_success_rate",
                value=success_rate,
                timestamp=timestamp,
                tags={'agent': self.agent_id, 'action_type': action_type.value}
            ))


# =============================================================================
# AGENT FACTORY REGISTRATION
# =============================================================================

@AgentFactory.register('remediation')
class RemediationAgentFactory:
    """Factory for creating RemediationAgent instances."""
    
    @staticmethod
    def create_agent(agent_id: str, config: Dict[str, Any]) -> RemediationAgent:
        """
        Create a new RemediationAgent instance.
        
        Args:
            agent_id: Unique identifier for the agent
            config: Configuration dictionary
            
        Returns:
            Configured RemediationAgent instance
        """
        return RemediationAgent(agent_id, config)
    
    @staticmethod
    def get_default_config() -> Dict[str, Any]:
        """
        Get default configuration for RemediationAgent.
        
        Returns:
            Default configuration dictionary
        """
        return {
            'auto_approve_low_risk': True,
            'auto_approve_medium_risk': False,
            'max_concurrent_remediations': 3,
            'default_timeout_seconds': 300,
            'enable_rollback': True,
            'max_remediations_per_hour': 10,
            'data_directory': '/var/lib/crown-jewel/remediation',
            'java_application': {
                'restart_command': 'systemctl restart crown-jewel-app',
                'health_check_url': 'http://localhost:8080/actuator/health',
                'jmx_host': 'localhost',
                'jmx_port': 9999
            }
        }