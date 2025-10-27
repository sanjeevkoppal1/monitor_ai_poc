#!/usr/bin/env python3
"""
Crown Jewel Java Application Monitor - Agent Framework
Agentic monitoring system for post-deployment Java application health and auto-remediation.

This module provides the core framework for building autonomous monitoring agents that can:
1. Monitor Java applications through various channels (logs, metrics, health checks)
2. Detect issues and anomalies proactively
3. Execute automated remediation actions
4. Escalate critical issues to human operators
5. Learn from past incidents to improve detection and remediation
"""

import asyncio
import logging
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, Union
from datetime import datetime, timedelta
from enum import Enum
import structlog

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================
# Configure structured logging for better observability and debugging
# Uses JSON format for easy parsing by log aggregation systems like Splunk
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,          # Filter by log level
        structlog.stdlib.add_logger_name,          # Add logger name to each log
        structlog.stdlib.add_log_level,            # Add log level to each log
        structlog.stdlib.PositionalArgumentsFormatter(),  # Format positional args
        structlog.processors.TimeStamper(fmt="iso"),       # Add ISO timestamp
        structlog.processors.StackInfoRenderer(),          # Add stack traces
        structlog.processors.format_exc_info,             # Format exceptions
        structlog.processors.UnicodeDecoder(),             # Handle unicode
        structlog.processors.JSONRenderer()               # Output as JSON
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


# =============================================================================
# ENUMERATIONS AND DATA STRUCTURES
# =============================================================================

class AlertSeverity(Enum):
    """
    Alert severity levels for incident classification.
    Used to prioritize alerts and determine escalation paths.
    """
    LOW = "low"         # Minor issues, informational
    MEDIUM = "medium"   # Issues that may impact performance
    HIGH = "high"       # Issues that impact availability
    CRITICAL = "critical"  # Issues that cause service outage


class AgentState(Enum):
    """
    Agent execution states for lifecycle management.
    Helps track agent health and troubleshoot issues.
    """
    IDLE = "idle"           # Agent is idle, waiting for next execution
    RUNNING = "running"     # Agent is currently executing
    ERROR = "error"         # Agent encountered an error
    DISABLED = "disabled"   # Agent is disabled and won't execute


@dataclass
class Alert:
    """
    Alert data structure for incident tracking.
    
    Contains all information needed to understand, route, and resolve an alert.
    Supports the full incident lifecycle from detection to resolution.
    """
    id: str                                    # Unique alert identifier
    title: str                                 # Human-readable alert title
    description: str                           # Detailed alert description
    severity: AlertSeverity                    # Alert severity level
    source: str                               # Source agent/system that generated alert
    timestamp: datetime                        # When alert was generated
    metadata: Dict[str, Any] = field(default_factory=dict)  # Additional context data
    resolved: bool = False                     # Whether alert has been resolved
    resolution_timestamp: Optional[datetime] = None  # When alert was resolved
    resolution_notes: Optional[str] = None    # How alert was resolved


@dataclass
class MonitoringMetric:
    """
    Monitoring metric data structure for performance tracking.
    
    Represents a single metric measurement with context and threshold information.
    Used for trend analysis, alerting, and automated decision making.
    """
    name: str                                  # Metric name (e.g., "cpu_usage")
    value: Union[int, float, str, bool]        # Metric value
    unit: str                                  # Unit of measurement (e.g., "percent", "ms")
    timestamp: datetime                        # When metric was collected
    labels: Dict[str, str] = field(default_factory=dict)  # Metric labels/tags
    threshold_violated: bool = False           # Whether metric exceeded threshold


@dataclass
class RemediationAction:
    """
    Remediation action data structure for automated problem resolution.
    
    Defines an action that can be taken to resolve an issue, including
    execution parameters, safety controls, and success tracking.
    """
    id: str                                    # Unique action identifier
    name: str                                  # Human-readable action name
    description: str                           # What this action does
    agent_type: str                           # Which agent type can execute this
    parameters: Dict[str, Any] = field(default_factory=dict)  # Action parameters
    auto_execute: bool = False                 # Can be executed automatically
    approval_required: bool = True             # Requires human approval
    success_rate: float = 0.0                # Historical success rate (0.0-1.0)
    last_executed: Optional[datetime] = None  # When action was last executed


# =============================================================================
# BASE AGENT CLASS
# =============================================================================

class BaseAgent(ABC):
    """
    Base class for all monitoring and remediation agents.
    
    Provides common functionality for:
    - Agent lifecycle management (initialize, execute, cleanup)
    - Event handling (alerts, metrics, actions)
    - Error handling and recovery
    - Status reporting and health monitoring
    - Callback system for inter-agent communication
    
    All specific agent types (Splunk, Java health, etc.) inherit from this class.
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        """
        Initialize base agent with name and configuration.
        
        Args:
            name: Unique agent name for identification
            config: Agent-specific configuration dictionary
        """
        self.name = name
        self.config = config
        self.state = AgentState.IDLE
        self.logger = structlog.get_logger().bind(agent=name)  # Agent-specific logger
        
        # Data storage for agent outputs
        self.metrics: List[MonitoringMetric] = []      # Collected metrics
        self.alerts: List[Alert] = []                  # Generated alerts
        self.actions: List[RemediationAction] = []     # Available actions
        
        # Execution tracking
        self.last_run: Optional[datetime] = None       # Last execution time
        self.run_count = 0                            # Total execution count
        self.error_count = 0                          # Total error count
        
        # Event callback system for communication with orchestrator and other agents
        self.callbacks: Dict[str, List[Callable]] = {
            'on_alert': [],     # Called when agent generates an alert
            'on_metric': [],    # Called when agent collects a metric
            'on_action': [],    # Called when agent executes an action
            'on_error': []      # Called when agent encounters an error
        }
    
    # -------------------------------------------------------------------------
    # ABSTRACT METHODS - Must be implemented by concrete agent classes
    # -------------------------------------------------------------------------
    
    @abstractmethod
    async def initialize(self) -> bool:
        """
        Initialize the agent with required resources and connections.
        
        This method should:
        - Establish connections to external systems (Splunk, databases, etc.)
        - Validate configuration
        - Set up monitoring targets
        - Initialize any required state
        
        Returns:
            bool: True if initialization successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def execute(self) -> Dict[str, Any]:
        """
        Execute the agent's main monitoring/remediation logic.
        
        This method should:
        - Collect metrics from monitored systems
        - Analyze data for anomalies or issues
        - Generate alerts for detected problems
        - Execute approved remediation actions
        - Return execution results
        
        Returns:
            Dict[str, Any]: Execution results and status
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """
        Cleanup resources when agent stops.
        
        This method should:
        - Close connections to external systems
        - Save any pending state
        - Release allocated resources
        - Perform graceful shutdown
        """
        pass
    
    # -------------------------------------------------------------------------
    # EVENT HANDLING METHODS
    # -------------------------------------------------------------------------
    
    def register_callback(self, event_type: str, callback: Callable):
        """
        Register a callback for specific events.
        
        Enables communication between agents and with the orchestrator.
        Callbacks are called asynchronously when events occur.
        
        Args:
            event_type: Type of event ('on_alert', 'on_metric', 'on_action', 'on_error')
            callback: Async function to call when event occurs
        """
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    async def emit_alert(self, alert: Alert) -> None:
        """
        Emit an alert when an issue is detected.
        
        This method:
        - Stores the alert in the agent's alert list
        - Logs the alert with structured logging
        - Notifies all registered alert callbacks
        - Handles callback errors gracefully
        
        Args:
            alert: Alert object containing issue details
        """
        self.alerts.append(alert)
        self.logger.warning("alert_emitted", 
                          alert_id=alert.id, 
                          severity=alert.severity.value,
                          title=alert.title)
        
        # Notify all alert callbacks
        for callback in self.callbacks['on_alert']:
            try:
                await callback(alert)
            except Exception as e:
                self.logger.error("callback_error", callback=str(callback), error=str(e))
    
    async def emit_metric(self, metric: MonitoringMetric) -> None:
        """
        Emit a metric when data is collected.
        
        This method:
        - Stores the metric in the agent's metric list
        - Logs threshold violations
        - Notifies all registered metric callbacks
        - Handles callback errors gracefully
        
        Args:
            metric: MonitoringMetric object containing measurement data
        """
        self.metrics.append(metric)
        
        # Log threshold violations for immediate visibility
        if metric.threshold_violated:
            self.logger.warning("metric_threshold_violated",
                              metric=metric.name,
                              value=metric.value,
                              labels=metric.labels)
        
        # Notify all metric callbacks
        for callback in self.callbacks['on_metric']:
            try:
                await callback(metric)
            except Exception as e:
                self.logger.error("callback_error", callback=str(callback), error=str(e))
    
    async def execute_action(self, action: RemediationAction) -> bool:
        """
        Execute a remediation action to resolve an issue.
        
        This method:
        - Logs action execution start
        - Calls the action implementation
        - Updates action success rate based on result
        - Notifies action callbacks
        - Handles execution errors gracefully
        
        Args:
            action: RemediationAction to execute
            
        Returns:
            bool: True if action succeeded, False otherwise
        """
        try:
            self.logger.info("executing_action", 
                           action_id=action.id,
                           action_name=action.name)
            
            # Execute the actual action implementation
            result = await self._execute_action_impl(action)
            action.last_executed = datetime.utcnow()
            
            # Update success rate based on result
            if result:
                action.success_rate = min(1.0, action.success_rate + 0.1)  # Increase by 10%
                self.logger.info("action_success", action_id=action.id)
            else:
                action.success_rate = max(0.0, action.success_rate - 0.2)  # Decrease by 20%
                self.logger.error("action_failed", action_id=action.id)
            
            # Notify action callbacks
            for callback in self.callbacks['on_action']:
                try:
                    await callback(action, result)
                except Exception as e:
                    self.logger.error("callback_error", callback=str(callback), error=str(e))
            
            return result
            
        except Exception as e:
            self.logger.error("action_execution_error", 
                            action_id=action.id, 
                            error=str(e))
            return False
    
    async def _execute_action_impl(self, action: RemediationAction) -> bool:
        """
        Override this method to implement specific action execution.
        
        Default implementation returns True (success).
        Concrete agent classes should override this to implement actual actions.
        
        Args:
            action: RemediationAction to execute
            
        Returns:
            bool: True if action succeeded, False otherwise
        """
        return True
    
    # -------------------------------------------------------------------------
    # EXECUTION AND LIFECYCLE METHODS
    # -------------------------------------------------------------------------
    
    async def run_once(self) -> Dict[str, Any]:
        """
        Run the agent once with full error handling and metrics tracking.
        
        This method:
        - Tracks execution time and run counts
        - Updates agent state during execution
        - Handles errors and updates error counts
        - Notifies error callbacks on failure
        - Returns execution results
        
        Returns:
            Dict[str, Any]: Execution results
            
        Raises:
            Exception: Re-raises any exception from agent execution
        """
        start_time = time.time()
        self.state = AgentState.RUNNING
        self.run_count += 1
        
        try:
            # Execute the agent's main logic
            result = await self.execute()
            self.last_run = datetime.utcnow()
            execution_time = time.time() - start_time
            
            self.logger.info("agent_execution_complete",
                           execution_time=execution_time,
                           run_count=self.run_count)
            
            self.state = AgentState.IDLE
            return result
            
        except Exception as e:
            self.error_count += 1
            self.state = AgentState.ERROR
            self.logger.error("agent_execution_error", error=str(e))
            
            # Notify error callbacks
            for callback in self.callbacks['on_error']:
                try:
                    await callback(e)
                except Exception as callback_error:
                    self.logger.error("callback_error", error=str(callback_error))
            
            raise  # Re-raise the exception for higher-level handling
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get comprehensive agent status for monitoring and debugging.
        
        Provides key metrics about agent health, performance, and recent activity.
        Used by the orchestrator for system health monitoring.
        
        Returns:
            Dict[str, Any]: Agent status information
        """
        return {
            "name": self.name,
            "state": self.state.value,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "run_count": self.run_count,
            "error_count": self.error_count,
            "alerts_count": len(self.alerts),
            "metrics_count": len(self.metrics),
            "success_rate": 1.0 - (self.error_count / max(1, self.run_count))
        }


# =============================================================================
# AGENT ORCHESTRATOR
# =============================================================================

class AgentOrchestrator:
    """
    Orchestrates multiple monitoring and remediation agents.
    
    The orchestrator is the central coordinator that:
    - Manages multiple agents (registration, lifecycle)
    - Coordinates agent execution (single, all, continuous)
    - Handles global event processing (alerts, metrics, errors)
    - Provides system-wide status and health monitoring
    - Implements alert handling and escalation
    
    This is the main entry point for the monitoring system.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the orchestrator with configuration.
        
        Args:
            config: Global configuration dictionary
        """
        self.config = config
        self.agents: Dict[str, BaseAgent] = {}     # Registered agents
        self.running = False                       # Continuous monitoring state
        self.logger = structlog.get_logger().bind(component="orchestrator")
        self.alert_handlers: List[Callable] = []  # Global alert handlers
        self.global_metrics: Dict[str, Any] = {}  # Global metrics storage
        self.alerting_system = None                # Alerting system reference
        
    def register_agent(self, agent: BaseAgent) -> None:
        """
        Register an agent with the orchestrator.
        
        This method:
        - Adds the agent to the managed agents list
        - Registers global event callbacks for the agent
        - Logs the registration for audit trail
        
        Args:
            agent: BaseAgent instance to register
        """
        self.agents[agent.name] = agent
        
        # Register global callbacks to handle events from this agent
        agent.register_callback('on_alert', self._handle_global_alert)
        agent.register_callback('on_metric', self._handle_global_metric)
        agent.register_callback('on_error', self._handle_global_error)
        
        self.logger.info("agent_registered", agent_name=agent.name)
    
    def set_alerting_system(self, alerting_system) -> None:
        """
        Set the alerting system for the orchestrator.
        
        Args:
            alerting_system: AlertingSystem instance for sending alerts
        """
        self.alerting_system = alerting_system
        self.logger.info("alerting_system_connected")
    
    async def initialize(self) -> bool:
        """
        Initialize the orchestrator.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            self.logger.info("orchestrator_initializing")
            # Additional initialization logic can be added here
            self.logger.info("orchestrator_initialized_successfully")
            return True
        except Exception as e:
            self.logger.error("orchestrator_initialization_failed", error=str(e))
            return False
    
    # -------------------------------------------------------------------------
    # GLOBAL EVENT HANDLERS
    # -------------------------------------------------------------------------
    
    async def _handle_global_alert(self, alert: Alert) -> None:
        """
        Handle alerts from any agent at the global level.
        
        This method:
        - Logs all alerts for central visibility
        - Routes alerts through registered alert handlers
        - Implements escalation logic for critical alerts
        - Handles alert processing errors gracefully
        
        Args:
            alert: Alert from any agent
        """
        self.logger.warning("global_alert", 
                          agent=alert.source,
                          alert_id=alert.id,
                          severity=alert.severity.value)
        
        # Send alert through alerting system if available
        if self.alerting_system:
            try:
                await self.alerting_system.send_alert(alert)
            except Exception as e:
                self.logger.error("alerting_system_error", error=str(e))
        
        # Process through all registered alert handlers
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                self.logger.error("alert_handler_error", error=str(e))
    
    async def _handle_global_metric(self, metric: MonitoringMetric) -> None:
        """
        Handle metrics from any agent at the global level.
        
        This method:
        - Stores metrics in global metrics storage
        - Implements metric retention policy (1 hour)
        - Enables cross-agent metric correlation
        - Supports system-wide performance monitoring
        
        Args:
            metric: MonitoringMetric from any agent
        """
        # Create unique key for metric storage
        metric_key = f"{metric.name}_{metric.timestamp.isoformat()}"
        self.global_metrics[metric_key] = {
            "name": metric.name,
            "value": metric.value,
            "unit": metric.unit,
            "timestamp": metric.timestamp.isoformat(),
            "labels": metric.labels,
            "threshold_violated": metric.threshold_violated
        }
        
        # Implement metric retention policy - keep only last hour of metrics
        cutoff = datetime.utcnow() - timedelta(hours=1)
        self.global_metrics = {
            k: v for k, v in self.global_metrics.items()
            if datetime.fromisoformat(v["timestamp"]) > cutoff
        }
    
    async def _handle_global_error(self, error: Exception) -> None:
        """
        Handle errors from any agent at the global level.
        
        This method:
        - Logs all agent errors for central visibility
        - Could implement error correlation and pattern detection
        - Enables system-wide error monitoring and alerting
        
        Args:
            error: Exception from any agent
        """
        self.logger.error("global_agent_error", error=str(error))
    
    # -------------------------------------------------------------------------
    # AGENT MANAGEMENT METHODS
    # -------------------------------------------------------------------------
    
    async def initialize_all_agents(self) -> Dict[str, bool]:
        """
        Initialize all registered agents.
        
        This method:
        - Calls initialize() on each registered agent
        - Tracks initialization success/failure for each agent
        - Logs initialization results
        - Returns status for each agent
        
        Returns:
            Dict[str, bool]: Agent name -> initialization success
        """
        results = {}
        
        for name, agent in self.agents.items():
            try:
                result = await agent.initialize()
                results[name] = result
                if result:
                    self.logger.info("agent_initialized", agent_name=name)
                else:
                    self.logger.error("agent_init_failed", agent_name=name)
            except Exception as e:
                results[name] = False
                self.logger.error("agent_init_error", agent_name=name, error=str(e))
        
        return results
    
    async def run_agent(self, agent_name: str) -> Dict[str, Any]:
        """
        Run a specific agent once.
        
        Useful for:
        - Testing individual agents
        - Manual agent execution
        - Debugging agent issues
        
        Args:
            agent_name: Name of agent to run
            
        Returns:
            Dict[str, Any]: Agent execution results
            
        Raises:
            ValueError: If agent name not found
        """
        if agent_name not in self.agents:
            raise ValueError(f"Agent {agent_name} not found")
        
        agent = self.agents[agent_name]
        return await agent.run_once()
    
    async def run_all_agents_once(self) -> Dict[str, Any]:
        """
        Run all agents once and collect results.
        
        This method:
        - Executes each agent's run_once() method
        - Collects results and errors for each agent
        - Provides system-wide execution status
        - Handles individual agent failures gracefully
        
        Returns:
            Dict[str, Any]: Results for each agent
        """
        results = {}
        
        for name, agent in self.agents.items():
            try:
                result = await agent.run_once()
                results[name] = {"success": True, "result": result}
            except Exception as e:
                results[name] = {"success": False, "error": str(e)}
        
        return results
    
    # -------------------------------------------------------------------------
    # CONTINUOUS MONITORING METHODS
    # -------------------------------------------------------------------------
    
    async def start_continuous_monitoring(self, interval: int = 60) -> None:
        """
        Start continuous monitoring with specified interval.
        
        This method:
        - Runs all agents repeatedly at specified intervals
        - Handles execution errors gracefully to maintain uptime
        - Provides the main monitoring loop for production use
        - Can be stopped with stop_monitoring()
        
        Args:
            interval: Seconds between monitoring cycles
        """
        self.running = True
        self.logger.info("starting_continuous_monitoring", interval=interval)
        
        while self.running:
            try:
                await self.run_all_agents_once()
                await asyncio.sleep(interval)
            except Exception as e:
                self.logger.error("monitoring_cycle_error", error=str(e))
                await asyncio.sleep(interval)  # Continue monitoring despite errors
    
    def stop_monitoring(self) -> None:
        """
        Stop continuous monitoring gracefully.
        
        Sets the running flag to False, which will cause the monitoring
        loop to exit after the current cycle completes.
        """
        self.running = False
        self.logger.info("stopping_monitoring")
    
    async def cleanup_all_agents(self) -> None:
        """
        Cleanup all agents gracefully.
        
        This method:
        - Calls cleanup() on each registered agent
        - Handles cleanup errors for individual agents
        - Ensures resources are released properly
        - Should be called before system shutdown
        """
        for name, agent in self.agents.items():
            try:
                await agent.cleanup()
                self.logger.info("agent_cleaned_up", agent_name=name)
            except Exception as e:
                self.logger.error("agent_cleanup_error", agent_name=name, error=str(e))
    
    # -------------------------------------------------------------------------
    # STATUS AND HEALTH MONITORING
    # -------------------------------------------------------------------------
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get comprehensive system status for monitoring dashboard.
        
        Provides:
        - Overall system health assessment
        - Individual agent statuses
        - System-wide metrics and counts
        - Performance indicators
        
        Returns:
            Dict[str, Any]: Complete system status
        """
        # Get status from all agents
        agent_statuses = {name: agent.get_status() for name, agent in self.agents.items()}
        
        # Calculate system-wide metrics
        total_alerts = sum(len(agent.alerts) for agent in self.agents.values())
        total_errors = sum(agent.error_count for agent in self.agents.values())
        total_runs = sum(agent.run_count for agent in self.agents.values())
        
        return {
            "orchestrator": {
                "running": self.running,
                "agents_count": len(self.agents),
                "total_alerts": total_alerts,
                "total_errors": total_errors,
                "total_runs": total_runs,
                "system_health": "healthy" if total_errors < total_runs * 0.1 else "degraded"
            },
            "agents": agent_statuses,
            "global_metrics_count": len(self.global_metrics),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def register_alert_handler(self, handler: Callable) -> None:
        """
        Register a global alert handler for custom alert processing.
        
        Alert handlers can implement:
        - Custom notification channels (Slack, email, PagerDuty)
        - Alert enrichment and correlation
        - Escalation workflows
        - Integration with ITSM systems
        
        Args:
            handler: Async function that takes an Alert parameter
        """
        self.alert_handlers.append(handler)


# =============================================================================
# AGENT FACTORY AND CONFIGURATION
# =============================================================================

class AgentFactory:
    """
    Factory for creating different types of agents.
    
    Implements the factory pattern to:
    - Decouple agent creation from agent usage
    - Support registration of new agent types
    - Provide consistent agent creation interface
    - Enable configuration-driven agent instantiation
    """
    
    _agent_types: Dict[str, type] = {}  # Registry of available agent types
    
    @classmethod
    def register_agent_type(cls, agent_type: str, agent_class: type) -> None:
        """
        Register an agent type for creation.
        
        This allows new agent types to be added to the system without
        modifying the factory code. Each agent type maps to a class
        that inherits from BaseAgent.
        
        Args:
            agent_type: String identifier for the agent type
            agent_class: Class that implements the agent (must inherit from BaseAgent)
        """
        cls._agent_types[agent_type] = agent_class
    
    @classmethod
    def create_agent(cls, agent_type: str, name: str, config: Dict[str, Any]) -> BaseAgent:
        """
        Create an agent of the specified type.
        
        Args:
            agent_type: Type of agent to create
            name: Unique name for the agent instance
            config: Configuration for the agent
            
        Returns:
            BaseAgent: Created agent instance
            
        Raises:
            ValueError: If agent type is not registered
        """
        if agent_type not in cls._agent_types:
            raise ValueError(f"Unknown agent type: {agent_type}")
        
        agent_class = cls._agent_types[agent_type]
        return agent_class(name, config)
    
    @classmethod
    def get_available_types(cls) -> List[str]:
        """
        Get list of available agent types.
        
        Returns:
            List[str]: Available agent type identifiers
        """
        return list(cls._agent_types.keys())


class AgentConfig:
    """
    Agent configuration management utility.
    
    Provides structured access to configuration data for:
    - Individual agent configurations
    - Global system settings
    - External system configurations (Splunk, Java app, etc.)
    - Alert and notification settings
    """
    
    def __init__(self, config_dict: Dict[str, Any]):
        """
        Initialize with configuration dictionary.
        
        Args:
            config_dict: Complete configuration dictionary
        """
        self.config = config_dict
    
    def get_agent_config(self, agent_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific agent.
        
        Args:
            agent_name: Name of the agent
            
        Returns:
            Dict[str, Any]: Agent-specific configuration
        """
        return self.config.get("agents", {}).get(agent_name, {})
    
    def get_global_config(self) -> Dict[str, Any]:
        """
        Get global configuration settings.
        
        Returns:
            Dict[str, Any]: Global configuration
        """
        return self.config.get("global", {})
    
    def get_splunk_config(self) -> Dict[str, Any]:
        """
        Get Splunk integration configuration.
        
        Returns:
            Dict[str, Any]: Splunk configuration
        """
        return self.config.get("splunk", {})
    
    def get_java_app_config(self) -> Dict[str, Any]:
        """
        Get Java application monitoring configuration.
        
        Returns:
            Dict[str, Any]: Java application configuration
        """
        return self.config.get("java_application", {})
    
    def get_alerting_config(self) -> Dict[str, Any]:
        """
        Get alerting and notification configuration.
        
        Returns:
            Dict[str, Any]: Alerting configuration
        """
        return self.config.get("alerting", {})


# =============================================================================
# MODULE EXPORTS
# =============================================================================
# Export main classes and enums for use by other modules
__all__ = [
    'BaseAgent',           # Base class for all agents
    'AgentOrchestrator',   # Main orchestrator class
    'AgentFactory',        # Factory for creating agents
    'AgentConfig',         # Configuration management
    'Alert',               # Alert data structure
    'AlertSeverity',       # Alert severity enumeration
    'MonitoringMetric',    # Metric data structure
    'RemediationAction',   # Action data structure
    'AgentState'           # Agent state enumeration
]