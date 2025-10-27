#!/usr/bin/env python3
"""
Crown Jewel Java Application Monitor
Agentic Post-Deployment Monitoring and Auto-Remediation System

A comprehensive, intelligent monitoring solution designed for crown jewel Java applications.
"""

__version__ = "1.0.0"
__author__ = "Crown Jewel Monitor Team"
__email__ = "monitoring-support@company.com"

from .core.agent_framework import (
    BaseAgent,
    AgentOrchestrator,
    AgentFactory,
    Alert,
    AlertSeverity,
    MonitoringMetric,
    RemediationAction
)

from .core.alerting_system import (
    AlertingSystem,
    NotificationChannel,
    EscalationRule,
    AlertContext
)

__all__ = [
    # Core framework
    'BaseAgent',
    'AgentOrchestrator', 
    'AgentFactory',
    'Alert',
    'AlertSeverity',
    'MonitoringMetric',
    'RemediationAction',
    
    # Alerting system
    'AlertingSystem',
    'NotificationChannel',
    'EscalationRule',
    'AlertContext',
    
    # Version info
    '__version__',
    '__author__',
    '__email__'
]