#!/usr/bin/env python3
"""
Crown Jewel Monitor - Core Module
"""

from .agent_framework import (
    BaseAgent,
    AgentOrchestrator,
    AgentFactory,
    Alert,
    AlertSeverity,
    MonitoringMetric,
    RemediationAction
)

from .alerting_system import (
    AlertingSystem,
    NotificationChannel,
    NotificationChannelConfig,
    EscalationRule,
    AlertContext
)

__all__ = [
    # Agent framework
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
    'NotificationChannelConfig',
    'EscalationRule',
    'AlertContext'
]