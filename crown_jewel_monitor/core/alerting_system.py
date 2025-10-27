#!/usr/bin/env python3
"""
Crown Jewel Java Application Monitor - Alerting and Escalation System
Comprehensive alerting system with intelligent routing, escalation, and notification delivery.

This system provides:
1. Multi-channel alert delivery (Slack, Email, PagerDuty, SMS, Webhooks)
2. Intelligent alert routing based on severity, content, and time
3. Escalation workflows with time-based and acknowledgment-based triggers
4. Alert suppression and deduplication to prevent alert fatigue
5. Rich notification formatting with context and remediation suggestions
6. Delivery tracking and retry mechanisms for reliable notifications
"""

import asyncio
import json
import time
import hashlib
import smtplib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set, Callable
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid

# HTTP clients and networking
import aiohttp
import requests

# Template rendering
try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

from .agent_framework import Alert, AlertSeverity, MonitoringMetric

import structlog
logger = structlog.get_logger()


# =============================================================================
# ALERTING DATA STRUCTURES
# =============================================================================

class NotificationChannel(Enum):
    """Types of notification channels available."""
    SLACK = "slack"
    EMAIL = "email"
    PAGERDUTY = "pagerduty"
    SMS = "sms"
    WEBHOOK = "webhook"
    TEAMS = "teams"
    DISCORD = "discord"


class EscalationTrigger(Enum):
    """Triggers for alert escalation."""
    TIME_BASED = "time_based"           # Escalate after time period
    ACKNOWLEDGMENT_TIMEOUT = "ack_timeout"  # Escalate if not acknowledged
    SEVERITY_INCREASE = "severity_increase"  # Escalate if severity increases
    REPEAT_OCCURRENCE = "repeat_occurrence"  # Escalate on repeated alerts
    MANUAL = "manual"                   # Manual escalation trigger


class AlertState(Enum):
    """States of an alert in the system."""
    NEW = "new"                        # Newly created alert
    SENT = "sent"                      # Alert has been sent
    ACKNOWLEDGED = "acknowledged"       # Alert has been acknowledged
    ESCALATED = "escalated"            # Alert has been escalated
    RESOLVED = "resolved"              # Alert has been resolved
    SUPPRESSED = "suppressed"          # Alert is suppressed
    EXPIRED = "expired"                # Alert has expired


@dataclass
class NotificationTemplate:
    """
    Template for formatting notifications for different channels.
    Supports Jinja2 templating for dynamic content generation.
    """
    channel: NotificationChannel       # Target notification channel
    template_name: str                 # Unique template identifier
    
    # Template content
    subject_template: str              # Subject/title template
    body_template: str                 # Message body template
    
    # Channel-specific formatting
    format_type: str = "text"          # text, html, markdown, json
    include_metadata: bool = True      # Include alert metadata
    include_remediation: bool = True   # Include remediation suggestions
    
    # Rendering options
    max_length: Optional[int] = None   # Maximum message length
    truncate_behavior: str = "truncate"  # truncate, summarize, split
    
    # Custom fields
    custom_fields: Dict[str, str] = field(default_factory=dict)


@dataclass
class NotificationChannelConfig:
    """
    Configuration for a specific notification channel.
    Contains delivery settings and channel-specific parameters.
    """
    channel_id: str                    # Unique channel identifier
    channel_type: NotificationChannel # Type of notification channel
    name: str                         # Human-readable channel name
    
    # Delivery settings
    enabled: bool = True              # Whether channel is active
    severity_filter: List[AlertSeverity] = field(default_factory=list)  # Severity levels to send
    
    # Channel configuration
    config: Dict[str, Any] = field(default_factory=dict)  # Channel-specific settings
    
    # Rate limiting
    rate_limit_per_hour: int = 100    # Maximum notifications per hour
    burst_limit: int = 10             # Maximum notifications in burst
    
    # Retry settings
    retry_attempts: int = 3           # Number of retry attempts
    retry_delay_seconds: int = 30     # Delay between retries
    timeout_seconds: int = 30         # Request timeout
    
    # Delivery tracking
    success_count: int = 0            # Successful deliveries
    failure_count: int = 0            # Failed deliveries
    last_delivery: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    
    # Templates
    templates: Dict[str, NotificationTemplate] = field(default_factory=dict)


@dataclass
class EscalationRule:
    """
    Rules defining when and how to escalate alerts.
    Supports multiple escalation paths and complex conditions.
    """
    rule_id: str                      # Unique rule identifier
    name: str                         # Human-readable rule name
    description: str                  # Rule description
    
    # Trigger conditions
    trigger_type: EscalationTrigger   # What triggers escalation
    trigger_conditions: Dict[str, Any] = field(default_factory=dict)
    
    # Alert matching criteria
    severity_levels: List[AlertSeverity] = field(default_factory=list)
    alert_patterns: List[str] = field(default_factory=list)  # Regex patterns
    source_agents: List[str] = field(default_factory=list)  # Source agent filters
    tag_filters: List[str] = field(default_factory=list)    # Required tags
    
    # Escalation timing
    initial_delay_minutes: int = 0    # Initial delay before first escalation
    escalation_interval_minutes: int = 30  # Time between escalation levels
    max_escalations: int = 3          # Maximum escalation levels
    
    # Escalation actions
    escalation_channels: List[str] = field(default_factory=list)  # Channels for each level
    escalation_recipients: Dict[int, List[str]] = field(default_factory=dict)
    
    # Active state
    enabled: bool = True
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0


@dataclass
class AlertDelivery:
    """
    Tracking information for alert delivery attempts.
    Records success/failure and provides delivery audit trail.
    """
    delivery_id: str                  # Unique delivery identifier
    alert_id: str                     # Associated alert ID
    channel_id: str                   # Target channel ID
    
    # Delivery details
    attempted_at: datetime            # When delivery was attempted
    completed_at: Optional[datetime] = None
    delivery_status: str = "pending"  # pending, sent, failed, retry
    
    # Delivery content
    subject: str = ""                 # Delivered subject/title
    message: str = ""                 # Delivered message content
    
    # Result tracking
    success: bool = False             # Whether delivery succeeded
    error_message: Optional[str] = None
    response_data: Dict[str, Any] = field(default_factory=dict)
    
    # Retry information
    retry_count: int = 0              # Number of retry attempts
    next_retry: Optional[datetime] = None


@dataclass
class AlertContext:
    """
    Extended context and state for an alert in the alerting system.
    Tracks delivery, escalation, and acknowledgment state.
    """
    alert: Alert                      # Original alert object
    
    # State tracking
    current_state: AlertState = AlertState.NEW
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    # Delivery tracking
    deliveries: List[AlertDelivery] = field(default_factory=list)
    successful_channels: Set[str] = field(default_factory=set)
    failed_channels: Set[str] = field(default_factory=set)
    
    # Escalation tracking
    escalation_level: int = 0         # Current escalation level
    escalated_at: Optional[datetime] = None
    escalation_rules_triggered: List[str] = field(default_factory=list)
    
    # Acknowledgment tracking
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    acknowledgment_comment: Optional[str] = None
    
    # Resolution tracking
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_comment: Optional[str] = None
    
    # Suppression tracking
    suppressed: bool = False
    suppressed_until: Optional[datetime] = None
    suppression_reason: Optional[str] = None
    
    # Metrics
    delivery_attempts: int = 0
    total_delivery_time_ms: float = 0.0


# =============================================================================
# ALERTING SYSTEM IMPLEMENTATION
# =============================================================================

class AlertingSystem:
    """
    Comprehensive alerting and escalation system for the Crown Jewel Monitor.
    
    Features:
    - Multi-channel notification delivery
    - Intelligent alert routing and filtering
    - Time-based and event-based escalation
    - Alert suppression and deduplication
    - Delivery tracking and reliability
    - Template-based message formatting
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the alerting system with configuration.
        
        Args:
            config: Alerting system configuration
        """
        self.config = config
        
        # Core settings
        self.enabled = config.get('enabled', True)
        self.default_severity_threshold = AlertSeverity(config.get('default_severity_threshold', 'medium'))
        self.alert_retention_hours = config.get('alert_retention_hours', 168)  # 1 week
        self.max_alerts_per_hour = config.get('max_alerts_per_hour', 1000)
        
        # State storage
        self.active_alerts: Dict[str, AlertContext] = {}
        self.notification_channels: Dict[str, NotificationChannelConfig] = {}
        self.escalation_rules: Dict[str, EscalationRule] = {}
        self.templates: Dict[str, NotificationTemplate] = {}
        
        # Suppression tracking
        self.suppression_cache: Dict[str, datetime] = {}
        self.alert_fingerprints: Dict[str, datetime] = {}
        
        # Rate limiting
        self.hourly_alert_count: List[datetime] = []
        self.channel_rate_limits: Dict[str, List[datetime]] = {}
        
        # Performance tracking
        self.delivery_stats: Dict[str, Dict[str, int]] = {}
        
        logger.info("AlertingSystem initialized", enabled=self.enabled)
    
    async def initialize(self) -> bool:
        """
        Initialize the alerting system.
        Load channels, templates, and escalation rules.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            logger.info("Initializing AlertingSystem")
            
            # Load notification channels
            await self._load_notification_channels()
            
            # Load notification templates
            await self._load_notification_templates()
            
            # Load escalation rules
            await self._load_escalation_rules()
            
            # Initialize delivery tracking
            await self._initialize_delivery_tracking()
            
            # Start background tasks
            asyncio.create_task(self._escalation_monitor())
            asyncio.create_task(self._cleanup_task())
            asyncio.create_task(self._retry_failed_deliveries())
            
            logger.info("AlertingSystem initialized successfully",
                       channels=len(self.notification_channels),
                       rules=len(self.escalation_rules))
            return True
            
        except Exception as e:
            logger.error("Failed to initialize AlertingSystem", error=str(e))
            return False
    
    async def process_alert(self, alert: Alert) -> AlertContext:
        """
        Process a new alert through the alerting system.
        
        Args:
            alert: Alert to process
            
        Returns:
            AlertContext for the processed alert
        """
        if not self.enabled:
            logger.debug("Alerting system disabled, skipping alert", alert_id=alert.id)
            return None
        
        # Check rate limits
        if not await self._check_rate_limits():
            logger.warning("Alert rate limit exceeded", alert_id=alert.id)
            return None
        
        # Check if alert should be suppressed
        if await self._should_suppress_alert(alert):
            logger.info("Alert suppressed", alert_id=alert.id)
            return None
        
        # Create alert context
        alert_context = AlertContext(alert=alert)
        
        # Store in active alerts
        self.active_alerts[alert.id] = alert_context
        
        logger.info("Processing new alert",
                   alert_id=alert.id,
                   severity=alert.severity.value,
                   source=alert.source)
        
        try:
            # Route alert to appropriate channels
            await self._route_alert(alert_context)
            
            # Check for immediate escalation rules
            await self._check_escalation_rules(alert_context)
            
            # Update alert state
            alert_context.current_state = AlertState.SENT
            alert_context.updated_at = datetime.utcnow()
            
        except Exception as e:
            logger.error("Error processing alert",
                        alert_id=alert.id, error=str(e))
            alert_context.current_state = AlertState.NEW  # Reset state on error
        
        return alert_context
    
    async def acknowledge_alert(self, alert_id: str, acknowledged_by: str,
                              comment: Optional[str] = None) -> bool:
        """
        Acknowledge an alert to stop escalation.
        
        Args:
            alert_id: ID of alert to acknowledge
            acknowledged_by: Who acknowledged the alert
            comment: Optional acknowledgment comment
            
        Returns:
            True if acknowledgment successful, False otherwise
        """
        if alert_id not in self.active_alerts:
            logger.warning("Alert not found for acknowledgment", alert_id=alert_id)
            return False
        
        alert_context = self.active_alerts[alert_id]
        
        if alert_context.current_state in [AlertState.ACKNOWLEDGED, AlertState.RESOLVED]:
            logger.info("Alert already acknowledged or resolved", alert_id=alert_id)
            return True
        
        # Update acknowledgment information
        alert_context.acknowledged_by = acknowledged_by
        alert_context.acknowledged_at = datetime.utcnow()
        alert_context.acknowledgment_comment = comment
        alert_context.current_state = AlertState.ACKNOWLEDGED
        alert_context.updated_at = datetime.utcnow()
        
        logger.info("Alert acknowledged",
                   alert_id=alert_id,
                   acknowledged_by=acknowledged_by)
        
        # Send acknowledgment notifications
        await self._send_acknowledgment_notification(alert_context)
        
        return True
    
    async def resolve_alert(self, alert_id: str, resolved_by: str,
                          resolution: Optional[str] = None) -> bool:
        """
        Resolve an alert to mark it as completed.
        
        Args:
            alert_id: ID of alert to resolve
            resolved_by: Who resolved the alert
            resolution: Optional resolution description
            
        Returns:
            True if resolution successful, False otherwise
        """
        if alert_id not in self.active_alerts:
            logger.warning("Alert not found for resolution", alert_id=alert_id)
            return False
        
        alert_context = self.active_alerts[alert_id]
        
        # Update resolution information
        alert_context.resolved_by = resolved_by
        alert_context.resolved_at = datetime.utcnow()
        alert_context.resolution_comment = resolution
        alert_context.current_state = AlertState.RESOLVED
        alert_context.updated_at = datetime.utcnow()
        
        logger.info("Alert resolved",
                   alert_id=alert_id,
                   resolved_by=resolved_by)
        
        # Send resolution notifications
        await self._send_resolution_notification(alert_context)
        
        return True
    
    # =========================================================================
    # ALERT ROUTING AND DELIVERY
    # =========================================================================
    
    async def _route_alert(self, alert_context: AlertContext) -> None:
        """
        Route alert to appropriate notification channels.
        
        Args:
            alert_context: Alert context to route
        """
        alert = alert_context.alert
        
        # Determine target channels based on alert properties
        target_channels = await self._determine_target_channels(alert)
        
        # Send to each target channel
        delivery_tasks = []
        for channel_id in target_channels:
            if channel_id in self.notification_channels:
                task = self._deliver_to_channel(alert_context, channel_id)
                delivery_tasks.append(task)
        
        # Execute deliveries in parallel
        if delivery_tasks:
            await asyncio.gather(*delivery_tasks, return_exceptions=True)
    
    async def _determine_target_channels(self, alert: Alert) -> List[str]:
        """
        Determine which channels should receive this alert.
        
        Args:
            alert: Alert to route
            
        Returns:
            List of channel IDs to deliver to
        """
        target_channels = []
        
        for channel_id, channel in self.notification_channels.items():
            if not channel.enabled:
                continue
            
            # Check severity filter
            if channel.severity_filter and alert.severity not in channel.severity_filter:
                continue
            
            # Check rate limits for this channel
            if not await self._check_channel_rate_limit(channel_id):
                logger.warning("Channel rate limit exceeded",
                              channel_id=channel_id, alert_id=alert.id)
                continue
            
            # Check if channel is available
            if await self._is_channel_available(channel_id):
                target_channels.append(channel_id)
        
        return target_channels
    
    async def _deliver_to_channel(self, alert_context: AlertContext,
                                channel_id: str) -> None:
        """
        Deliver alert to a specific notification channel.
        
        Args:
            alert_context: Alert context to deliver
            channel_id: Target channel ID
        """
        start_time = time.time()
        channel = self.notification_channels[channel_id]
        alert = alert_context.alert
        
        # Create delivery record
        delivery = AlertDelivery(
            delivery_id=str(uuid.uuid4()),
            alert_id=alert.id,
            channel_id=channel_id,
            attempted_at=datetime.utcnow()
        )
        
        try:
            logger.info("Delivering alert to channel",
                       alert_id=alert.id,
                       channel_id=channel_id,
                       channel_type=channel.channel_type.value)
            
            # Format message for this channel
            subject, message = await self._format_message(alert_context, channel)
            delivery.subject = subject
            delivery.message = message
            
            # Deliver based on channel type
            success = False
            if channel.channel_type == NotificationChannel.SLACK:
                success = await self._deliver_to_slack(channel, subject, message, alert)
            elif channel.channel_type == NotificationChannel.EMAIL:
                success = await self._deliver_to_email(channel, subject, message, alert)
            elif channel.channel_type == NotificationChannel.PAGERDUTY:
                success = await self._deliver_to_pagerduty(channel, subject, message, alert)
            elif channel.channel_type == NotificationChannel.WEBHOOK:
                success = await self._deliver_to_webhook(channel, subject, message, alert)
            elif channel.channel_type == NotificationChannel.TEAMS:
                success = await self._deliver_to_teams(channel, subject, message, alert)
            
            # Update delivery status
            delivery.success = success
            delivery.delivery_status = "sent" if success else "failed"
            delivery.completed_at = datetime.utcnow()
            
            if success:
                alert_context.successful_channels.add(channel_id)
                channel.success_count += 1
                channel.last_delivery = datetime.utcnow()
            else:
                alert_context.failed_channels.add(channel_id)
                channel.failure_count += 1
                channel.last_failure = datetime.utcnow()
                
                # Schedule retry if configured
                if channel.retry_attempts > 0:
                    delivery.next_retry = datetime.utcnow() + timedelta(seconds=channel.retry_delay_seconds)
        
        except Exception as e:
            delivery.success = False
            delivery.delivery_status = "failed"
            delivery.error_message = str(e)
            delivery.completed_at = datetime.utcnow()
            alert_context.failed_channels.add(channel_id)
            
            logger.error("Error delivering alert to channel",
                        alert_id=alert.id,
                        channel_id=channel_id,
                        error=str(e))
        
        finally:
            # Record delivery attempt
            alert_context.deliveries.append(delivery)
            alert_context.delivery_attempts += 1
            alert_context.total_delivery_time_ms += (time.time() - start_time) * 1000
            
            # Update delivery statistics
            if channel_id not in self.delivery_stats:
                self.delivery_stats[channel_id] = {'success': 0, 'failure': 0}
            
            if delivery.success:
                self.delivery_stats[channel_id]['success'] += 1
            else:
                self.delivery_stats[channel_id]['failure'] += 1
    
    # =========================================================================
    # CHANNEL-SPECIFIC DELIVERY IMPLEMENTATIONS
    # =========================================================================
    
    async def _deliver_to_slack(self, channel: NotificationChannelConfig,
                              subject: str, message: str, alert: Alert) -> bool:
        """
        Deliver alert to Slack channel.
        
        Args:
            channel: Slack channel configuration
            subject: Message subject
            message: Message body
            alert: Original alert
            
        Returns:
            True if delivery successful, False otherwise
        """
        try:
            webhook_url = channel.config.get('webhook_url')
            if not webhook_url:
                logger.error("Slack webhook URL not configured", channel_id=channel.channel_id)
                return False
            
            # Create Slack payload
            payload = {
                "text": subject,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🚨 {alert.severity.value.upper()} Alert"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{subject}*\n{message}"
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"Source: {alert.source} | Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
                            }
                        ]
                    }
                ]
            }
            
            # Add color based on severity
            color_map = {
                AlertSeverity.CRITICAL: "danger",
                AlertSeverity.HIGH: "warning",
                AlertSeverity.MEDIUM: "warning",
                AlertSeverity.LOW: "good"
            }
            payload["attachments"] = [{
                "color": color_map.get(alert.severity, "warning")
            }]
            
            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=channel.timeout_seconds)
                ) as response:
                    return response.status == 200
        
        except Exception as e:
            logger.error("Error delivering to Slack", error=str(e))
            return False
    
    async def _deliver_to_email(self, channel: NotificationChannelConfig,
                              subject: str, message: str, alert: Alert) -> bool:
        """
        Deliver alert via email.
        
        Args:
            channel: Email channel configuration
            subject: Email subject
            message: Email body
            alert: Original alert
            
        Returns:
            True if delivery successful, False otherwise
        """
        try:
            config = channel.config
            smtp_host = config.get('smtp_host')
            smtp_port = config.get('smtp_port', 587)
            smtp_username = config.get('smtp_username')
            smtp_password = config.get('smtp_password')
            from_address = config.get('from_address')
            recipients = config.get('recipients', [])
            
            if not all([smtp_host, smtp_username, smtp_password, from_address]):
                logger.error("Email configuration incomplete", channel_id=channel.channel_id)
                return False
            
            # Determine recipients based on severity
            if isinstance(recipients, dict):
                severity_recipients = recipients.get(alert.severity.value, recipients.get('default', []))
            else:
                severity_recipients = recipients
            
            if not severity_recipients:
                logger.warning("No recipients configured for severity", severity=alert.severity.value)
                return False
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = from_address
            msg['To'] = ', '.join(severity_recipients)
            msg['Subject'] = subject
            
            # Add HTML body if configured
            if config.get('html_format', False):
                html_message = message.replace('\n', '<br>')
                msg.attach(MIMEText(html_message, 'html'))
            else:
                msg.attach(MIMEText(message, 'plain'))
            
            # Send email
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
            server.quit()
            
            return True
        
        except Exception as e:
            logger.error("Error delivering email", error=str(e))
            return False
    
    async def _deliver_to_pagerduty(self, channel: NotificationChannelConfig,
                                  subject: str, message: str, alert: Alert) -> bool:
        """
        Deliver alert to PagerDuty.
        
        Args:
            channel: PagerDuty channel configuration
            subject: Alert subject
            message: Alert message
            alert: Original alert
            
        Returns:
            True if delivery successful, False otherwise
        """
        try:
            integration_key = channel.config.get('integration_key')
            if not integration_key:
                logger.error("PagerDuty integration key not configured", channel_id=channel.channel_id)
                return False
            
            # Map severity to PagerDuty severity
            severity_map = {
                AlertSeverity.CRITICAL: "critical",
                AlertSeverity.HIGH: "error",
                AlertSeverity.MEDIUM: "warning",
                AlertSeverity.LOW: "info"
            }
            
            # Create PagerDuty payload
            payload = {
                "routing_key": integration_key,
                "event_action": "trigger",
                "dedup_key": alert.id,
                "payload": {
                    "summary": subject,
                    "source": alert.source,
                    "severity": severity_map.get(alert.severity, "warning"),
                    "component": alert.source,
                    "group": "crown-jewel-monitor",
                    "class": alert.severity.value,
                    "custom_details": {
                        "description": message,
                        "alert_id": alert.id,
                        "timestamp": alert.timestamp.isoformat(),
                        "tags": alert.tags
                    }
                }
            }
            
            # Send to PagerDuty
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=channel.timeout_seconds)
                ) as response:
                    return response.status == 202
        
        except Exception as e:
            logger.error("Error delivering to PagerDuty", error=str(e))
            return False
    
    async def _deliver_to_webhook(self, channel: NotificationChannelConfig,
                                subject: str, message: str, alert: Alert) -> bool:
        """
        Deliver alert to custom webhook.
        
        Args:
            channel: Webhook channel configuration
            subject: Alert subject
            message: Alert message
            alert: Original alert
            
        Returns:
            True if delivery successful, False otherwise
        """
        try:
            webhook_url = channel.config.get('url')
            if not webhook_url:
                logger.error("Webhook URL not configured", channel_id=channel.channel_id)
                return False
            
            # Create webhook payload
            payload = {
                "alert_id": alert.id,
                "title": subject,
                "description": message,
                "severity": alert.severity.value,
                "source": alert.source,
                "timestamp": alert.timestamp.isoformat(),
                "tags": alert.tags,
                "metadata": alert.metadata
            }
            
            # Custom headers
            headers = channel.config.get('headers', {})
            headers.setdefault('Content-Type', 'application/json')
            
            # Send to webhook
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=channel.timeout_seconds)
                ) as response:
                    return response.status in [200, 201, 202, 204]
        
        except Exception as e:
            logger.error("Error delivering to webhook", error=str(e))
            return False
    
    async def _deliver_to_teams(self, channel: NotificationChannelConfig,
                              subject: str, message: str, alert: Alert) -> bool:
        """
        Deliver alert to Microsoft Teams.
        
        Args:
            channel: Teams channel configuration
            subject: Alert subject
            message: Alert message
            alert: Original alert
            
        Returns:
            True if delivery successful, False otherwise
        """
        try:
            webhook_url = channel.config.get('webhook_url')
            if not webhook_url:
                logger.error("Teams webhook URL not configured", channel_id=channel.channel_id)
                return False
            
            # Create Teams adaptive card
            color_map = {
                AlertSeverity.CRITICAL: "attention",
                AlertSeverity.HIGH: "warning",
                AlertSeverity.MEDIUM: "warning",
                AlertSeverity.LOW: "good"
            }
            
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color_map.get(alert.severity, "warning"),
                "summary": subject,
                "sections": [{
                    "activityTitle": f"🚨 {alert.severity.value.upper()} Alert",
                    "activitySubtitle": subject,
                    "text": message,
                    "facts": [
                        {"name": "Source", "value": alert.source},
                        {"name": "Time", "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')},
                        {"name": "Alert ID", "value": alert.id}
                    ]
                }]
            }
            
            # Send to Teams
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=channel.timeout_seconds)
                ) as response:
                    return response.status == 200
        
        except Exception as e:
            logger.error("Error delivering to Teams", error=str(e))
            return False
    
    # =========================================================================
    # MESSAGE FORMATTING
    # =========================================================================
    
    async def _format_message(self, alert_context: AlertContext,
                            channel: NotificationChannelConfig) -> Tuple[str, str]:
        """
        Format alert message for specific channel.
        
        Args:
            alert_context: Alert context to format
            channel: Target channel configuration
            
        Returns:
            Tuple of (subject, message)
        """
        alert = alert_context.alert
        
        # Get template for this channel
        template = None
        for template_name, tmpl in channel.templates.items():
            if tmpl.channel == channel.channel_type:
                template = tmpl
                break
        
        if not template:
            # Use default formatting
            return await self._format_default_message(alert, channel)
        
        # Use template formatting
        return await self._format_template_message(alert, template)
    
    async def _format_default_message(self, alert: Alert,
                                    channel: NotificationChannelConfig) -> Tuple[str, str]:
        """
        Format message using default templates.
        
        Args:
            alert: Alert to format
            channel: Target channel
            
        Returns:
            Tuple of (subject, message)
        """
        # Default subject
        subject = f"[{alert.severity.value.upper()}] {alert.title}"
        
        # Default message body
        message = f"""
Alert Details:
Title: {alert.title}
Description: {alert.description}
Severity: {alert.severity.value.upper()}
Source: {alert.source}
Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
Alert ID: {alert.id}
"""
        
        # Add tags if present
        if alert.tags:
            message += f"\nTags: {', '.join(alert.tags)}"
        
        # Add metadata if configured
        if channel.config.get('include_metadata', True) and alert.metadata:
            message += "\n\nMetadata:"
            for key, value in alert.metadata.items():
                message += f"\n  {key}: {value}"
        
        # Add remediation suggestions if available
        if (channel.config.get('include_remediation', True) and 
            alert.metadata and 'remediation_suggestions' in alert.metadata):
            suggestions = alert.metadata['remediation_suggestions']
            if suggestions:
                message += "\n\nSuggested Actions:"
                for suggestion in suggestions:
                    message += f"\n  • {suggestion}"
        
        return subject, message.strip()
    
    async def _format_template_message(self, alert: Alert,
                                     template: NotificationTemplate) -> Tuple[str, str]:
        """
        Format message using Jinja2 template.
        
        Args:
            alert: Alert to format
            template: Template to use
            
        Returns:
            Tuple of (subject, message)
        """
        if not JINJA2_AVAILABLE:
            logger.warning("Jinja2 not available, using default formatting")
            return await self._format_default_message(alert, None)
        
        try:
            # Prepare template context
            context = {
                'alert': alert,
                'severity': alert.severity.value,
                'severity_upper': alert.severity.value.upper(),
                'timestamp': alert.timestamp,
                'formatted_time': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'tags_str': ', '.join(alert.tags) if alert.tags else '',
                'has_metadata': bool(alert.metadata),
                'metadata': alert.metadata or {}
            }
            
            # Add custom fields
            context.update(template.custom_fields)
            
            # Render subject
            subject_template = Template(template.subject_template)
            subject = subject_template.render(**context)
            
            # Render message
            body_template = Template(template.body_template)
            message = body_template.render(**context)
            
            # Apply length limits if configured
            if template.max_length:
                if len(message) > template.max_length:
                    if template.truncate_behavior == "truncate":
                        message = message[:template.max_length - 3] + "..."
                    elif template.truncate_behavior == "summarize":
                        # Simple summarization
                        message = f"{alert.title}\n{alert.description[:template.max_length - 100]}..."
            
            return subject.strip(), message.strip()
        
        except Exception as e:
            logger.error("Error formatting template message", error=str(e))
            return await self._format_default_message(alert, None)
    
    # =========================================================================
    # ESCALATION SYSTEM
    # =========================================================================
    
    async def _check_escalation_rules(self, alert_context: AlertContext) -> None:
        """
        Check if alert matches any escalation rules.
        
        Args:
            alert_context: Alert context to check
        """
        alert = alert_context.alert
        
        for rule_id, rule in self.escalation_rules.items():
            if not rule.enabled:
                continue
            
            # Check if rule matches this alert
            if await self._rule_matches_alert(rule, alert):
                await self._trigger_escalation_rule(rule, alert_context)
    
    async def _rule_matches_alert(self, rule: EscalationRule, alert: Alert) -> bool:
        """
        Check if escalation rule matches the given alert.
        
        Args:
            rule: Escalation rule to check
            alert: Alert to match against
            
        Returns:
            True if rule matches, False otherwise
        """
        # Check severity levels
        if rule.severity_levels and alert.severity not in rule.severity_levels:
            return False
        
        # Check source agents
        if rule.source_agents and alert.source not in rule.source_agents:
            return False
        
        # Check tag filters
        if rule.tag_filters:
            alert_tags = set(alert.tags) if alert.tags else set()
            required_tags = set(rule.tag_filters)
            if not required_tags.issubset(alert_tags):
                return False
        
        # Check alert patterns
        if rule.alert_patterns:
            import re
            text_to_match = f"{alert.title} {alert.description}"
            for pattern in rule.alert_patterns:
                if re.search(pattern, text_to_match, re.IGNORECASE):
                    return True
            return False  # No patterns matched
        
        return True
    
    async def _trigger_escalation_rule(self, rule: EscalationRule,
                                     alert_context: AlertContext) -> None:
        """
        Trigger an escalation rule for an alert.
        
        Args:
            rule: Escalation rule to trigger
            alert_context: Alert context to escalate
        """
        logger.info("Triggering escalation rule",
                   rule_id=rule.rule_id,
                   alert_id=alert_context.alert.id)
        
        # Schedule escalation based on trigger type
        if rule.trigger_type == EscalationTrigger.TIME_BASED:
            # Schedule time-based escalation
            delay_seconds = rule.initial_delay_minutes * 60
            asyncio.create_task(
                self._schedule_time_based_escalation(rule, alert_context, delay_seconds)
            )
        elif rule.trigger_type == EscalationTrigger.ACKNOWLEDGMENT_TIMEOUT:
            # Schedule ack timeout escalation
            timeout_seconds = rule.trigger_conditions.get('timeout_minutes', 30) * 60
            asyncio.create_task(
                self._schedule_ack_timeout_escalation(rule, alert_context, timeout_seconds)
            )
        
        # Record rule trigger
        alert_context.escalation_rules_triggered.append(rule.rule_id)
        rule.last_triggered = datetime.utcnow()
        rule.trigger_count += 1
    
    async def _schedule_time_based_escalation(self, rule: EscalationRule,
                                            alert_context: AlertContext,
                                            delay_seconds: int) -> None:
        """
        Schedule time-based escalation for an alert.
        
        Args:
            rule: Escalation rule
            alert_context: Alert context
            delay_seconds: Delay before escalation
        """
        await asyncio.sleep(delay_seconds)
        
        # Check if alert is still active and unresolved
        if (alert_context.alert.id in self.active_alerts and 
            alert_context.current_state not in [AlertState.RESOLVED, AlertState.ACKNOWLEDGED]):
            
            await self._execute_escalation(rule, alert_context)
    
    async def _schedule_ack_timeout_escalation(self, rule: EscalationRule,
                                             alert_context: AlertContext,
                                             timeout_seconds: int) -> None:
        """
        Schedule acknowledgment timeout escalation.
        
        Args:
            rule: Escalation rule
            alert_context: Alert context
            timeout_seconds: Timeout before escalation
        """
        await asyncio.sleep(timeout_seconds)
        
        # Check if alert is still unacknowledged
        if (alert_context.alert.id in self.active_alerts and 
            alert_context.current_state == AlertState.SENT):
            
            await self._execute_escalation(rule, alert_context)
    
    async def _execute_escalation(self, rule: EscalationRule,
                                alert_context: AlertContext) -> None:
        """
        Execute escalation for an alert.
        
        Args:
            rule: Escalation rule to execute
            alert_context: Alert context to escalate
        """
        alert_context.escalation_level += 1
        alert_context.escalated_at = datetime.utcnow()
        alert_context.current_state = AlertState.ESCALATED
        
        logger.info("Executing alert escalation",
                   alert_id=alert_context.alert.id,
                   rule_id=rule.rule_id,
                   escalation_level=alert_context.escalation_level)
        
        # Get escalation channels for this level
        level = min(alert_context.escalation_level - 1, len(rule.escalation_channels) - 1)
        if level < len(rule.escalation_channels):
            escalation_channel_id = rule.escalation_channels[level]
            
            # Create escalated alert message
            escalated_alert = Alert(
                id=f"{alert_context.alert.id}_escalation_{alert_context.escalation_level}",
                title=f"[ESCALATED] {alert_context.alert.title}",
                description=f"ESCALATION LEVEL {alert_context.escalation_level}\n\n{alert_context.alert.description}",
                severity=alert_context.alert.severity,
                source=alert_context.alert.source,
                timestamp=datetime.utcnow(),
                tags=alert_context.alert.tags + ['escalated'],
                metadata={
                    **alert_context.alert.metadata,
                    'escalation_level': alert_context.escalation_level,
                    'original_alert_id': alert_context.alert.id,
                    'escalation_rule': rule.rule_id
                }
            )
            
            # Create temporary alert context for escalation
            escalated_context = AlertContext(alert=escalated_alert)
            
            # Deliver to escalation channel
            await self._deliver_to_channel(escalated_context, escalation_channel_id)
        
        # Schedule next escalation if within limits
        if (alert_context.escalation_level < rule.max_escalations and 
            rule.escalation_interval_minutes > 0):
            
            delay_seconds = rule.escalation_interval_minutes * 60
            asyncio.create_task(
                self._schedule_time_based_escalation(rule, alert_context, delay_seconds)
            )
    
    # =========================================================================
    # BACKGROUND TASKS
    # =========================================================================
    
    async def _escalation_monitor(self) -> None:
        """
        Background task to monitor escalations.
        """
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                # Check for escalation conditions
                current_time = datetime.utcnow()
                
                for alert_id, alert_context in list(self.active_alerts.items()):
                    if alert_context.current_state in [AlertState.RESOLVED, AlertState.ACKNOWLEDGED]:
                        continue
                    
                    # Check for any pending escalations
                    # This is handled by scheduled tasks, but we can add additional logic here
                    pass
            
            except Exception as e:
                logger.error("Error in escalation monitor", error=str(e))
    
    async def _cleanup_task(self) -> None:
        """
        Background task to clean up old alerts and data.
        """
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                current_time = datetime.utcnow()
                cutoff_time = current_time - timedelta(hours=self.alert_retention_hours)
                
                # Clean up old alerts
                expired_alerts = []
                for alert_id, alert_context in self.active_alerts.items():
                    if alert_context.created_at < cutoff_time:
                        expired_alerts.append(alert_id)
                
                for alert_id in expired_alerts:
                    del self.active_alerts[alert_id]
                
                # Clean up rate limiting data
                self.hourly_alert_count = [
                    timestamp for timestamp in self.hourly_alert_count
                    if current_time - timestamp < timedelta(hours=1)
                ]
                
                for channel_id in list(self.channel_rate_limits.keys()):
                    self.channel_rate_limits[channel_id] = [
                        timestamp for timestamp in self.channel_rate_limits[channel_id]
                        if current_time - timestamp < timedelta(hours=1)
                    ]
                
                logger.info("Cleanup completed",
                           expired_alerts=len(expired_alerts),
                           active_alerts=len(self.active_alerts))
            
            except Exception as e:
                logger.error("Error in cleanup task", error=str(e))
    
    async def _retry_failed_deliveries(self) -> None:
        """
        Background task to retry failed deliveries.
        """
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                
                current_time = datetime.utcnow()
                
                # Find deliveries that need retry
                for alert_context in self.active_alerts.values():
                    for delivery in alert_context.deliveries:
                        if (delivery.delivery_status == "failed" and 
                            delivery.next_retry and 
                            current_time >= delivery.next_retry and
                            delivery.retry_count < self.notification_channels.get(delivery.channel_id, NotificationChannelConfig("", NotificationChannel.WEBHOOK, "")).retry_attempts):
                            
                            # Attempt retry
                            delivery.retry_count += 1
                            delivery.next_retry = current_time + timedelta(seconds=self.notification_channels[delivery.channel_id].retry_delay_seconds)
                            
                            # Re-attempt delivery
                            asyncio.create_task(self._deliver_to_channel(alert_context, delivery.channel_id))
            
            except Exception as e:
                logger.error("Error in retry task", error=str(e))
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    async def _should_suppress_alert(self, alert: Alert) -> bool:
        """
        Check if alert should be suppressed.
        
        Args:
            alert: Alert to check
            
        Returns:
            True if alert should be suppressed, False otherwise
        """
        # Create alert fingerprint for deduplication
        fingerprint = self._create_alert_fingerprint(alert)
        
        # Check if we've seen this alert recently
        if fingerprint in self.alert_fingerprints:
            last_seen = self.alert_fingerprints[fingerprint]
            if datetime.utcnow() - last_seen < timedelta(minutes=30):  # 30-minute suppression window
                return True
        
        # Update fingerprint timestamp
        self.alert_fingerprints[fingerprint] = datetime.utcnow()
        
        return False
    
    def _create_alert_fingerprint(self, alert: Alert) -> str:
        """
        Create unique fingerprint for alert deduplication.
        
        Args:
            alert: Alert to fingerprint
            
        Returns:
            Unique fingerprint string
        """
        fingerprint_data = f"{alert.title}:{alert.source}:{alert.severity.value}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()
    
    async def _check_rate_limits(self) -> bool:
        """
        Check global rate limits.
        
        Returns:
            True if within limits, False otherwise
        """
        current_time = datetime.utcnow()
        
        # Clean old entries
        self.hourly_alert_count = [
            timestamp for timestamp in self.hourly_alert_count
            if current_time - timestamp < timedelta(hours=1)
        ]
        
        # Check limit
        if len(self.hourly_alert_count) >= self.max_alerts_per_hour:
            return False
        
        # Add current time
        self.hourly_alert_count.append(current_time)
        return True
    
    async def _check_channel_rate_limit(self, channel_id: str) -> bool:
        """
        Check rate limit for specific channel.
        
        Args:
            channel_id: Channel ID to check
            
        Returns:
            True if within limits, False otherwise
        """
        channel = self.notification_channels.get(channel_id)
        if not channel:
            return False
        
        current_time = datetime.utcnow()
        
        # Initialize if needed
        if channel_id not in self.channel_rate_limits:
            self.channel_rate_limits[channel_id] = []
        
        # Clean old entries
        self.channel_rate_limits[channel_id] = [
            timestamp for timestamp in self.channel_rate_limits[channel_id]
            if current_time - timestamp < timedelta(hours=1)
        ]
        
        # Check limit
        if len(self.channel_rate_limits[channel_id]) >= channel.rate_limit_per_hour:
            return False
        
        # Add current time
        self.channel_rate_limits[channel_id].append(current_time)
        return True
    
    async def _is_channel_available(self, channel_id: str) -> bool:
        """
        Check if channel is available for delivery.
        
        Args:
            channel_id: Channel ID to check
            
        Returns:
            True if available, False otherwise
        """
        # For now, just check if channel exists and is enabled
        channel = self.notification_channels.get(channel_id)
        return channel is not None and channel.enabled
    
    async def _send_acknowledgment_notification(self, alert_context: AlertContext) -> None:
        """
        Send notification about alert acknowledgment.
        
        Args:
            alert_context: Acknowledged alert context
        """
        # Create acknowledgment notification (simplified)
        logger.info("Alert acknowledged notification sent",
                   alert_id=alert_context.alert.id,
                   acknowledged_by=alert_context.acknowledged_by)
    
    async def _send_resolution_notification(self, alert_context: AlertContext) -> None:
        """
        Send notification about alert resolution.
        
        Args:
            alert_context: Resolved alert context
        """
        # Create resolution notification (simplified)
        logger.info("Alert resolution notification sent",
                   alert_id=alert_context.alert.id,
                   resolved_by=alert_context.resolved_by)
    
    # =========================================================================
    # CONFIGURATION LOADING
    # =========================================================================
    
    async def _load_notification_channels(self) -> None:
        """
        Load notification channels from configuration.
        """
        channels_config = self.config.get('channels', {})
        
        for channel_id, channel_config in channels_config.items():
            channel = NotificationChannelConfig(
                channel_id=channel_id,
                channel_type=NotificationChannel(channel_config['type']),
                name=channel_config.get('name', channel_id),
                enabled=channel_config.get('enabled', True),
                severity_filter=[AlertSeverity(s) for s in channel_config.get('severity_filter', [])],
                config=channel_config.get('config', {}),
                rate_limit_per_hour=channel_config.get('rate_limit_per_hour', 100),
                retry_attempts=channel_config.get('retry_attempts', 3),
                timeout_seconds=channel_config.get('timeout_seconds', 30)
            )
            
            self.notification_channels[channel_id] = channel
        
        logger.info("Loaded notification channels", count=len(self.notification_channels))
    
    async def _load_notification_templates(self) -> None:
        """
        Load notification templates from configuration.
        """
        # Load default templates or from configuration
        # For now, using built-in templates
        pass
    
    async def _load_escalation_rules(self) -> None:
        """
        Load escalation rules from configuration.
        """
        rules_config = self.config.get('escalation_rules', {})
        
        for rule_id, rule_config in rules_config.items():
            rule = EscalationRule(
                rule_id=rule_id,
                name=rule_config.get('name', rule_id),
                description=rule_config.get('description', ''),
                trigger_type=EscalationTrigger(rule_config.get('trigger_type', 'time_based')),
                trigger_conditions=rule_config.get('trigger_conditions', {}),
                severity_levels=[AlertSeverity(s) for s in rule_config.get('severity_levels', [])],
                alert_patterns=rule_config.get('alert_patterns', []),
                source_agents=rule_config.get('source_agents', []),
                tag_filters=rule_config.get('tag_filters', []),
                initial_delay_minutes=rule_config.get('initial_delay_minutes', 0),
                escalation_interval_minutes=rule_config.get('escalation_interval_minutes', 30),
                max_escalations=rule_config.get('max_escalations', 3),
                escalation_channels=rule_config.get('escalation_channels', []),
                enabled=rule_config.get('enabled', True)
            )
            
            self.escalation_rules[rule_id] = rule
        
        logger.info("Loaded escalation rules", count=len(self.escalation_rules))
    
    async def _initialize_delivery_tracking(self) -> None:
        """
        Initialize delivery tracking systems.
        """
        # Initialize delivery statistics
        for channel_id in self.notification_channels:
            self.delivery_stats[channel_id] = {'success': 0, 'failure': 0}
        
        logger.info("Delivery tracking initialized")