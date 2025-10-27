#!/usr/bin/env python3
"""
Crown Jewel Java Application Monitor - REST API Server
Comprehensive REST API for monitoring, configuration, and management operations.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

# FastAPI and HTTP components
try:
    from fastapi import FastAPI, HTTPException, Depends, status, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from ..core.agent_framework import AgentOrchestrator, Alert, AlertSeverity, MonitoringMetric
from ..core.alerting_system import AlertingSystem

import structlog
logger = structlog.get_logger()


class RestAPIServer:
    """
    REST API server for Crown Jewel Monitor management and monitoring.
    
    Provides endpoints for:
    - System status and health monitoring
    - Agent management and control
    - Alert management and acknowledgment
    - Metrics retrieval and analysis
    - Configuration management
    - Remediation control
    """
    
    def __init__(self, orchestrator: AgentOrchestrator,
                 alerting_system: AlertingSystem,
                 config: Dict[str, Any]):
        """
        Initialize REST API server.
        
        Args:
            orchestrator: Agent orchestrator instance
            alerting_system: Alerting system instance
            config: API configuration
        """
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is required for REST API server. Install with: pip install fastapi uvicorn")
        
        self.orchestrator = orchestrator
        self.alerting_system = alerting_system
        self.config = config
        
        # Server configuration
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 8080)
        self.debug = config.get('debug', False)
        
        # Security configuration
        self.auth_enabled = config.get('authentication', {}).get('enabled', False)
        self.api_tokens = config.get('authentication', {}).get('tokens', [])
        
        # Initialize FastAPI app
        self.app = FastAPI(
            title="Crown Jewel Monitor API",
            description="REST API for Crown Jewel Java Application Monitor",
            version="1.0.0",
            docs_url="/docs" if self.debug else None,
            redoc_url="/redoc" if self.debug else None
        )
        
        # Setup middleware and routes
        self._setup_middleware()
        self._setup_routes()
        
        # Server instance
        self.server = None
        
        logger.info("RestAPIServer initialized",
                   host=self.host,
                   port=self.port,
                   auth_enabled=self.auth_enabled)
    
    async def initialize(self) -> bool:
        """
        Initialize the REST API server.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            logger.info("Initializing REST API server")
            
            # Validate configuration
            if self.port < 1 or self.port > 65535:
                logger.error("Invalid port configuration", port=self.port)
                return False
            
            logger.info("REST API server initialized successfully")
            return True
            
        except Exception as e:
            logger.error("Failed to initialize REST API server", error=str(e))
            return False
    
    async def start(self) -> None:
        """Start the REST API server."""
        try:
            logger.info("Starting REST API server", host=self.host, port=self.port)
            
            config = uvicorn.Config(
                app=self.app,
                host=self.host,
                port=self.port,
                log_level="info" if self.debug else "warning",
                access_log=self.debug
            )
            
            self.server = uvicorn.Server(config)
            await self.server.serve()
            
        except Exception as e:
            logger.error("Error starting REST API server", error=str(e))
            raise
    
    async def stop(self) -> None:
        """Stop the REST API server."""
        if self.server:
            logger.info("Stopping REST API server")
            self.server.should_exit = True
            # Give server time to shutdown gracefully
            await asyncio.sleep(1)
    
    def _setup_middleware(self) -> None:
        """Setup FastAPI middleware."""
        # CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config.get('cors', {}).get('origins', ["*"]),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Request logging middleware
        @self.app.middleware("http")
        async def log_requests(request: Request, call_next):
            start_time = time.time()
            response = await call_next(request)
            process_time = time.time() - start_time
            
            logger.info("API request",
                       method=request.method,
                       url=str(request.url),
                       status_code=response.status_code,
                       process_time=f"{process_time:.3f}s")
            
            return response
    
    def _setup_routes(self) -> None:
        """Setup API routes."""
        # Authentication dependency
        security = HTTPBearer() if self.auth_enabled else None
        
        def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
            if not self.auth_enabled:
                return {"user": "anonymous", "permissions": ["read", "write", "admin"]}
            
            token = credentials.credentials
            for token_config in self.api_tokens:
                if token_config.get('token') == token:
                    return {
                        "user": token_config.get('user', 'api_user'),
                        "permissions": token_config.get('permissions', ['read'])
                    }
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token"
            )
        
        # System status endpoints
        @self.app.get("/api/status")
        async def get_system_status(user=Depends(get_current_user)):
            """Get overall system status."""
            try:
                return {
                    "status": "healthy",
                    "timestamp": datetime.utcnow().isoformat(),
                    "version": "1.0.0",
                    "uptime_seconds": time.time() - getattr(self.orchestrator, 'start_time', time.time()),
                    "agents": {
                        "total": len(self.orchestrator.agents),
                        "running": len([a for a in self.orchestrator.agents.values() if a.is_running]),
                        "stopped": len([a for a in self.orchestrator.agents.values() if not a.is_running]),
                        "error": 0  # TODO: Add error tracking
                    },
                    "alerts": {
                        "active": len(self.alerting_system.active_alerts),
                        "total_processed": getattr(self.alerting_system, 'total_processed', 0)
                    }
                }
            except Exception as e:
                logger.error("Error getting system status", error=str(e))
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.get("/api/health")
        async def health_check(user=Depends(get_current_user)):
            """Detailed health check."""
            try:
                components = {
                    "orchestrator": {
                        "status": "healthy" if self.orchestrator else "unavailable",
                        "agents_count": len(self.orchestrator.agents) if self.orchestrator else 0
                    },
                    "alerting_system": {
                        "status": "healthy" if self.alerting_system else "unavailable",
                        "channels_count": len(self.alerting_system.notification_channels) if self.alerting_system else 0
                    }
                }
                
                overall_status = "healthy" if all(
                    comp["status"] == "healthy" for comp in components.values()
                ) else "degraded"
                
                return {
                    "status": overall_status,
                    "timestamp": datetime.utcnow().isoformat(),
                    "components": components
                }
            except Exception as e:
                logger.error("Error in health check", error=str(e))
                raise HTTPException(status_code=500, detail="Health check failed")
        
        # Agent management endpoints
        @self.app.get("/api/agents")
        async def list_agents(user=Depends(get_current_user)):
            """List all registered agents."""
            try:
                agents = []
                for agent_id, agent in self.orchestrator.agents.items():
                    agents.append({
                        "id": agent_id,
                        "type": agent.__class__.__name__,
                        "status": "running" if agent.is_running else "stopped",
                        "last_execution": getattr(agent, 'last_execution', None),
                        "execution_count": getattr(agent, 'execution_count', 0),
                        "success_rate": getattr(agent, 'success_rate', 1.0)
                    })
                
                return {"agents": agents}
            except Exception as e:
                logger.error("Error listing agents", error=str(e))
                raise HTTPException(status_code=500, detail="Failed to list agents")
        
        @self.app.get("/api/agents/{agent_id}")
        async def get_agent_details(agent_id: str, user=Depends(get_current_user)):
            """Get detailed information about a specific agent."""
            try:
                if agent_id not in self.orchestrator.agents:
                    raise HTTPException(status_code=404, detail="Agent not found")
                
                agent = self.orchestrator.agents[agent_id]
                
                return {
                    "id": agent_id,
                    "type": agent.__class__.__name__,
                    "status": "running" if agent.is_running else "stopped",
                    "configuration": getattr(agent, 'config', {}),
                    "statistics": {
                        "total_executions": getattr(agent, 'execution_count', 0),
                        "last_execution": getattr(agent, 'last_execution', None),
                        "success_rate": getattr(agent, 'success_rate', 1.0)
                    }
                }
            except HTTPException:
                raise
            except Exception as e:
                logger.error("Error getting agent details", agent_id=agent_id, error=str(e))
                raise HTTPException(status_code=500, detail="Failed to get agent details")
        
        @self.app.post("/api/agents/{agent_id}/execute")
        async def execute_agent(agent_id: str, user=Depends(get_current_user)):
            """Manually trigger agent execution."""
            try:
                if "write" not in user["permissions"]:
                    raise HTTPException(status_code=403, detail="Insufficient permissions")
                
                if agent_id not in self.orchestrator.agents:
                    raise HTTPException(status_code=404, detail="Agent not found")
                
                agent = self.orchestrator.agents[agent_id]
                
                # Execute agent
                start_time = time.time()
                result = await agent.execute()
                duration_ms = (time.time() - start_time) * 1000
                
                return {
                    "execution_id": f"manual_{int(time.time())}",
                    "status": "completed",
                    "duration_ms": duration_ms,
                    "results": result
                }
            except HTTPException:
                raise
            except Exception as e:
                logger.error("Error executing agent", agent_id=agent_id, error=str(e))
                raise HTTPException(status_code=500, detail="Failed to execute agent")
        
        # Alert management endpoints
        @self.app.get("/api/alerts")
        async def list_alerts(
            severity: Optional[str] = None,
            status: Optional[str] = None,
            limit: int = 100,
            offset: int = 0,
            user=Depends(get_current_user)
        ):
            """List alerts with optional filtering."""
            try:
                alerts = []
                
                for alert_id, alert_context in self.alerting_system.active_alerts.items():
                    alert = alert_context.alert
                    
                    # Apply filters
                    if severity and alert.severity.value != severity:
                        continue
                    if status and alert_context.current_state.value != status:
                        continue
                    
                    alerts.append({
                        "id": alert.id,
                        "title": alert.title,
                        "description": alert.description,
                        "severity": alert.severity.value,
                        "status": alert_context.current_state.value,
                        "source": alert.source,
                        "timestamp": alert.timestamp.isoformat(),
                        "tags": alert.tags,
                        "acknowledged_by": alert_context.acknowledged_by,
                        "resolved_by": alert_context.resolved_by
                    })
                
                # Apply pagination
                total_count = len(alerts)
                alerts = alerts[offset:offset + limit]
                
                return {
                    "alerts": alerts,
                    "total_count": total_count,
                    "limit": limit,
                    "offset": offset,
                    "has_more": offset + limit < total_count
                }
            except Exception as e:
                logger.error("Error listing alerts", error=str(e))
                raise HTTPException(status_code=500, detail="Failed to list alerts")
        
        @self.app.post("/api/alerts/{alert_id}/acknowledge")
        async def acknowledge_alert(
            alert_id: str,
            request: Request,
            user=Depends(get_current_user)
        ):
            """Acknowledge an alert."""
            try:
                if "write" not in user["permissions"]:
                    raise HTTPException(status_code=403, detail="Insufficient permissions")
                
                body = await request.json()
                comment = body.get("comment")
                
                success = await self.alerting_system.acknowledge_alert(
                    alert_id=alert_id,
                    acknowledged_by=user["user"],
                    comment=comment
                )
                
                if not success:
                    raise HTTPException(status_code=404, detail="Alert not found")
                
                return {
                    "status": "acknowledged",
                    "acknowledged_by": user["user"],
                    "acknowledged_at": datetime.utcnow().isoformat()
                }
            except HTTPException:
                raise
            except Exception as e:
                logger.error("Error acknowledging alert", alert_id=alert_id, error=str(e))
                raise HTTPException(status_code=500, detail="Failed to acknowledge alert")
        
        @self.app.post("/api/alerts/{alert_id}/resolve")
        async def resolve_alert(
            alert_id: str,
            request: Request,
            user=Depends(get_current_user)
        ):
            """Resolve an alert."""
            try:
                if "write" not in user["permissions"]:
                    raise HTTPException(status_code=403, detail="Insufficient permissions")
                
                body = await request.json()
                resolution = body.get("resolution")
                
                success = await self.alerting_system.resolve_alert(
                    alert_id=alert_id,
                    resolved_by=user["user"],
                    resolution=resolution
                )
                
                if not success:
                    raise HTTPException(status_code=404, detail="Alert not found")
                
                return {
                    "status": "resolved",
                    "resolved_by": user["user"],
                    "resolved_at": datetime.utcnow().isoformat()
                }
            except HTTPException:
                raise
            except Exception as e:
                logger.error("Error resolving alert", alert_id=alert_id, error=str(e))
                raise HTTPException(status_code=500, detail="Failed to resolve alert")
        
        # Metrics endpoints
        @self.app.get("/api/metrics")
        async def get_metrics(
            metric_type: Optional[str] = None,
            source: Optional[str] = None,
            since: Optional[str] = None,
            user=Depends(get_current_user)
        ):
            """Get system and application metrics."""
            try:
                # Get metrics from orchestrator
                metrics = getattr(self.orchestrator, 'get_metrics', lambda: [])()
                
                # Apply filters
                filtered_metrics = []
                for metric in metrics:
                    if metric_type and metric.get('type') != metric_type:
                        continue
                    if source and metric.get('source') != source:
                        continue
                    # TODO: Add since filtering
                    
                    filtered_metrics.append(metric)
                
                return {
                    "metrics": filtered_metrics,
                    "timestamp": datetime.utcnow().isoformat()
                }
            except Exception as e:
                logger.error("Error getting metrics", error=str(e))
                raise HTTPException(status_code=500, detail="Failed to get metrics")
        
        @self.app.get("/api/metrics/summary")
        async def get_metrics_summary(user=Depends(get_current_user)):
            """Get summarized metrics for dashboard."""
            try:
                # Get current system metrics
                summary = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "system_health": "healthy",  # TODO: Calculate from actual metrics
                    "agents": {
                        "total": len(self.orchestrator.agents),
                        "running": len([a for a in self.orchestrator.agents.values() if a.is_running])
                    },
                    "alerts": {
                        "active": len(self.alerting_system.active_alerts),
                        "critical": len([
                            a for a in self.alerting_system.active_alerts.values()
                            if a.alert.severity == AlertSeverity.CRITICAL
                        ])
                    }
                }
                
                return summary
            except Exception as e:
                logger.error("Error getting metrics summary", error=str(e))
                raise HTTPException(status_code=500, detail="Failed to get metrics summary")
        
        # Configuration endpoints
        @self.app.get("/api/config")
        async def get_configuration(user=Depends(get_current_user)):
            """Get current configuration (sensitive values masked)."""
            try:
                if "admin" not in user["permissions"]:
                    raise HTTPException(status_code=403, detail="Admin permissions required")
                
                # Return masked configuration
                config = {
                    "global": {
                        "log_level": "INFO",
                        "monitoring_interval": 60
                    },
                    "agents": {},
                    "alerting": {
                        "enabled": True
                    }
                }
                
                return config
            except HTTPException:
                raise
            except Exception as e:
                logger.error("Error getting configuration", error=str(e))
                raise HTTPException(status_code=500, detail="Failed to get configuration")
        
        # Error handlers
        @self.app.exception_handler(404)
        async def not_found_handler(request: Request, exc: HTTPException):
            return JSONResponse(
                status_code=404,
                content={
                    "error": {
                        "code": "NOT_FOUND",
                        "message": "Resource not found",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                }
            )
        
        @self.app.exception_handler(500)
        async def internal_error_handler(request: Request, exc: Exception):
            logger.error("Internal server error", error=str(exc))
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "Internal server error",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                }
            )