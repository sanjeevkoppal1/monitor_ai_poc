# Crown Jewel Monitor - API Documentation

## 🌐 REST API Reference

The Crown Jewel Monitor exposes a comprehensive REST API for monitoring, configuration, and management operations.

## 🔑 Authentication

All API endpoints require authentication via Bearer token:

```bash
curl -H "Authorization: Bearer your-api-token" \
  http://localhost:8080/api/status
```

### API Token Configuration
```yaml
# config/config.yaml
security:
  api:
    authentication:
      tokens:
        - token: "your-secure-api-token"
          permissions: ["read", "write", "admin"]
          expires: "2024-12-31"
```

## 📊 System Status Endpoints

### GET /api/status
Get overall system status and health.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "uptime_seconds": 86400,
  "agents": {
    "total": 2,
    "running": 2,
    "stopped": 0,
    "error": 0
  },
  "system": {
    "cpu_usage_percent": 15.2,
    "memory_usage_mb": 512,
    "disk_usage_percent": 45.8
  }
}
```

### GET /api/health
Detailed health check with component status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "components": {
    "orchestrator": {
      "status": "healthy",
      "last_check": "2024-01-15T10:29:55Z"
    },
    "splunk_connection": {
      "status": "healthy",
      "response_time_ms": 45,
      "last_check": "2024-01-15T10:29:50Z"
    },
    "java_jmx_connection": {
      "status": "healthy",
      "response_time_ms": 12,
      "last_check": "2024-01-15T10:29:52Z"
    }
  }
}
```

## 🤖 Agent Management Endpoints

### GET /api/agents
List all registered agents.

**Response:**
```json
{
  "agents": [
    {
      "id": "splunk_monitor",
      "type": "splunk",
      "status": "running",
      "last_execution": "2024-01-15T10:29:00Z",
      "execution_count": 1440,
      "average_duration_ms": 2500,
      "success_rate": 0.998
    },
    {
      "id": "java_health_monitor",
      "type": "java_health",
      "status": "running",
      "last_execution": "2024-01-15T10:29:30Z",
      "execution_count": 1440,
      "average_duration_ms": 1200,
      "success_rate": 1.0
    }
  ]
}
```

### GET /api/agents/{agent_id}
Get detailed information about a specific agent.

**Response:**
```json
{
  "id": "splunk_monitor",
  "type": "splunk",
  "status": "running",
  "configuration": {
    "execution_interval": 300,
    "enabled": true
  },
  "statistics": {
    "total_executions": 1440,
    "successful_executions": 1437,
    "failed_executions": 3,
    "average_duration_ms": 2500,
    "last_error": "2024-01-15T08:15:00Z",
    "last_error_message": "Temporary connection timeout"
  },
  "current_state": {
    "is_executing": false,
    "next_execution": "2024-01-15T10:35:00Z",
    "resource_usage": {
      "cpu_percent": 5.2,
      "memory_mb": 128
    }
  }
}
```

### POST /api/agents/{agent_id}/execute
Manually trigger agent execution.

**Request:**
```json
{
  "wait_for_completion": true,
  "timeout_seconds": 60
}
```

**Response:**
```json
{
  "execution_id": "exec_12345",
  "status": "completed",
  "duration_ms": 2340,
  "results": {
    "alerts_generated": 0,
    "metrics_collected": 15,
    "events_processed": 342
  }
}
```

### POST /api/agents/{agent_id}/stop
Stop a running agent.

**Response:**
```json
{
  "status": "stopped",
  "message": "Agent stopped successfully"
}
```

### POST /api/agents/{agent_id}/start
Start a stopped agent.

**Response:**
```json
{
  "status": "started",
  "message": "Agent started successfully"
}
```

## 🚨 Alert Management Endpoints

### GET /api/alerts
Get alerts with optional filtering.

**Query Parameters:**
- `severity`: Filter by severity (critical, high, medium, low)
- `status`: Filter by status (open, acknowledged, resolved)
- `since`: ISO timestamp for earliest alert
- `limit`: Maximum number of results (default: 100)
- `offset`: Pagination offset

**Example:**
```bash
curl "http://localhost:8080/api/alerts?severity=critical&status=open&limit=50"
```

**Response:**
```json
{
  "alerts": [
    {
      "id": "alert_12345",
      "severity": "critical",
      "status": "open",
      "title": "OutOfMemoryError detected",
      "description": "Java application experiencing memory issues",
      "source_agent": "splunk_monitor",
      "timestamp": "2024-01-15T10:25:00Z",
      "tags": ["memory", "java", "critical"],
      "affected_components": ["crown-jewel-app"],
      "remediation_suggestions": [
        "Restart application",
        "Increase heap size",
        "Check for memory leaks"
      ]
    }
  ],
  "total_count": 1,
  "has_more": false
}
```

### GET /api/alerts/{alert_id}
Get detailed information about a specific alert.

**Response:**
```json
{
  "id": "alert_12345",
  "severity": "critical",
  "status": "open",
  "title": "OutOfMemoryError detected",
  "description": "Java application experiencing memory issues",
  "source_agent": "splunk_monitor",
  "timestamp": "2024-01-15T10:25:00Z",
  "details": {
    "error_pattern": "java.lang.OutOfMemoryError: Java heap space",
    "frequency": 3,
    "time_window": "5 minutes",
    "affected_hosts": ["app-server-01"],
    "log_samples": [
      "2024-01-15 10:25:00 ERROR OutOfMemoryError: Java heap space"
    ]
  },
  "remediation": {
    "suggested_actions": [
      "Restart application",
      "Increase heap size"
    ],
    "automated_actions_taken": [],
    "escalation_level": 1
  }
}
```

### POST /api/alerts/{alert_id}/acknowledge
Acknowledge an alert.

**Request:**
```json
{
  "acknowledged_by": "john.doe@company.com",
  "comment": "Investigating memory issue"
}
```

**Response:**
```json
{
  "status": "acknowledged",
  "acknowledged_at": "2024-01-15T10:30:00Z",
  "acknowledged_by": "john.doe@company.com"
}
```

### POST /api/alerts/{alert_id}/resolve
Mark an alert as resolved.

**Request:**
```json
{
  "resolved_by": "john.doe@company.com",
  "resolution": "Increased heap size and restarted application"
}
```

**Response:**
```json
{
  "status": "resolved",
  "resolved_at": "2024-01-15T10:45:00Z",
  "resolved_by": "john.doe@company.com"
}
```

## 📈 Metrics Endpoints

### GET /api/metrics
Get system and application metrics.

**Query Parameters:**
- `metric_type`: Filter by metric type (jvm, system, application)
- `source`: Filter by source agent
- `since`: ISO timestamp for earliest metrics
- `until`: ISO timestamp for latest metrics
- `aggregation`: Aggregation method (avg, min, max, sum)
- `interval`: Aggregation interval (1m, 5m, 15m, 1h)

**Example:**
```bash
curl "http://localhost:8080/api/metrics?metric_type=jvm&since=2024-01-15T09:00:00Z&interval=5m"
```

**Response:**
```json
{
  "metrics": [
    {
      "timestamp": "2024-01-15T10:00:00Z",
      "metric_type": "jvm",
      "source": "java_health_monitor",
      "values": {
        "heap_usage_percent": 67.5,
        "gc_pause_time_ms": 45.2,
        "thread_count": 42,
        "cpu_usage_percent": 15.8
      }
    },
    {
      "timestamp": "2024-01-15T10:05:00Z",
      "metric_type": "jvm",
      "source": "java_health_monitor",
      "values": {
        "heap_usage_percent": 69.1,
        "gc_pause_time_ms": 52.1,
        "thread_count": 44,
        "cpu_usage_percent": 18.2
      }
    }
  ],
  "aggregation": {
    "interval": "5m",
    "method": "avg"
  }
}
```

### GET /api/metrics/summary
Get summarized metrics for dashboard display.

**Response:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "jvm_metrics": {
    "heap_usage_percent": 68.5,
    "cpu_usage_percent": 16.2,
    "gc_pause_time_ms": 48.7,
    "thread_count": 43
  },
  "application_metrics": {
    "response_time_ms": 234.5,
    "error_rate_percent": 0.02,
    "throughput_rps": 125.8
  },
  "system_metrics": {
    "cpu_usage_percent": 25.4,
    "memory_usage_percent": 45.8,
    "disk_usage_percent": 67.2
  }
}
```

## ⚙️ Configuration Endpoints

### GET /api/config
Get current configuration (sensitive values masked).

**Response:**
```json
{
  "global": {
    "log_level": "INFO",
    "monitoring_interval": 60,
    "max_concurrent_agents": 5
  },
  "agents": {
    "splunk_monitor": {
      "type": "splunk",
      "enabled": true,
      "execution_interval": 300
    },
    "java_health_monitor": {
      "type": "java_health",
      "enabled": true,
      "execution_interval": 60
    }
  },
  "alerting": {
    "enabled": true,
    "channels": ["slack", "email"]
  }
}
```

### POST /api/config/reload
Reload configuration from file.

**Response:**
```json
{
  "status": "reloaded",
  "timestamp": "2024-01-15T10:30:00Z",
  "changes_detected": true,
  "affected_agents": ["splunk_monitor"]
}
```

### POST /api/config/validate
Validate configuration without applying changes.

**Request:**
```json
{
  "config": {
    "global": {
      "log_level": "DEBUG"
    }
  }
}
```

**Response:**
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "Debug logging may impact performance"
  ]
}
```

## 🔧 Remediation Endpoints

### GET /api/remediation/actions
Get available remediation actions.

**Response:**
```json
{
  "actions": [
    {
      "id": "restart_application",
      "name": "Restart Java Application",
      "description": "Restart the monitored Java application",
      "risk_level": "medium",
      "requires_approval": true,
      "estimated_downtime_seconds": 30
    },
    {
      "id": "clear_cache",
      "name": "Clear Application Cache",
      "description": "Clear application cache to free memory",
      "risk_level": "low",
      "requires_approval": false,
      "estimated_downtime_seconds": 0
    }
  ]
}
```

### POST /api/remediation/actions/{action_id}/execute
Execute a remediation action.

**Request:**
```json
{
  "alert_id": "alert_12345",
  "parameters": {
    "confirmation": true,
    "notify_team": true
  }
}
```

**Response:**
```json
{
  "execution_id": "remediation_67890",
  "status": "completed",
  "result": "success",
  "duration_ms": 15000,
  "message": "Application restarted successfully",
  "side_effects": [
    "Active sessions terminated",
    "Cache cleared"
  ]
}
```

### GET /api/remediation/history
Get remediation action history.

**Response:**
```json
{
  "executions": [
    {
      "execution_id": "remediation_67890",
      "action_id": "restart_application",
      "triggered_by": "alert_12345",
      "executed_at": "2024-01-15T10:30:00Z",
      "status": "completed",
      "result": "success",
      "duration_ms": 15000
    }
  ]
}
```

## 📊 Reporting Endpoints

### GET /api/reports/health
Generate system health report.

**Query Parameters:**
- `period`: Report period (1h, 6h, 24h, 7d, 30d)
- `format`: Output format (json, pdf, csv)

**Response:**
```json
{
  "report_id": "health_20240115",
  "period": "24h",
  "generated_at": "2024-01-15T10:30:00Z",
  "summary": {
    "overall_health": "good",
    "total_alerts": 12,
    "critical_alerts": 1,
    "average_response_time_ms": 245.6,
    "availability_percent": 99.8
  },
  "trends": {
    "memory_usage": "increasing",
    "response_time": "stable",
    "error_rate": "decreasing"
  }
}
```

### GET /api/reports/performance
Generate performance analysis report.

**Response:**
```json
{
  "report_id": "perf_20240115",
  "analysis_period": "7d",
  "performance_score": 85.2,
  "bottlenecks": [
    {
      "component": "database_connections",
      "severity": "medium",
      "impact": "Response time increase of 15%"
    }
  ],
  "recommendations": [
    "Increase database connection pool size",
    "Optimize slow SQL queries"
  ]
}
```

## 🔍 Search and Query Endpoints

### POST /api/search/logs
Search application logs via Splunk.

**Request:**
```json
{
  "query": "search index=main \"ERROR\" earliest=-1h",
  "max_results": 100,
  "timeout_seconds": 30
}
```

**Response:**
```json
{
  "search_id": "search_12345",
  "results": [
    {
      "timestamp": "2024-01-15T10:25:00Z",
      "host": "app-server-01",
      "source": "/var/log/app.log",
      "message": "ERROR: Database connection failed"
    }
  ],
  "total_results": 15,
  "execution_time_ms": 1250
}
```

### GET /api/search/suggestions
Get search suggestions and common queries.

**Response:**
```json
{
  "suggestions": [
    {
      "category": "errors",
      "queries": [
        "search index=main \"ERROR\" earliest=-1h",
        "search index=main \"Exception\" earliest=-1h"
      ]
    },
    {
      "category": "performance",
      "queries": [
        "search index=main \"slow query\" earliest=-1h",
        "search index=main response_time>5000 earliest=-1h"
      ]
    }
  ]
}
```

## 🔐 Security and Authentication

### POST /api/auth/token
Generate new API token.

**Request:**
```json
{
  "username": "admin",
  "password": "secure_password",
  "permissions": ["read", "write"],
  "expires_days": 30
}
```

**Response:**
```json
{
  "token": "new-secure-api-token",
  "expires": "2024-02-15T10:30:00Z",
  "permissions": ["read", "write"]
}
```

### DELETE /api/auth/token/{token_id}
Revoke API token.

**Response:**
```json
{
  "status": "revoked",
  "message": "Token revoked successfully"
}
```

## 📝 Error Responses

All endpoints return consistent error responses:

```json
{
  "error": {
    "code": "AGENT_NOT_FOUND",
    "message": "Agent 'invalid_agent' not found",
    "details": {
      "agent_id": "invalid_agent",
      "available_agents": ["splunk_monitor", "java_health_monitor"]
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req_12345"
  }
}
```

### Common Error Codes
- `INVALID_REQUEST` (400): Malformed request
- `UNAUTHORIZED` (401): Invalid or missing authentication
- `FORBIDDEN` (403): Insufficient permissions
- `NOT_FOUND` (404): Resource not found
- `CONFLICT` (409): Resource conflict
- `RATE_LIMITED` (429): Too many requests
- `INTERNAL_ERROR` (500): Server error
- `SERVICE_UNAVAILABLE` (503): Service temporarily unavailable

## 🚀 WebSocket API

Real-time updates via WebSocket connection:

```javascript
const ws = new WebSocket('ws://localhost:8080/ws/events');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  if (data.type === 'alert') {
    console.log('New alert:', data.alert);
  } else if (data.type === 'metric') {
    console.log('New metric:', data.metric);
  }
};
```

### WebSocket Event Types
- `alert`: New alert generated
- `metric`: New metric collected
- `agent_status`: Agent status change
- `system_health`: System health update

---

This API documentation provides comprehensive access to all Crown Jewel Monitor functionality. For additional examples and integration guides, see the [examples/](../examples/) directory.