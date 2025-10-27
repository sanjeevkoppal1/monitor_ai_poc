# Crown Jewel Monitor - Configuration Guide

## 📋 Configuration Overview

The Crown Jewel Monitor uses YAML configuration files to define system behavior, agent settings, and monitoring parameters. Configuration follows a hierarchical structure with global settings and agent-specific configurations.

## 🗂️ Configuration Structure

```yaml
# Global settings affect all agents and system behavior
global:
  # ... global configuration

# Splunk integration settings
splunk:
  # ... Splunk-specific configuration

# Java application monitoring settings
java_application:
  # ... Java app-specific configuration

# Individual agent configurations
agents:
  agent_name:
    type: agent_type
    config:
      # ... agent-specific settings

# Alerting and notification settings
alerting:
  # ... alerting configuration

# Security and authentication settings
security:
  # ... security configuration
```

## 🌐 Global Configuration

### Basic Settings
```yaml
global:
  # Logging configuration
  log_level: INFO                    # DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_format: json                   # json, text
  log_file: "/var/log/crown-jewel-monitor.log"
  
  # Monitoring behavior
  monitoring_interval: 60            # Default monitoring interval in seconds
  max_concurrent_agents: 5           # Maximum concurrent agent executions
  
  # Data retention
  data_retention_hours: 24           # How long to keep metrics and alerts
  metric_storage_limit: 10000        # Maximum metrics to store per agent
  
  # Performance settings
  async_timeout: 30                  # Async operation timeout in seconds
  connection_pool_size: 10           # HTTP connection pool size
  
  # Feature flags
  enable_ml_anomaly_detection: true  # Enable ML-based anomaly detection
  enable_auto_remediation: false     # Enable automated remediation
  enable_predictive_alerts: true     # Enable predictive alerting
```

### Advanced Global Settings
```yaml
global:
  # Cluster settings (for distributed deployments)
  cluster:
    enabled: false
    node_id: "node-1"
    discovery_method: "static"       # static, consul, etcd
    discovery_endpoints:
      - "http://node-2:8080"
      - "http://node-3:8080"
  
  # Resource limits
  resource_limits:
    max_memory_mb: 2048             # Maximum memory usage
    max_cpu_percent: 80             # Maximum CPU usage
    max_disk_mb: 1024               # Maximum disk usage
  
  # Monitoring system self-monitoring
  self_monitoring:
    enabled: true
    health_check_interval: 30       # Self-health check interval
    metrics_export_port: 9090       # Prometheus metrics port
```

## 🔍 Splunk Configuration

### Basic Splunk Settings
```yaml
splunk:
  # Connection settings
  host: "splunk.company.com"
  port: 8089
  scheme: "https"                    # http or https
  verify_ssl: true
  
  # Authentication (choose one method)
  # Method 1: Username/Password
  username: "monitoring_user"
  password: "secure_password"
  
  # Method 2: Token-based authentication (recommended)
  # token: "your-splunk-auth-token"
  
  # Method 3: Certificate-based authentication
  # cert_file: "/path/to/client.crt"
  # key_file: "/path/to/client.key"
  # ca_file: "/path/to/ca.crt"
  
  # Search settings
  indexes: ["main", "java_logs", "application"]
  default_earliest_time: "-15m"
  default_latest_time: "now"
  max_search_results: 1000
  search_timeout: 300                # Search timeout in seconds
  
  # Java application specific settings
  java_app_name: "crown-jewel-app"
  log_source_patterns:
    - "*crown-jewel*"
    - "*java-app*"
  sourcetypes:
    - "java_application"
    - "catalina"
    - "gc_logs"
```

### Advanced Splunk Settings
```yaml
splunk:
  # Connection pooling and performance
  connection_pool:
    max_connections: 10
    connection_timeout: 30
    read_timeout: 60
    retry_attempts: 3
    backoff_factor: 2
  
  # Search optimization
  search_optimization:
    use_cache: true
    cache_ttl_minutes: 5
    parallel_searches: true
    batch_size: 100
  
  # Custom queries for specific monitoring
  custom_queries:
    error_monitoring:
      query: |
        search index=main source="*crown-jewel*" 
        (ERROR OR Exception OR FATAL)
        | bucket _time span=5m 
        | stats count as error_count by _time
      interval: 300
      alert_threshold: 10
    
    performance_monitoring:
      query: |
        search index=main source="*crown-jewel*" 
        "response_time" 
        | rex field=_raw "response_time=(?<response_ms>\\d+)"
        | stats avg(response_ms) as avg_response by _time
      interval: 180
      alert_threshold: 5000
  
  # Pattern definitions for log analysis
  log_patterns:
    critical_errors:
      - pattern: "OutOfMemoryError"
        severity: "critical"
        frequency_threshold: 1
        time_window_minutes: 1
      - pattern: "java.lang.StackOverflowError"
        severity: "critical"
        frequency_threshold: 1
        time_window_minutes: 5
    
    performance_issues:
      - pattern: "slow query"
        severity: "medium"
        frequency_threshold: 5
        time_window_minutes: 10
      - pattern: "timeout"
        severity: "high"
        frequency_threshold: 3
        time_window_minutes: 5
```

## ☕ Java Application Configuration

### Basic Java Settings
```yaml
java_application:
  # Application identification
  name: "crown-jewel-app"
  process_pattern: "java.*crown-jewel"  # Pattern to find Java processes
  java_home: "/usr/lib/jvm/default-java"
  
  # JMX configuration
  jmx:
    host: "localhost"
    port: 9999
    username: "jmx_user"              # Optional
    password: "jmx_password"          # Optional
    ssl_enabled: false
    connection_timeout: 10
  
  # Health endpoint configuration
  health_endpoints:
    - url: "http://localhost:8080/actuator/health"
      timeout: 10
      expected_status: 200
    - url: "http://localhost:8080/health"
      timeout: 5
      expected_status: 200
    - url: "http://localhost:8080/actuator/metrics"
      timeout: 15
      expected_status: 200
  
  # Monitoring thresholds
  thresholds:
    memory_percent: 85               # Heap usage alert threshold
    cpu_percent: 80                  # CPU usage alert threshold
    gc_pause_ms: 1000               # GC pause time alert threshold
    response_time_ms: 5000          # Response time alert threshold
    error_rate_percent: 5           # Error rate alert threshold
    thread_count: 500               # Thread count alert threshold
```

### Advanced Java Settings
```yaml
java_application:
  # Process monitoring
  process_monitoring:
    scan_interval: 60               # Process discovery interval
    resource_monitoring: true      # Monitor CPU, memory, etc.
    thread_monitoring: true        # Monitor thread states
    gc_monitoring: true            # Monitor garbage collection
  
  # JVM-specific monitoring
  jvm_monitoring:
    memory_pools:
      - "Heap Memory"
      - "Non-Heap Memory"
      - "Eden Space"
      - "Survivor Space"
      - "Old Gen"
    
    garbage_collectors:
      - "G1 Young Generation"
      - "G1 Old Generation"
      - "Parallel GC"
    
    thread_states:
      - "RUNNABLE"
      - "BLOCKED"
      - "WAITING"
      - "TIMED_WAITING"
  
  # Performance baselines (learned automatically)
  performance_baselines:
    heap_usage_percent: 60.0
    cpu_usage_percent: 40.0
    avg_response_time_ms: 500.0
    gc_pause_time_ms: 100.0
    thread_count: 50
  
  # Custom metrics collection
  custom_metrics:
    business_metrics:
      - name: "active_sessions"
        jmx_bean: "com.company:type=SessionManager"
        attribute: "ActiveSessions"
        unit: "count"
      - name: "transaction_rate"
        jmx_bean: "com.company:type=TransactionManager"
        attribute: "TransactionsPerSecond"
        unit: "per_second"
    
    application_metrics:
      - name: "cache_hit_rate"
        endpoint: "/actuator/metrics/cache.gets"
        path: "measurements[0].value"
        unit: "percent"
```

## 🤖 Agent Configuration

### Agent Registration
```yaml
agents:
  # Splunk monitoring agent
  splunk_monitor:
    type: "splunk"
    enabled: true
    execution_interval: 300         # Run every 5 minutes
    config:
      # Agent-specific Splunk configuration
      # Inherits from global splunk section
      custom_queries_only: false
      pattern_matching_enabled: true
      anomaly_detection_enabled: true
  
  # Java health monitoring agent
  java_health_monitor:
    type: "java_health"
    enabled: true
    execution_interval: 60          # Run every minute
    config:
      # Agent-specific Java configuration
      # Inherits from global java_application section
      jmx_monitoring_enabled: true
      health_endpoint_monitoring: true
      process_monitoring_enabled: true
  
  # Custom agent example
  custom_business_monitor:
    type: "custom"
    enabled: false
    execution_interval: 120
    config:
      monitoring_endpoints:
        - "http://localhost:8080/api/business/health"
      custom_patterns:
        - "Business transaction failed"
```

### Agent-specific Settings
```yaml
agents:
  splunk_monitor:
    type: "splunk"
    config:
      # Override global Splunk settings for this agent
      indexes: ["java_logs"]        # Monitor only java_logs index
      search_frequency: 180         # Custom search frequency
      pattern_sensitivity: "high"   # Pattern matching sensitivity
      
      # Agent-specific query overrides
      queries:
        error_rate:
          enabled: true
          custom_threshold: 5       # Override global threshold
        
        memory_monitoring:
          enabled: true
          query: |
            search index=java_logs "heap" 
            | rex field=_raw "heap.*?(?<heap_pct>\\d+)%"
            | where heap_pct > 80
  
  java_health_monitor:
    type: "java_health"
    config:
      # JMX-specific settings
      jmx_connection_retry: 3
      jmx_retry_delay: 10
      
      # Health check customization
      health_check_parallel: true
      health_check_timeout: 15
      
      # Performance monitoring
      performance_analysis:
        trend_analysis_enabled: true
        anomaly_detection_window: 60  # minutes
        baseline_learning_rate: 0.1
```

## 🚨 Alerting Configuration

### Alert Channels
```yaml
alerting:
  # Global alerting settings
  enabled: true
  default_severity_threshold: "medium"  # minimum severity to process
  alert_suppression_window: 300         # seconds
  max_alerts_per_hour: 100
  
  # Notification channels
  channels:
    # Slack integration
    slack:
      enabled: true
      webhook_url: "https://hooks.slack.com/services/..."
      channel: "#monitoring-alerts"
      username: "Crown Jewel Monitor"
      severity_mapping:
        critical: "@channel CRITICAL"
        high: "HIGH"
        medium: "medium"
        low: "low"
    
    # Email notifications
    email:
      enabled: true
      smtp_host: "smtp.company.com"
      smtp_port: 587
      smtp_username: "alerts@company.com"
      smtp_password: "smtp_password"
      from_address: "crown-jewel-monitor@company.com"
      recipients:
        critical: ["oncall@company.com", "management@company.com"]
        high: ["dev-team@company.com", "ops-team@company.com"]
        medium: ["dev-team@company.com"]
        low: ["dev-team@company.com"]
    
    # PagerDuty integration
    pagerduty:
      enabled: true
      integration_key: "your-pagerduty-integration-key"
      severity_mapping:
        critical: "critical"
        high: "error"
        medium: "warning"
        low: "info"
    
    # Custom webhook
    custom_webhook:
      enabled: false
      url: "https://your-webhook-endpoint.com/alerts"
      headers:
        Authorization: "Bearer your-token"
        Content-Type: "application/json"
```

### Alert Rules and Escalation
```yaml
alerting:
  # Alert routing rules
  routing_rules:
    - name: "critical_java_errors"
      conditions:
        - agent: "splunk_monitor"
        - severity: "critical"
        - pattern: "OutOfMemoryError|StackOverflowError"
      actions:
        - channel: "pagerduty"
        - channel: "slack"
        - channel: "email"
      escalation:
        initial_delay: 0
        escalation_delay: 300       # 5 minutes
        max_escalations: 3
    
    - name: "performance_degradation"
      conditions:
        - agent: "java_health_monitor"
        - severity: ["high", "critical"]
        - metric_type: "performance"
      actions:
        - channel: "slack"
        - channel: "email"
      escalation:
        initial_delay: 60          # 1 minute
        escalation_delay: 600      # 10 minutes
        max_escalations: 2
  
  # Alert suppression rules
  suppression_rules:
    - name: "maintenance_window"
      schedule:
        - day: "sunday"
          start_time: "02:00"
          end_time: "04:00"
          timezone: "UTC"
      suppress_severities: ["low", "medium"]
    
    - name: "duplicate_memory_alerts"
      conditions:
        - alert_type: "memory_usage"
        - time_window: 300          # 5 minutes
      action: "suppress_duplicates"
      max_alerts: 1
```

## 🔐 Security Configuration

### Authentication and Authorization
```yaml
security:
  # API security
  api:
    enabled: true
    port: 8443
    ssl_enabled: true
    ssl_cert: "/path/to/server.crt"
    ssl_key: "/path/to/server.key"
    
    # Authentication methods
    authentication:
      type: "token"                 # token, basic, certificate
      tokens:
        - token: "secure-api-token-1"
          permissions: ["read", "write", "admin"]
          expires: "2024-12-31"
        - token: "readonly-token"
          permissions: ["read"]
          expires: "2024-06-30"
  
  # Data protection
  data_protection:
    # PII detection and filtering
    pii_filtering:
      enabled: true
      patterns:
        - "\\b\\d{3}-\\d{2}-\\d{4}\\b"      # SSN
        - "\\b\\d{16}\\b"                    # Credit card
        - "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"  # Email
    
    # Sensitive data encryption
    encryption:
      enabled: true
      algorithm: "AES-256-GCM"
      key_rotation_days: 90
  
  # Access control
  access_control:
    # Role-based access control
    roles:
      admin:
        permissions: ["*"]
        users: ["admin@company.com"]
      
      operator:
        permissions: ["read", "acknowledge_alerts", "run_actions"]
        users: ["ops@company.com", "dev@company.com"]
      
      readonly:
        permissions: ["read"]
        users: ["manager@company.com"]
```

### Audit and Compliance
```yaml
security:
  # Audit logging
  audit:
    enabled: true
    log_file: "/var/log/crown-jewel-monitor-audit.log"
    log_format: "json"
    events:
      - "authentication"
      - "authorization"
      - "configuration_changes"
      - "alert_acknowledgment"
      - "remediation_actions"
    retention_days: 365
  
  # Compliance settings
  compliance:
    # SOX compliance
    sox_compliance:
      enabled: true
      require_dual_approval: true
      audit_trail_retention: 2555   # 7 years in days
    
    # GDPR compliance
    gdpr_compliance:
      enabled: true
      data_retention_days: 1095      # 3 years
      anonymization_enabled: true
      right_to_deletion: true
```

## 🎛️ Environment-specific Configuration

### Development Environment
```yaml
# config/dev.yaml
global:
  log_level: DEBUG
  monitoring_interval: 30
  data_retention_hours: 2

splunk:
  host: "dev-splunk.company.com"
  verify_ssl: false

java_application:
  thresholds:
    memory_percent: 95              # Higher thresholds for dev
    cpu_percent: 90

alerting:
  channels:
    slack:
      channel: "#dev-monitoring"
    email:
      enabled: false                # Disable email in dev
```

### Production Environment
```yaml
# config/prod.yaml
global:
  log_level: INFO
  monitoring_interval: 60
  data_retention_hours: 168         # 1 week

splunk:
  host: "splunk.company.com"
  verify_ssl: true

java_application:
  thresholds:
    memory_percent: 80              # Stricter thresholds for prod
    cpu_percent: 70

alerting:
  channels:
    pagerduty:
      enabled: true                 # Enable PagerDuty in prod
    email:
      enabled: true
```

## 📝 Configuration Validation

### Validation Rules
The system validates configuration on startup:

```yaml
# Configuration schema validation
validation:
  required_fields:
    - global.log_level
    - splunk.host
    - java_application.name
  
  field_constraints:
    global.monitoring_interval:
      min: 10
      max: 3600
    
    java_application.thresholds.memory_percent:
      min: 50
      max: 99
  
  dependency_checks:
    - if: splunk.enabled
      then: required [splunk.host, splunk.username]
    
    - if: java_application.jmx.ssl_enabled
      then: required [java_application.jmx.keystore]
```

### Configuration Testing
```bash
# Validate configuration
python -m crown_jewel_monitor.config.validate --config config/prod.yaml

# Test connectivity with configuration
python -m crown_jewel_monitor.config.test --config config/prod.yaml

# Show resolved configuration
python -m crown_jewel_monitor.config.show --config config/prod.yaml
```

---

This configuration guide provides comprehensive settings for all aspects of the Crown Jewel Monitor system. Adjust values based on your specific environment and requirements.