# Crown Jewel Monitor - Troubleshooting Guide

## 🛠️ Common Issues and Solutions

This guide provides comprehensive solutions for common issues encountered when running the Crown Jewel Monitor system.

## 🔍 Diagnostic Commands

### System Health Check
```bash
# Check overall system status
python -m crown_jewel_monitor.health_check --config config/config.yaml

# Validate configuration
python -m crown_jewel_monitor.config.validate --config config/config.yaml

# Test connectivity to external systems
python -m crown_jewel_monitor.connectivity_test --config config/config.yaml
```

### Agent Status
```bash
# Check agent status
curl http://localhost:8080/api/agents/status

# Get detailed agent information
curl http://localhost:8080/api/agents/details

# View agent logs
tail -f /var/log/crown-jewel-monitor.log | grep "agent_name"
```

## 🚫 Connection Issues

### Splunk Connection Problems

#### **Issue**: Unable to connect to Splunk
```
ERROR: SplunkConnectionError: Failed to connect to Splunk at https://splunk.company.com:8089
```

**Solution**:
```bash
# 1. Verify Splunk connectivity
curl -k -u username:password "https://splunk-host:8089/services/auth/login"

# 2. Check firewall and network access
telnet splunk-host 8089

# 3. Verify SSL certificate (if using HTTPS)
openssl s_client -connect splunk-host:8089 -showcerts

# 4. Test with different authentication method
# Update config.yaml to use token instead of username/password
splunk:
  token: "your-auth-token"
  # Comment out username/password
```

#### **Issue**: Authentication failures
```
ERROR: Authentication failed for user 'monitoring_user'
```

**Solution**:
```bash
# 1. Verify credentials in Splunk web interface
# 2. Check if account is locked
# 3. Verify user has required permissions:
#    - search capability
#    - access to required indexes
#    - REST API access

# 4. Create service account with minimal required permissions
# In Splunk: Settings > Access controls > Users > New User
# Required capabilities: search, rest_properties_get
```

#### **Issue**: SSL/TLS certificate errors
```
ERROR: SSL certificate verification failed
```

**Solution**:
```yaml
# Option 1: Disable SSL verification (development only)
splunk:
  verify_ssl: false

# Option 2: Provide certificate bundle
splunk:
  ca_file: "/path/to/splunk-ca.crt"

# Option 3: Use system certificate store
splunk:
  verify_ssl: true
  ca_file: null  # Uses system certificates
```

### JMX Connection Issues

#### **Issue**: Cannot connect to Java application JMX
```
ERROR: JMXConnectionError: Connection refused to localhost:9999
```

**Solution**:
```bash
# 1. Verify JMX is enabled on Java application
java -Dcom.sun.management.jmxremote \
     -Dcom.sun.management.jmxremote.port=9999 \
     -Dcom.sun.management.jmxremote.authenticate=false \
     -Dcom.sun.management.jmxremote.ssl=false \
     -jar your-app.jar

# 2. Check if port is open and accessible
netstat -an | grep 9999
telnet localhost 9999

# 3. Verify Java process is running
ps aux | grep java

# 4. Use jconsole to test JMX connectivity
jconsole localhost:9999
```

#### **Issue**: JMX authentication failures
```
ERROR: JMX authentication failed
```

**Solution**:
```bash
# 1. Create JMX password file
echo "monitor password123" > jmx.password
chmod 600 jmx.password

# 2. Create JMX access file
echo "monitor readonly" > jmx.access
chmod 644 jmx.access

# 3. Start Java application with authentication
java -Dcom.sun.management.jmxremote \
     -Dcom.sun.management.jmxremote.port=9999 \
     -Dcom.sun.management.jmxremote.authenticate=true \
     -Dcom.sun.management.jmxremote.password.file=jmx.password \
     -Dcom.sun.management.jmxremote.access.file=jmx.access \
     -jar your-app.jar

# 4. Update crown-jewel-monitor configuration
java_application:
  jmx:
    username: "monitor"
    password: "password123"
```

### Health Endpoint Issues

#### **Issue**: Health endpoints returning errors
```
ERROR: Health endpoint http://localhost:8080/actuator/health returned 404
```

**Solution**:
```bash
# 1. Verify Spring Boot Actuator is enabled
# Add to application.properties:
management.endpoints.web.exposure.include=health,metrics,info
management.endpoint.health.show-details=always

# 2. Check if endpoints are accessible
curl -v http://localhost:8080/actuator/health
curl -v http://localhost:8080/actuator/metrics

# 3. Verify application is running on expected port
netstat -tlnp | grep :8080

# 4. Update configuration with correct endpoints
java_application:
  health_endpoints:
    - url: "http://localhost:8080/actuator/health"
    - url: "http://localhost:8080/health"  # Fallback
```

## ⚡ Performance Issues

### High Memory Usage

#### **Issue**: Crown Jewel Monitor consuming excessive memory
```
WARNING: Agent memory usage: 2.5GB (threshold: 2GB)
```

**Solution**:
```yaml
# 1. Reduce monitoring frequency
global:
  monitoring_interval: 120  # Increase from 60 seconds

# 2. Limit data retention
global:
  data_retention_hours: 12  # Reduce from 24 hours
  metric_storage_limit: 5000  # Reduce from 10000

# 3. Disable intensive features temporarily
global:
  enable_ml_anomaly_detection: false  # Disable ML features

# 4. Optimize Splunk queries
splunk:
  max_search_results: 500  # Reduce from 1000
  search_optimization:
    batch_size: 50  # Reduce batch size
```

### Slow Performance

#### **Issue**: Monitoring system responding slowly
```
WARNING: Agent execution time: 45s (threshold: 30s)
```

**Solution**:
```yaml
# 1. Enable parallel processing
global:
  max_concurrent_agents: 3  # Increase concurrency

# 2. Optimize Splunk searches
splunk:
  search_optimization:
    parallel_searches: true
    use_cache: true
    cache_ttl_minutes: 10

# 3. Reduce monitoring scope temporarily
agents:
  splunk_monitor:
    config:
      indexes: ["main"]  # Monitor fewer indexes
      
  java_health_monitor:
    execution_interval: 120  # Reduce frequency
```

### CPU Usage Issues

#### **Issue**: High CPU usage from monitoring agents
```
WARNING: Crown Jewel Monitor CPU usage: 85%
```

**Solution**:
```bash
# 1. Check which agent is consuming CPU
top -p $(pgrep -f crown-jewel-monitor)

# 2. Reduce monitoring intensity
# Update config.yaml:
global:
  monitoring_interval: 180  # Every 3 minutes instead of 1

# 3. Disable CPU-intensive features
global:
  enable_ml_anomaly_detection: false
  enable_predictive_alerts: false

# 4. Use sampling for high-volume data
splunk:
  search_optimization:
    batch_size: 25
    parallel_searches: false
```

## 📊 Data Issues

### Missing Metrics

#### **Issue**: No metrics being collected from Java application
```
WARNING: No JVM metrics received in last 10 minutes
```

**Solution**:
```bash
# 1. Verify JMX connectivity
jconsole localhost:9999

# 2. Check if py4j is installed
pip install py4j

# 3. Verify Java application has JMX enabled
jinfo -flags <java-pid> | grep jmxremote

# 4. Test manual JMX query
python3 << EOF
from py4j.java_gateway import JavaGateway
gateway = JavaGateway()
app = gateway.entry_point
print(app.getMemoryUsage())
EOF
```

### Incorrect Log Analysis

#### **Issue**: Splunk agent not detecting known errors
```
INFO: No critical patterns detected in last hour
# But manual search shows OutOfMemoryError events
```

**Solution**:
```yaml
# 1. Verify log patterns are correctly configured
splunk:
  log_patterns:
    critical_errors:
      - pattern: "OutOfMemoryError"
        severity: "critical"
        frequency_threshold: 1

# 2. Check if logs are in expected indexes
splunk:
  indexes: ["main", "java_logs", "application"]

# 3. Verify sourcetype patterns
splunk:
  sourcetypes:
    - "java_application"
    - "catalina"
    - "application_logs"

# 4. Test pattern manually in Splunk
search index=main "OutOfMemoryError" earliest=-1h
```

### Data Retention Issues

#### **Issue**: Historical data not available
```
ERROR: No historical data found for baseline calculation
```

**Solution**:
```yaml
# 1. Increase data retention
global:
  data_retention_hours: 72  # 3 days instead of 24 hours

# 2. Verify data is being stored
# Check data directory
ls -la /var/lib/crown-jewel-monitor/data/

# 3. Check disk space
df -h /var/lib/crown-jewel-monitor/

# 4. Enable data persistence
global:
  data_persistence:
    enabled: true
    storage_path: "/var/lib/crown-jewel-monitor/data"
```

## 🔧 Configuration Issues

### Invalid Configuration

#### **Issue**: Configuration validation errors
```
ERROR: Configuration validation failed: Invalid threshold value
```

**Solution**:
```bash
# 1. Validate configuration syntax
python -m crown_jewel_monitor.config.validate --config config/config.yaml

# 2. Check required fields
# Ensure all required sections are present:
global:
  log_level: INFO
splunk:
  host: "required"
java_application:
  name: "required"

# 3. Verify value ranges
java_application:
  thresholds:
    memory_percent: 85  # Must be 50-99
    cpu_percent: 80     # Must be 10-99
```

### Environment-specific Issues

#### **Issue**: Configuration works in dev but fails in production
```
ERROR: Connection timeout in production environment
```

**Solution**:
```yaml
# 1. Create environment-specific configs
# config/prod.yaml
global:
  monitoring_interval: 60
  async_timeout: 60  # Increase timeout for prod

splunk:
  host: "prod-splunk.company.com"
  connection_pool:
    connection_timeout: 60  # Increase for prod
    read_timeout: 120

# 2. Use environment variables
export CROWN_JEWEL_ENV=production
export SPLUNK_HOST=prod-splunk.company.com
export SPLUNK_TOKEN=prod-token

# 3. Test connectivity in production environment
curl -k "https://prod-splunk.company.com:8089/services/auth/login"
```

## 🚨 Alert Issues

### Missing Alerts

#### **Issue**: Critical issues not generating alerts
```
# OutOfMemoryError occurred but no alert was sent
```

**Solution**:
```yaml
# 1. Verify alerting is enabled
alerting:
  enabled: true
  default_severity_threshold: "medium"  # Lower threshold

# 2. Check alert routing rules
alerting:
  routing_rules:
    - name: "critical_java_errors"
      conditions:
        - severity: "critical"
        - pattern: "OutOfMemoryError"
      actions:
        - channel: "slack"
        - channel: "email"

# 3. Test alert channels
# For Slack:
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test alert"}' \
  YOUR_SLACK_WEBHOOK_URL

# For Email:
python3 << EOF
import smtplib
server = smtplib.SMTP('smtp.company.com', 587)
server.send_message(test_message)
EOF
```

### Too Many Alerts

#### **Issue**: Alert fatigue from excessive notifications
```
WARNING: 150 alerts generated in last hour
```

**Solution**:
```yaml
# 1. Enable alert suppression
alerting:
  alert_suppression_window: 600  # 10 minutes
  max_alerts_per_hour: 50

# 2. Increase alert thresholds
java_application:
  thresholds:
    memory_percent: 90  # Increase from 85
    cpu_percent: 85     # Increase from 80

# 3. Add suppression rules
alerting:
  suppression_rules:
    - name: "duplicate_memory_alerts"
      conditions:
        - alert_type: "memory_usage"
        - time_window: 600
      max_alerts: 1

# 4. Adjust pattern sensitivity
splunk:
  log_patterns:
    performance_issues:
      - pattern: "slow query"
        frequency_threshold: 10  # Increase threshold
        time_window_minutes: 15  # Longer window
```

## 🔄 Service Management Issues

### Startup Problems

#### **Issue**: Crown Jewel Monitor fails to start
```
ERROR: Failed to initialize agents
```

**Solution**:
```bash
# 1. Check system dependencies
python3 --version  # Ensure Python 3.8+
pip list | grep -E "(splunk|aiohttp|psutil)"

# 2. Verify configuration
python -m crown_jewel_monitor.config.validate --config config/config.yaml

# 3. Check file permissions
ls -la config/config.yaml
chmod 644 config/config.yaml

# 4. Start with debug logging
python -m crown_jewel_monitor.main \
  --config config/config.yaml \
  --log-level DEBUG

# 5. Check for port conflicts
netstat -tlnp | grep 8080
```

### Service Crashes

#### **Issue**: Monitoring service crashes unexpectedly
```
ERROR: Agent crashed with exception: MemoryError
```

**Solution**:
```bash
# 1. Check system resources
free -h
df -h

# 2. Review crash logs
tail -100 /var/log/crown-jewel-monitor.log
journalctl -u crown-jewel-monitor --since "1 hour ago"

# 3. Add memory limits
# Update systemd service file:
[Service]
MemoryLimit=2G
MemoryAccounting=true

# 4. Enable automatic restart
[Service]
Restart=always
RestartSec=10
```

### Performance Degradation

#### **Issue**: System becomes slow over time
```
WARNING: Response time increased 300% over 24 hours
```

**Solution**:
```bash
# 1. Check for memory leaks
ps aux | grep crown-jewel-monitor
pmap $(pgrep crown-jewel-monitor)

# 2. Restart agents periodically
# Add to crontab:
0 */6 * * * systemctl restart crown-jewel-monitor

# 3. Clear accumulated data
find /var/lib/crown-jewel-monitor/data -mtime +7 -delete

# 4. Optimize database queries
# Vacuum SQLite databases if used:
sqlite3 /var/lib/crown-jewel-monitor/metrics.db "VACUUM;"
```

## 🛡️ Security Issues

### Authentication Problems

#### **Issue**: API authentication failures
```
ERROR: Invalid API token
```

**Solution**:
```yaml
# 1. Generate new API token
security:
  api:
    authentication:
      tokens:
        - token: "new-secure-token-here"
          permissions: ["read", "write"]
          expires: "2025-12-31"

# 2. Verify token format
# Token should be at least 32 characters
openssl rand -hex 32

# 3. Check token permissions
curl -H "Authorization: Bearer your-token" \
  http://localhost:8080/api/status
```

### Certificate Issues

#### **Issue**: SSL certificate validation errors
```
ERROR: Certificate verification failed
```

**Solution**:
```bash
# 1. Check certificate validity
openssl x509 -in /path/to/cert.crt -text -noout

# 2. Verify certificate chain
openssl verify -CAfile /path/to/ca.crt /path/to/cert.crt

# 3. Update certificate bundle
curl -o /etc/ssl/certs/ca-certificates.crt \
  https://curl.se/ca/cacert.pem

# 4. Temporarily disable SSL verification (testing only)
export PYTHONHTTPSVERIFY=0
```

## 📋 Debugging Checklist

### Pre-troubleshooting Steps
- [ ] Check system resources (CPU, memory, disk)
- [ ] Verify all dependencies are installed
- [ ] Validate configuration file syntax
- [ ] Check network connectivity to external systems
- [ ] Review recent log entries

### Network Connectivity
- [ ] Ping Splunk server
- [ ] Test Splunk REST API access
- [ ] Verify JMX port accessibility
- [ ] Check health endpoint responses
- [ ] Test alert notification channels

### Service Health
- [ ] Verify all agents are running
- [ ] Check agent execution times
- [ ] Monitor memory usage trends
- [ ] Review error rates and patterns
- [ ] Validate alert generation

### Data Quality
- [ ] Confirm metrics are being collected
- [ ] Verify log patterns are matching
- [ ] Check data retention settings
- [ ] Validate baseline calculations
- [ ] Test anomaly detection accuracy

## 📞 Getting Help

### Log Collection
```bash
# Collect comprehensive logs for support
mkdir crown-jewel-debug
cp config/config.yaml crown-jewel-debug/
cp /var/log/crown-jewel-monitor.log crown-jewel-debug/
dmesg > crown-jewel-debug/dmesg.log
ps aux > crown-jewel-debug/processes.log
netstat -tlnp > crown-jewel-debug/network.log
tar -czf crown-jewel-debug.tar.gz crown-jewel-debug/
```

### Support Information
When contacting support, please provide:
1. Crown Jewel Monitor version
2. Operating system and version
3. Python version
4. Configuration file (sanitized)
5. Error logs and stack traces
6. Network topology diagram
7. Java application details

### Community Resources
- **Documentation**: [docs/](docs/)
- **GitHub Issues**: Report bugs and feature requests
- **Discussions**: Community Q&A and best practices
- **Stack Overflow**: Tag questions with `crown-jewel-monitor`

---

This troubleshooting guide covers the most common issues encountered with the Crown Jewel Monitor system. For additional help, please refer to the documentation or contact support.