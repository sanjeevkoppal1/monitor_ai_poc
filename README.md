# Java Application Monitor

**Agentic Post-Deployment Monitoring and Auto-Remediation System**

A comprehensive, intelligent monitoring solution designed for crown jewel Java applications that provides proactive monitoring, automated issue detection, and self-healing capabilities through Splunk integration and direct JVM monitoring.

## 🎯 Overview

The Crown Jewel Monitor is an autonomous monitoring system that:

- **Monitors Java applications** through multiple channels (Splunk logs, JMX metrics, health endpoints)
- **Detects issues proactively** using ML-based anomaly detection and pattern matching
- **Executes automated remediation** for common issues without human intervention
- **Escalates critical issues** to human operators with detailed context
- **Learns from incidents** to improve detection accuracy and reduce false positives

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Agent Orchestrator                          │
│           (Central Coordination & Management)               │
└─────────────────┬───────────────────┬───────────────────────┘
                  │                   │
        ┌─────────▼─────────┐ ┌───────▼──────────┐
        │  Splunk Agent     │ │ Java Health Agent │
        │  - Log Analysis   │ │ - JVM Metrics     │
        │  - Pattern Match  │ │ - Health Checks   │
        │  - Anomaly Detect │ │ - Process Monitor │
        └─────────┬─────────┘ └───────┬──────────┘
                  │                   │
        ┌─────────▼─────────┐ ┌───────▼──────────┐
        │ Issue Detection   │ │ Remediation      │
        │ Agent             │ │ Agent            │
        │ - Root Cause      │ │ - Auto-healing   │
        │ - Correlation     │ │ - Escalation     │
        └───────────────────┘ └──────────────────┘
```

## 🚀 Key Features

### **Intelligent Monitoring**
- **Multi-source Data Collection**: Splunk logs, JMX metrics, health endpoints, process monitoring
- **Real-time Analysis**: Sub-second monitoring with intelligent sampling
- **Pattern Recognition**: ML-based pattern detection for known issues
- **Anomaly Detection**: Statistical analysis to identify unusual behavior

### **Proactive Issue Detection**
- **Predictive Alerts**: Early warning system for potential issues
- **Root Cause Analysis**: Automated correlation across multiple data sources
- **Business Impact Assessment**: Prioritization based on business criticality
- **False Positive Reduction**: Self-learning algorithms to improve accuracy

### **Automated Remediation**
- **Self-healing Actions**: Automated fixes for common issues
- **Approval Workflows**: Human approval for high-impact actions
- **Success Tracking**: Learning from remediation success/failure rates
- **Rollback Capabilities**: Safe action execution with rollback options

### **Observability & Insights**
- **Comprehensive Dashboards**: Real-time system health visualization
- **Historical Analysis**: Trend analysis and capacity planning
- **Performance Baselines**: Adaptive learning of normal behavior
- **Audit Trails**: Complete tracking of all monitoring and remediation activities

## 📋 Prerequisites

### System Requirements
- **Python**: 3.8+ with asyncio support
- **Java Application**: Java 8+ with JMX enabled
- **Splunk**: Splunk Enterprise or Cloud with REST API access
- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 2GB RAM for monitoring agent
- **Network**: Access to monitored applications and Splunk instance

### Java Application Setup
```bash
# Enable JMX on your Java application
java -Dcom.sun.management.jmxremote \
     -Dcom.sun.management.jmxremote.port=9999 \
     -Dcom.sun.management.jmxremote.authenticate=false \
     -Dcom.sun.management.jmxremote.ssl=false \
     -jar your-crown-jewel-app.jar
```

### Splunk Configuration
```bash
# Ensure your application logs are indexed in Splunk
# Minimum required indexes: main, java_logs
# Required sourcetypes: java_application, application_logs
```

## 🛠️ Installation

### 1. Clone Repository
```bash
git clone <repository-url>
cd crown-jewel-monitor
```

### 2. Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install optional dependencies for enhanced features
pip install py4j  # For JMX integration
python -m spacy download en_core_web_sm  # For log analysis
```

### 3. Configuration
```bash
# Copy and customize configuration
cp config/config.example.yaml config/config.yaml
```

See [Configuration Guide](docs/CONFIGURATION.md) for detailed setup instructions.

## 🚦 Quick Start

### 1. Basic Configuration
```yaml
# config/config.yaml
global:
  log_level: INFO
  monitoring_interval: 60

splunk:
  host: "your-splunk-host.com"
  port: 8089
  username: "monitoring_user"
  password: "secure_password"
  
java_application:
  name: "crown-jewel-app"
  jmx_host: "localhost"
  jmx_port: 9999
  health_endpoints:
    - "http://localhost:8080/actuator/health"
    - "http://localhost:8080/health"
```

### 2. Run the Monitor
```bash
# Start the monitoring system
python -m crown_jewel_monitor.main --config config/config.yaml

# Or run with specific agents only
python -m crown_jewel_monitor.main --agents splunk,java_health
```

### 3. Verify Operation
```bash
# Check agent status
curl http://localhost:8080/status

# View recent alerts
curl http://localhost:8080/alerts

# Get system health
curl http://localhost:8080/health
```

## 📊 Usage Examples

### Monitoring Java Application Health
```python
from crown_jewel_monitor import AgentOrchestrator, AgentConfig

# Load configuration
config = AgentConfig.from_file("config/config.yaml")

# Create orchestrator
orchestrator = AgentOrchestrator(config.get_global_config())

# Create and register agents
splunk_agent = AgentFactory.create_agent(
    "splunk", "splunk_monitor", config.get_splunk_config()
)
java_agent = AgentFactory.create_agent(
    "java_health", "java_monitor", config.get_java_app_config()
)

orchestrator.register_agent(splunk_agent)
orchestrator.register_agent(java_agent)

# Initialize and start monitoring
await orchestrator.initialize_all_agents()
await orchestrator.start_continuous_monitoring(interval=60)
```

### Custom Alert Handlers
```python
async def custom_alert_handler(alert):
    """Custom alert processing logic."""
    if alert.severity == AlertSeverity.CRITICAL:
        # Send to PagerDuty
        await send_pagerduty_alert(alert)
    elif alert.severity == AlertSeverity.HIGH:
        # Send to Slack
        await send_slack_notification(alert)
    
    # Log all alerts
    logger.info("Alert processed", alert_id=alert.id)

# Register custom handler
orchestrator.register_alert_handler(custom_alert_handler)
```

## 📈 Monitoring Capabilities

### Splunk Integration
- **Log Pattern Analysis**: Real-time parsing of Java application logs
- **Error Rate Monitoring**: Tracking error frequencies and trends
- **Performance Metrics**: Response times, throughput analysis
- **Security Event Detection**: Authentication failures, suspicious activity
- **Business Transaction Monitoring**: Transaction success/failure rates

### Java Application Health
- **JVM Metrics**: Memory usage, garbage collection, thread analysis
- **Health Endpoints**: Spring Boot Actuator, custom health checks
- **Process Monitoring**: CPU usage, memory consumption, thread counts
- **Performance Analysis**: Response times, error rates, throughput
- **Anomaly Detection**: Statistical analysis against performance baselines

### Proactive Issue Detection
- **Memory Leak Detection**: Heap usage trend analysis
- **Performance Degradation**: Response time increase detection
- **Deadlock Detection**: Thread dump analysis for concurrency issues
- **Resource Exhaustion**: Predictive alerts for resource limits
- **Configuration Issues**: Detection of misconfigurations

## 🔧 Configuration

The system uses YAML configuration files for setup. Key configuration sections:

### Global Settings
```yaml
global:
  log_level: INFO
  monitoring_interval: 60
  max_concurrent_agents: 5
  data_retention_hours: 24
```

### Splunk Configuration
```yaml
splunk:
  host: "splunk.company.com"
  port: 8089
  username: "monitor_user"
  token: "your-auth-token"  # Alternative to username/password
  indexes: ["main", "java_logs", "application"]
  verify_ssl: true
```

### Java Application Settings
```yaml
java_application:
  name: "crown-jewel-app"
  process_pattern: "java.*crown-jewel"
  jmx_host: "localhost"
  jmx_port: 9999
  health_endpoints:
    - "http://localhost:8080/actuator/health"
  thresholds:
    memory_percent: 85
    cpu_percent: 80
    response_time_ms: 5000
```

See [Complete Configuration Reference](docs/CONFIGURATION.md) for all options.

## 🚨 Alerting & Escalation

### Alert Severity Levels
- **CRITICAL**: Immediate action required (service outage, data loss)
- **HIGH**: Urgent attention needed (performance degradation, errors)
- **MEDIUM**: Issue that should be addressed (warnings, trends)
- **LOW**: Informational (configuration changes, minor issues)

### Escalation Paths
1. **Automated Remediation**: Attempt self-healing for known issues
2. **Team Notification**: Alert development/operations teams
3. **Management Escalation**: Notify management for critical issues
4. **Emergency Response**: Trigger incident response procedures

### Notification Channels
- **Slack**: Real-time team notifications
- **Email**: Detailed alert summaries
- **PagerDuty**: Critical issue escalation
- **SMS**: Emergency notifications
- **Dashboard**: Visual monitoring displays

## 🔍 Troubleshooting

### Common Issues

#### Agent Connection Failures
```bash
# Check Splunk connectivity
curl -k -u username:password "https://splunk-host:8089/services/auth/login"

# Verify JMX access
jconsole localhost:9999
```

#### High Memory Usage
```bash
# Monitor agent memory usage
ps aux | grep crown-jewel-monitor
top -p $(pgrep -f crown-jewel-monitor)

# Adjust monitoring frequency
export MONITORING_INTERVAL=120  # Reduce frequency
```

#### Missing Metrics
```bash
# Check Java application JMX settings
jinfo -flags <java-pid>

# Verify health endpoints
curl -v http://localhost:8080/actuator/health
```

See [Detailed Troubleshooting Guide](docs/TROUBLESHOOTING.md) for comprehensive solutions.

## 📚 Documentation

- [Architecture Guide](docs/ARCHITECTURE.md) - Detailed system architecture
- [Configuration Reference](docs/CONFIGURATION.md) - Complete configuration options
- [API Documentation](docs/API.md) - REST API reference
- [Agent Development](docs/AGENT_DEVELOPMENT.md) - Creating custom agents
- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment
- [Security Guide](docs/SECURITY.md) - Security best practices
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Problem resolution

## 🔐 Security

### Authentication & Authorization
- **API Authentication**: Token-based authentication for REST API
- **Splunk Access**: Secure credential management
- **JMX Security**: Optional SSL/TLS encryption
- **Role-based Access**: Different access levels for users

### Data Protection
- **Sensitive Data Filtering**: Automatic PII detection and filtering
- **Encrypted Storage**: Sensitive configuration encryption
- **Audit Logging**: Complete audit trail of all activities
- **Network Security**: TLS encryption for all communications

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
# Clone repository
git clone <repository-url>
cd crown-jewel-monitor

# Create development environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run with development configuration
python -m crown_jewel_monitor.main --config config/dev.yaml
```

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Email**: monitoring-support@company.com

## 🎉 Acknowledgments

- Splunk team for excellent log aggregation platform
- Spring Boot team for comprehensive health endpoints
- Python asyncio community for asynchronous programming patterns
- Open source monitoring and observability community

---

**Crown Jewel Java Application Monitor** - Intelligent, proactive monitoring for mission-critical applications.
