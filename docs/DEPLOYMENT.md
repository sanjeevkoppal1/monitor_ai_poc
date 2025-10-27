# Crown Jewel Monitor - Deployment Guide

## 🚀 Production Deployment Guide

This guide covers deploying the Crown Jewel Monitor in production environments with high availability, security, and scalability considerations.

## 🏗️ Architecture Overview

### Single Instance Deployment
```
┌─────────────────────────────────────────┐
│           Production Server             │
│ ┌─────────────────────────────────────┐ │
│ │      Crown Jewel Monitor            │ │
│ │ ┌─────────────┐ ┌─────────────────┐ │ │
│ │ │Orchestrator │ │  Agent Pool     │ │ │
│ │ │             │ │ • Splunk        │ │ │
│ │ │             │ │ • Java Health   │ │ │
│ │ │             │ │ • Custom Agents │ │ │
│ │ └─────────────┘ └─────────────────┘ │ │
│ └─────────────────────────────────────┘ │
│           ┌─────────────────┐           │
│           │  Load Balancer  │           │
│           └─────────────────┘           │
└─────────────────────────────────────────┘
```

### High Availability Deployment
```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   Primary       │  │   Secondary     │  │   Database      │
│   Monitor       │  │   Monitor       │  │   Cluster       │
│                 │  │                 │  │                 │
│ • Orchestrator  │  │ • Standby       │  │ • PostgreSQL    │
│ • Active Agents │  │ • Health Check  │  │ • Redis Cache   │
│ • API Server    │  │ • Failover      │  │ • Metrics Store │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │  (HAProxy/Nginx)│
                    └─────────────────┘
```

## 📋 Prerequisites

### System Requirements

#### Minimum Requirements
```bash
# Hardware
CPU: 2 cores (Intel/AMD x64)
Memory: 4GB RAM
Storage: 20GB available disk space
Network: 1Gbps network interface

# Operating System
Ubuntu 20.04+ / CentOS 8+ / RHEL 8+
Python 3.8+ with pip
```

#### Recommended Requirements
```bash
# Hardware
CPU: 4+ cores (Intel/AMD x64)
Memory: 8GB+ RAM
Storage: 50GB+ SSD storage
Network: 1Gbps+ network interface

# Operating System
Ubuntu 22.04 LTS / RHEL 9+
Python 3.10+ with pip
```

### Network Requirements
```bash
# Outbound Connections
Splunk Server: Port 8089 (HTTPS)
Java Applications: Configurable JMX ports (default 9999)
SMTP Server: Port 587/465 (Email alerts)
Slack/Teams: Port 443 (HTTPS webhooks)

# Inbound Connections
API Server: Port 8080 (HTTP) or 8443 (HTTPS)
Metrics Export: Port 9090 (Prometheus)
Health Check: Port 8081
```

## 🛠️ Installation

### 1. System Preparation

#### Create Service User
```bash
# Create dedicated user for the service
sudo useradd -r -m -s /bin/bash crown-jewel
sudo usermod -aG wheel crown-jewel  # For RHEL/CentOS
sudo usermod -aG sudo crown-jewel   # For Ubuntu

# Create application directories
sudo mkdir -p /opt/crown-jewel-monitor
sudo mkdir -p /var/log/crown-jewel
sudo mkdir -p /var/lib/crown-jewel
sudo mkdir -p /etc/crown-jewel

# Set ownership
sudo chown -R crown-jewel:crown-jewel /opt/crown-jewel-monitor
sudo chown -R crown-jewel:crown-jewel /var/log/crown-jewel
sudo chown -R crown-jewel:crown-jewel /var/lib/crown-jewel
sudo chown -R crown-jewel:crown-jewel /etc/crown-jewel
```

#### Install System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3.10 python3.10-pip python3.10-venv
sudo apt install -y build-essential python3.10-dev
sudo apt install -y curl wget git htop
sudo apt install -y openjdk-11-jdk  # For JMX tools

# RHEL/CentOS
sudo dnf update
sudo dnf install -y python3.10 python3.10-pip
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y python3.10-devel
sudo dnf install -y curl wget git htop
sudo dnf install -y java-11-openjdk-devel
```

### 2. Application Installation

#### Download and Install
```bash
# Switch to service user
sudo su - crown-jewel

# Clone repository (or extract release package)
cd /opt/crown-jewel-monitor
git clone https://github.com/company/crown-jewel-monitor.git .

# Create virtual environment
python3.10 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install optional dependencies for production
pip install gunicorn uvicorn[standard]
pip install py4j  # For JMX integration
python -m spacy download en_core_web_sm  # For log analysis
```

#### Verify Installation
```bash
# Test basic functionality
python -m crown_jewel_monitor.config.validate --help
python -m crown_jewel_monitor.health_check --version
```

### 3. Configuration Setup

#### Create Production Configuration
```bash
# Copy configuration templates
cp config/config.example.yaml /etc/crown-jewel/config.yaml
cp config/prod.example.yaml /etc/crown-jewel/prod.yaml

# Create environment-specific configs
cp /etc/crown-jewel/config.yaml /etc/crown-jewel/production.yaml
```

#### Production Configuration Example
```yaml
# /etc/crown-jewel/production.yaml
global:
  log_level: INFO
  log_file: "/var/log/crown-jewel/crown-jewel-monitor.log"
  monitoring_interval: 60
  max_concurrent_agents: 8
  data_retention_hours: 168  # 1 week
  
  # Resource limits
  resource_limits:
    max_memory_mb: 4096
    max_cpu_percent: 80
    max_disk_mb: 2048

splunk:
  host: "prod-splunk.company.com"
  port: 8089
  scheme: "https"
  verify_ssl: true
  token: "${SPLUNK_AUTH_TOKEN}"  # Use environment variable
  
  indexes: ["main", "java_logs", "application"]
  connection_pool:
    max_connections: 10
    connection_timeout: 30
    read_timeout: 60

java_application:
  name: "crown-jewel-app"
  process_pattern: "java.*crown-jewel"
  
  jmx:
    host: "app-server.company.com"
    port: 9999
    username: "${JMX_USERNAME}"
    password: "${JMX_PASSWORD}"
    ssl_enabled: true
    connection_timeout: 15
  
  health_endpoints:
    - url: "https://app-server.company.com:8443/actuator/health"
      timeout: 10
      verify_ssl: true
  
  thresholds:
    memory_percent: 85
    cpu_percent: 80
    gc_pause_ms: 1000
    response_time_ms: 5000

alerting:
  enabled: true
  channels:
    slack:
      enabled: true
      webhook_url: "${SLACK_WEBHOOK_URL}"
      channel: "#production-alerts"
    
    email:
      enabled: true
      smtp_host: "smtp.company.com"
      smtp_port: 587
      smtp_username: "${SMTP_USERNAME}"
      smtp_password: "${SMTP_PASSWORD}"
      recipients:
        critical: ["oncall@company.com", "management@company.com"]
        high: ["devops@company.com"]
    
    pagerduty:
      enabled: true
      integration_key: "${PAGERDUTY_INTEGRATION_KEY}"

security:
  api:
    enabled: true
    port: 8443
    ssl_enabled: true
    ssl_cert: "/etc/ssl/certs/crown-jewel-monitor.crt"
    ssl_key: "/etc/ssl/private/crown-jewel-monitor.key"
    
    authentication:
      type: "token"
      tokens:
        - token: "${API_TOKEN_ADMIN}"
          permissions: ["read", "write", "admin"]
        - token: "${API_TOKEN_READONLY}"
          permissions: ["read"]
```

#### Environment Variables
```bash
# Create environment file
sudo tee /etc/crown-jewel/environment << EOF
# Splunk Configuration
SPLUNK_AUTH_TOKEN=your-splunk-token-here

# JMX Configuration
JMX_USERNAME=monitoring_user
JMX_PASSWORD=secure_jmx_password

# Alert Configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
SMTP_USERNAME=alerts@company.com
SMTP_PASSWORD=secure_smtp_password
PAGERDUTY_INTEGRATION_KEY=your-pagerduty-key

# API Configuration
API_TOKEN_ADMIN=your-secure-admin-token-here
API_TOKEN_READONLY=your-readonly-token-here
EOF

# Secure environment file
sudo chmod 600 /etc/crown-jewel/environment
sudo chown crown-jewel:crown-jewel /etc/crown-jewel/environment
```

### 4. SSL/TLS Configuration

#### Generate SSL Certificates
```bash
# Option 1: Self-signed certificates (development/testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/crown-jewel-monitor.key \
  -out /etc/ssl/certs/crown-jewel-monitor.crt \
  -subj "/C=US/ST=State/L=City/O=Company/CN=crown-jewel-monitor.company.com"

# Option 2: Use Let's Encrypt (production)
sudo certbot certonly --standalone \
  -d crown-jewel-monitor.company.com \
  --cert-path /etc/ssl/certs/crown-jewel-monitor.crt \
  --key-path /etc/ssl/private/crown-jewel-monitor.key

# Set permissions
sudo chmod 644 /etc/ssl/certs/crown-jewel-monitor.crt
sudo chmod 600 /etc/ssl/private/crown-jewel-monitor.key
sudo chown crown-jewel:crown-jewel /etc/ssl/private/crown-jewel-monitor.key
```

## 🔧 Service Configuration

### 1. Systemd Service

#### Create Service File
```bash
sudo tee /etc/systemd/system/crown-jewel-monitor.service << EOF
[Unit]
Description=Crown Jewel Java Application Monitor
Documentation=https://github.com/company/crown-jewel-monitor
After=network.target
Wants=network.target

[Service]
Type=exec
User=crown-jewel
Group=crown-jewel
WorkingDirectory=/opt/crown-jewel-monitor
Environment=PYTHONPATH=/opt/crown-jewel-monitor
EnvironmentFile=/etc/crown-jewel/environment

ExecStartPre=/opt/crown-jewel-monitor/venv/bin/python -m crown_jewel_monitor.config.validate --config /etc/crown-jewel/production.yaml
ExecStart=/opt/crown-jewel-monitor/venv/bin/python -m crown_jewel_monitor.main --config /etc/crown-jewel/production.yaml
ExecReload=/bin/kill -HUP \$MAINPID

Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/crown-jewel /var/lib/crown-jewel /tmp

# Resource limits
MemoryLimit=4G
MemoryAccounting=true
CPUQuota=200%  # Allow up to 2 CPU cores

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=crown-jewel-monitor

[Install]
WantedBy=multi-user.target
EOF
```

#### Enable and Start Service
```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable crown-jewel-monitor

# Start the service
sudo systemctl start crown-jewel-monitor

# Check service status
sudo systemctl status crown-jewel-monitor

# View logs
sudo journalctl -u crown-jewel-monitor -f
```

### 2. Log Rotation

#### Configure Logrotate
```bash
sudo tee /etc/logrotate.d/crown-jewel-monitor << EOF
/var/log/crown-jewel/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 crown-jewel crown-jewel
    postrotate
        systemctl reload crown-jewel-monitor
    endscript
}
EOF
```

### 3. Monitoring Scripts

#### Health Check Script
```bash
sudo tee /usr/local/bin/crown-jewel-health-check << 'EOF'
#!/bin/bash

# Health check script for Crown Jewel Monitor
set -e

HEALTH_URL="http://localhost:8080/api/health"
TIMEOUT=30

echo "Checking Crown Jewel Monitor health..."

# Check if service is running
if ! systemctl is-active --quiet crown-jewel-monitor; then
    echo "ERROR: Crown Jewel Monitor service is not running"
    exit 1
fi

# Check API health endpoint
if command -v curl >/dev/null 2>&1; then
    response=$(curl -s --max-time $TIMEOUT "$HEALTH_URL" || echo "")
    if [[ $response == *'"status":"healthy"'* ]]; then
        echo "OK: Crown Jewel Monitor is healthy"
        exit 0
    else
        echo "ERROR: Health check failed - $response"
        exit 1
    fi
else
    echo "WARNING: curl not available, skipping API health check"
fi

echo "OK: Service is running"
EOF

chmod +x /usr/local/bin/crown-jewel-health-check
```

#### Backup Script
```bash
sudo tee /usr/local/bin/crown-jewel-backup << 'EOF'
#!/bin/bash

# Backup script for Crown Jewel Monitor
set -e

BACKUP_DIR="/var/backups/crown-jewel"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="crown-jewel-backup-$DATE.tar.gz"

echo "Creating backup: $BACKUP_FILE"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    -C /etc/crown-jewel config.yaml production.yaml environment \
    -C /var/lib/crown-jewel . \
    --exclude='*.tmp' --exclude='*.pid'

# Keep only last 7 backups
find "$BACKUP_DIR" -name "crown-jewel-backup-*.tar.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_DIR/$BACKUP_FILE"
EOF

chmod +x /usr/local/bin/crown-jewel-backup
```

## 🔍 Monitoring and Observability

### 1. Prometheus Integration

#### Enable Metrics Export
```yaml
# Add to production.yaml
global:
  self_monitoring:
    enabled: true
    metrics_export_port: 9090
    health_check_interval: 30
```

#### Prometheus Configuration
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'crown-jewel-monitor'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 30s
    metrics_path: /metrics
```

### 2. Log Monitoring

#### Configure Rsyslog
```bash
sudo tee /etc/rsyslog.d/10-crown-jewel.conf << EOF
# Crown Jewel Monitor logs
if \$programname == 'crown-jewel-monitor' then /var/log/crown-jewel/crown-jewel-monitor.log
& stop
EOF

sudo systemctl restart rsyslog
```

### 3. External Monitoring

#### Nagios/Icinga Check
```bash
sudo tee /usr/lib/nagios/plugins/check_crown_jewel << 'EOF'
#!/bin/bash

# Nagios plugin for Crown Jewel Monitor
/usr/local/bin/crown-jewel-health-check

case $? in
    0) echo "OK - Crown Jewel Monitor is healthy"; exit 0;;
    1) echo "CRITICAL - Crown Jewel Monitor is unhealthy"; exit 2;;
    *) echo "UNKNOWN - Unable to determine status"; exit 3;;
esac
EOF

chmod +x /usr/lib/nagios/plugins/check_crown_jewel
```

## 🔐 Security Hardening

### 1. Firewall Configuration

#### UFW (Ubuntu)
```bash
sudo ufw allow from 10.0.0.0/8 to any port 8080 comment "Crown Jewel API"
sudo ufw allow from 10.0.0.0/8 to any port 8443 comment "Crown Jewel HTTPS API"
sudo ufw allow from monitoring-server to any port 9090 comment "Prometheus metrics"
```

#### Firewalld (RHEL/CentOS)
```bash
sudo firewall-cmd --permanent --add-rich-rule="rule family="ipv4" source address="10.0.0.0/8" port protocol="tcp" port="8080" accept"
sudo firewall-cmd --permanent --add-rich-rule="rule family="ipv4" source address="10.0.0.0/8" port protocol="tcp" port="8443" accept"
sudo firewall-cmd --reload
```

### 2. SELinux Configuration (RHEL/CentOS)

```bash
# Create SELinux policy for Crown Jewel Monitor
sudo setsebool -P httpd_can_network_connect 1
sudo semanage port -a -t http_port_t -p tcp 8080
sudo semanage port -a -t http_port_t -p tcp 8443

# Set file contexts
sudo semanage fcontext -a -t admin_home_t "/opt/crown-jewel-monitor(/.*)?"
sudo semanage fcontext -a -t var_log_t "/var/log/crown-jewel(/.*)?"
sudo restorecon -R /opt/crown-jewel-monitor /var/log/crown-jewel
```

### 3. File Permissions

```bash
# Secure configuration files
sudo chmod 600 /etc/crown-jewel/production.yaml
sudo chmod 600 /etc/crown-jewel/environment

# Secure data directories
sudo chmod 750 /var/lib/crown-jewel
sudo chmod 750 /var/log/crown-jewel

# Secure application directory
sudo chmod 755 /opt/crown-jewel-monitor
sudo chmod -R 644 /opt/crown-jewel-monitor/config/
sudo chmod 755 /opt/crown-jewel-monitor/config/
```

## 🔄 Maintenance and Updates

### 1. Update Procedure

#### Create Update Script
```bash
sudo tee /usr/local/bin/crown-jewel-update << 'EOF'
#!/bin/bash

# Update script for Crown Jewel Monitor
set -e

echo "Starting Crown Jewel Monitor update..."

# Backup current installation
/usr/local/bin/crown-jewel-backup

# Stop service
systemctl stop crown-jewel-monitor

# Switch to service user
sudo -u crown-jewel bash << 'USEREOF'
cd /opt/crown-jewel-monitor

# Backup virtual environment
cp -r venv venv.backup

# Update code
git fetch origin
git checkout main
git pull origin main

# Update dependencies
source venv/bin/activate
pip install --upgrade -r requirements.txt

# Run tests
python -m pytest tests/ --tb=short

echo "Update completed successfully"
USEREOF

# Validate configuration
sudo -u crown-jewel /opt/crown-jewel-monitor/venv/bin/python \
    -m crown_jewel_monitor.config.validate \
    --config /etc/crown-jewel/production.yaml

# Start service
systemctl start crown-jewel-monitor

# Verify service is healthy
sleep 10
/usr/local/bin/crown-jewel-health-check

echo "Crown Jewel Monitor update completed successfully"
EOF

chmod +x /usr/local/bin/crown-jewel-update
```

### 2. Rollback Procedure

```bash
sudo tee /usr/local/bin/crown-jewel-rollback << 'EOF'
#!/bin/bash

# Rollback script for Crown Jewel Monitor
set -e

echo "Starting Crown Jewel Monitor rollback..."

# Stop service
systemctl stop crown-jewel-monitor

# Switch to service user
sudo -u crown-jewel bash << 'USEREOF'
cd /opt/crown-jewel-monitor

# Restore from backup
if [ -d "venv.backup" ]; then
    rm -rf venv
    mv venv.backup venv
    echo "Virtual environment restored from backup"
fi

# Rollback to previous commit
git reset --hard HEAD~1

echo "Rollback completed"
USEREOF

# Start service
systemctl start crown-jewel-monitor

# Verify service is healthy
sleep 10
/usr/local/bin/crown-jewel-health-check

echo "Crown Jewel Monitor rollback completed successfully"
EOF

chmod +x /usr/local/bin/crown-jewel-rollback
```

### 3. Scheduled Maintenance

#### Add to Crontab
```bash
sudo tee -a /etc/crontab << EOF
# Crown Jewel Monitor maintenance tasks
0 2 * * 0    crown-jewel    /usr/local/bin/crown-jewel-backup    # Weekly backup
0 3 * * *    crown-jewel    find /var/lib/crown-jewel/data -mtime +7 -delete    # Clean old data
*/5 * * * *  crown-jewel    /usr/local/bin/crown-jewel-health-check || systemctl restart crown-jewel-monitor    # Health check and auto-restart
EOF
```

## 📊 Performance Tuning

### 1. System Optimization

```bash
# Increase file descriptor limits
echo "crown-jewel soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "crown-jewel hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network settings
echo "net.core.somaxconn = 1024" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_tw_reuse = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 2. Application Tuning

```yaml
# Optimize configuration for high-volume environments
global:
  max_concurrent_agents: 10
  monitoring_interval: 30
  
  # Connection pooling
  connection_pool_size: 20
  async_timeout: 45

splunk:
  connection_pool:
    max_connections: 15
    connection_timeout: 45
    retry_attempts: 3
  
  search_optimization:
    parallel_searches: true
    batch_size: 200
    use_cache: true
    cache_ttl_minutes: 10
```

## 🚨 Troubleshooting

### Common Deployment Issues

#### Service Won't Start
```bash
# Check service status and logs
sudo systemctl status crown-jewel-monitor
sudo journalctl -u crown-jewel-monitor --since "1 hour ago"

# Check configuration
sudo -u crown-jewel /opt/crown-jewel-monitor/venv/bin/python \
    -m crown_jewel_monitor.config.validate \
    --config /etc/crown-jewel/production.yaml

# Check permissions
ls -la /etc/crown-jewel/
ls -la /var/log/crown-jewel/
ls -la /var/lib/crown-jewel/
```

#### Performance Issues
```bash
# Monitor resource usage
htop
iostat 1
netstat -tulpn | grep python

# Check for memory leaks
ps aux | grep crown-jewel
pmap $(pgrep -f crown-jewel-monitor)

# Monitor disk usage
df -h
du -sh /var/lib/crown-jewel/*
```

#### Network Connectivity
```bash
# Test external connections
curl -v https://splunk-server:8089/services/auth/login
telnet java-app-server 9999
nmap -p 8080,8443,9090 localhost
```

---

This deployment guide provides comprehensive instructions for production deployment of the Crown Jewel Monitor. For additional support, refer to the [Troubleshooting Guide](TROUBLESHOOTING.md) or contact the development team.