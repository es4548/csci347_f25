# Week 7 Homework Hints: Security Monitoring with SIEM

## 🎯 Quick Start Guide (5 hours total)

### Time Breakdown
- **Splunk Setup & Log Import**: 1 hour
- **Search Queries & Analysis**: 2 hours
- **Dashboard Creation**: 1.5 hours
- **Alert Rules Configuration**: 30 minutes

## 📋 Step-by-Step Implementation

### Step 1: Understanding SIEM with Splunk (30 minutes)

**Assignment Focus:**
- **Use Splunk Free** (not build custom SIEM)
- **Analyze provided log files** (not collect live logs)
- **Create SPL search queries** for security events
- **Build dashboards** showing security metrics
- **Configure alerts** for common attacks

**Key Splunk Concepts:**
- **Search Processing Language (SPL)**: Splunk's query language
- **Indexes**: Where log data is stored
- **Source Types**: Log format definitions
- **Dashboards**: Visual representations of data
- **Alerts**: Automated notifications based on searches

### Step 2: Splunk Setup (30 minutes)

**Assignment Requirement**: Download Splunk Free (500MB/day limit)

```bash
# Download Splunk Free from splunk.com
# Install and start Splunk
# Access web interface at http://localhost:8000

mkdir week07-splunk-analysis
cd week07-splunk-analysis
mkdir sample_logs screenshots

# Create sample log files for import
touch splunk_queries.txt
touch dashboard_config.xml
touch alert_rules.txt
touch incident_report.md
```

### Step 3: Sample Log Data Generation (30 minutes)

**Assignment Requirement**: Use provided sample logs for Splunk analysis

```python
# generate_sample_logs.py - Create realistic log files for Splunk import

def generate_sample_logs():
    """Generate sample log files that mimic the provided assignment data"""

    # Web server logs with attacks
    web_server_logs = [
        '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /login.php" 200 1234',
        '192.168.1.100 - - [15/Jan/2024:10:30:46 +0000] "POST /login.php" 401 89',
        '192.168.1.100 - - [15/Jan/2024:10:30:47 +0000] "POST /login.php" 401 89',
        '192.168.1.100 - - [15/Jan/2024:10:30:48 +0000] "POST /login.php" 401 89',
        '192.168.1.100 - - [15/Jan/2024:10:30:49 +0000] "POST /login.php" 401 89',
        '192.168.1.100 - - [15/Jan/2024:10:30:50 +0000] "POST /login.php" 200 567',  # Success after attempts
        '10.0.0.50 - - [15/Jan/2024:10:31:00 +0000] "GET /admin.php" 403 567',
        '10.0.0.50 - - [15/Jan/2024:10:31:15 +0000] "GET /../../etc/passwd" 404 0',  # Directory traversal
        '10.0.0.50 - - [15/Jan/2024:10:31:16 +0000] "GET /../../../etc/shadow" 404 0',
        '172.16.0.25 - - [15/Jan/2024:10:31:30 +0000] "GET /admin/config.php" 404 0',
        '172.16.0.25 - - [15/Jan/2024:10:31:31 +0000] "GET /wp-admin/" 404 0',
        '172.16.0.25 - - [15/Jan/2024:10:31:32 +0000] "GET /phpmyadmin/" 404 0',
        '203.0.113.50 - - [15/Jan/2024:10:32:00 +0000] "GET /login.php?user=admin\\' OR 1=1--" 200 89',  # SQL injection
        '203.0.113.50 - - [15/Jan/2024:10:32:01 +0000] "POST /search.php" 200 15678',  # Large response (data exfil)
        '192.168.1.200 - - [15/Jan/2024:10:33:00 +0000] "GET /index.php" 200 2345',  # Normal traffic
        '192.168.1.201 - - [15/Jan/2024:10:33:30 +0000] "GET /contact.php" 200 1890'
    ]

    # Authentication logs with brute force
    auth_logs = [
        'Jan 15 10:30:45 webserver sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2',
        'Jan 15 10:30:47 webserver sshd[1235]: Failed password for admin from 192.168.1.100 port 22 ssh2',
        'Jan 15 10:30:49 webserver sshd[1236]: Failed password for admin from 192.168.1.100 port 22 ssh2',
        'Jan 15 10:30:51 webserver sshd[1237]: Failed password for admin from 192.168.1.100 port 22 ssh2',
        'Jan 15 10:30:53 webserver sshd[1238]: Failed password for admin from 192.168.1.100 port 22 ssh2',
        'Jan 15 10:30:55 webserver sshd[1239]: Accepted password for admin from 192.168.1.100 port 22 ssh2',
        'Jan 15 10:31:15 database mysqld[5678]: Access denied for user "root"@"10.0.0.50" (using password: YES)',
        'Jan 15 10:31:16 database mysqld[5679]: Access denied for user "admin"@"10.0.0.50" (using password: YES)',
        'Jan 15 10:31:17 database mysqld[5680]: Access denied for user "sa"@"10.0.0.50" (using password: YES)',
        'Jan 15 10:31:18 database mysqld[5681]: Access denied for user "test"@"10.0.0.50" (using password: YES)',
        'Jan 15 10:33:45 fileserver smbd[1111]: Failed authentication for user admin from 172.16.0.25',
        'Jan 15 10:34:00 webserver sudo[9999]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow',  # Privilege escalation
        'Jan 15 10:35:15 webserver login[2222]: FAILED LOGIN (3) on tty1 FOR root, User unknown',
        'Jan 15 10:36:30 webserver su[3333]: FAILED su for root by admin'
    ]

    # Network logs with scanning activity
    network_logs = [
        'Jan 15 10:30:40 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.10 PROTO=TCP DPT=22',
        'Jan 15 10:30:41 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.10 PROTO=TCP DPT=23',
        'Jan 15 10:30:42 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.10 PROTO=TCP DPT=80',
        'Jan 15 10:30:43 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.10 PROTO=TCP DPT=443',
        'Jan 15 10:30:44 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.10 PROTO=TCP DPT=3389',
        'Jan 15 10:30:45 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.10 PROTO=TCP DPT=135',
        'Jan 15 10:30:46 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.10 PROTO=TCP DPT=139',
        'Jan 15 10:30:47 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=192.168.1.10 PROTO=TCP DPT=445',
        'Jan 15 10:31:00 firewall kernel: [UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.200 DST=172.16.0.10 PROTO=TCP DPT=80',
        'Jan 15 10:31:15 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=10.0.0.50 DST=192.168.1.1 PROTO=ICMP TYPE=8',
        'Jan 15 10:32:00 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.25 DST=192.168.1.5 PROTO=TCP DPT=1433',  # SQL Server
        'Jan 15 10:32:30 firewall kernel: [UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.150 DST=172.16.0.5 PROTO=TCP DPT=443'
    ]

    # System logs with privilege escalation
    system_logs = [
        'Jan 15 10:34:00 webserver sudo[9999]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow',
        'Jan 15 10:34:15 webserver sudo[10001]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/passwd',
        'Jan 15 10:34:30 webserver kernel: audit: type=1400 audit(1673781270.123:456): avc: denied { read } for pid=10002 comm="cat" name="shadow" dev="dm-0" ino=123456',
        'Jan 15 10:35:00 webserver crontab[10003]: (admin) LIST (admin)',
        'Jan 15 10:35:15 webserver usermod[10004]: change user `admin` password',
        'Jan 15 10:35:30 webserver groupadd[10005]: group added to /etc/group: name=hackers, GID=1001',
        'Jan 15 10:35:45 webserver useradd[10006]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor',
        'Jan 15 10:36:00 webserver su[10007]: Successful su for root by admin',
        'Jan 15 10:36:15 webserver systemd[1]: Started malicious.service',  # Suspicious service
        'Jan 15 10:36:30 webserver kernel: Process /tmp/malware.sh executed'
    ]

    # Create log files
    import os
    os.makedirs('sample_logs', exist_ok=True)

    with open('sample_logs/webserver.log', 'w') as f:
        f.write('\n'.join(web_server_logs))

    with open('sample_logs/auth.log', 'w') as f:
        f.write('\n'.join(auth_logs))

    with open('sample_logs/firewall.log', 'w') as f:
        f.write('\n'.join(network_logs))

    with open('sample_logs/system.log', 'w') as f:
        f.write('\n'.join(system_logs))

    print("✅ Generated sample log files:")
    print("   - sample_logs/webserver.log (web attacks)")
    print("   - sample_logs/auth.log (brute force)")
    print("   - sample_logs/firewall.log (port scanning)")
    print("   - sample_logs/system.log (privilege escalation)")

if __name__ == "__main__":
    generate_sample_logs()
```

### Step 4: Splunk Search Queries for Security Analysis (2 hours)

**Assignment Requirement**: Create SPL search queries for security events

# Essential Splunk SPL Queries for Security Analysis

def generate_splunk_queries():
    """Generate SPL search queries for common security analysis tasks"""

    queries = []

    # Basic log analysis queries
    queries.append("# Basic Log Analysis Queries")
    queries.append("")

    # 1. Failed login attempts
    queries.append("# 1. Failed Login Attempts (Brute Force Detection)")
    queries.append('index=main sourcetype=auth "Failed password" | stats count by src_ip | where count > 5 | sort -count')
    queries.append("")

    # 2. Successful logins after failed attempts
    queries.append("# 2. Successful Login After Multiple Failures")
    queries.append('index=main sourcetype=auth | eval login_status=if(searchmatch("Failed password"), "failed", "success") | stats count by src_ip, login_status | where count > 1')
    queries.append("")

    # 3. Web application errors
    queries.append("# 3. HTTP Error Codes Analysis")
    queries.append('index=main sourcetype=access_combined status>=400 | stats count by clientip, status | where count > 10 | sort -count')
    queries.append("")

    # 4. SQL injection attempts
    queries.append("# 4. SQL Injection Detection")
    queries.append('index=main sourcetype=access_combined (uri="*union*select*" OR uri="*or*1=1*" OR uri="*drop*table*") | table _time, clientip, uri, status')
    queries.append("")

    # 5. Directory traversal attempts
    queries.append("# 5. Directory Traversal Attempts")
    queries.append('index=main sourcetype=access_combined (uri="*../*" OR uri="*../etc/passwd*") | table _time, clientip, uri, status')
    queries.append("")

    # Advanced correlation queries
    queries.append("# Advanced Correlation Queries")
    queries.append("")

    # 6. Port scanning detection
    queries.append("# 6. Port Scanning Detection")
    queries.append('index=main sourcetype=firewall action=BLOCK | stats dc(dest_port) as unique_ports by src_ip | where unique_ports > 5 | sort -unique_ports')
    queries.append("")

    # 7. Privilege escalation detection
    queries.append("# 7. Privilege Escalation Detection")
    queries.append('index=main sourcetype=syslog ("sudo" OR "su root" OR "/etc/passwd" OR "/etc/shadow") | table _time, host, message')
    queries.append("")

    # 8. Data exfiltration indicators
    queries.append("# 8. Data Exfiltration Indicators")
    queries.append('index=main sourcetype=access_combined bytes>1000000 | stats sum(bytes) as total_bytes by clientip | where total_bytes > 10000000 | sort -total_bytes')
    queries.append("")

    # 9. Suspicious user accounts
    queries.append("# 9. Suspicious User Account Activity")
    queries.append('index=main sourcetype=syslog ("useradd" OR "usermod" OR "groupadd") | table _time, host, message')
    queries.append("")

    # 10. Malware indicators
    queries.append("# 10. Malware Execution Indicators")
    queries.append('index=main sourcetype=syslog ("/tmp/*" OR "malware" OR "backdoor" OR ".sh executed") | table _time, host, message')
    queries.append("")

    # Time-based analysis
    queries.append("# Time-Based Analysis Queries")
    queries.append("")

    # 11. Events by hour of day
    queries.append("# 11. Security Events by Hour of Day")
    queries.append('index=main | eval hour=strftime(_time, "%H") | stats count by hour | sort hour')
    queries.append("")

    # 12. Weekend activity anomalies
    queries.append("# 12. Weekend Activity Anomalies")
    queries.append('index=main | eval weekday=strftime(_time, "%A") | where weekday="Saturday" OR weekday="Sunday" | stats count by weekday, sourcetype')
    queries.append("")

    # Dashboard queries
    queries.append("# Dashboard Visualization Queries")
    queries.append("")

    # 13. Top attacking IPs
    queries.append("# 13. Top Attacking IP Addresses")
    queries.append('index=main (sourcetype=auth "Failed password" OR sourcetype=firewall action=BLOCK) | stats count by src_ip | head 10 | sort -count')
    queries.append("")

    # 14. Attack timeline
    queries.append("# 14. Attack Timeline Visualization")
    queries.append('index=main (sourcetype=auth "Failed password" OR sourcetype=access_combined status>=400) | timechart span=1h count by sourcetype')
    queries.append("")

    # 15. Geographic analysis (if GeoIP enabled)
    queries.append("# 15. Geographic Analysis of Attacks")
    queries.append('index=main sourcetype=auth "Failed password" | iplocation clientip | stats count by Country | head 10 | sort -count')
    queries.append("")

    return queries

def save_splunk_queries():
    """Save SPL queries to file for assignment submission"""
    queries = generate_splunk_queries()

    with open('splunk_queries.txt', 'w') as f:
        f.write("# Week 7 Assignment: Splunk Security Analysis Queries\n")
        f.write("# Generated SPL searches for detecting common attacks\n\n")

        for query in queries:
            f.write(query + '\n')

    print("✅ Splunk queries saved to splunk_queries.txt")

    # Also create a summary of query purposes
    with open('query_explanations.md', 'w') as f:
        f.write("# Splunk Query Explanations\n\n")
        f.write("## Purpose of Each Query\n\n")
        f.write("1. **Failed Login Attempts**: Detects brute force attacks by counting failed SSH logins per IP\n")
        f.write("2. **Successful After Failures**: Identifies potentially successful brute force attacks\n")
        f.write("3. **HTTP Error Analysis**: Finds web application scanning/attack attempts\n")
        f.write("4. **SQL Injection Detection**: Searches for common SQL injection patterns in URLs\n")
        f.write("5. **Directory Traversal**: Detects path traversal attack attempts\n")
        f.write("6. **Port Scanning**: Identifies IPs scanning multiple ports\n")
        f.write("7. **Privilege Escalation**: Detects attempts to gain elevated privileges\n")
        f.write("8. **Data Exfiltration**: Finds large data transfers that may indicate data theft\n")
        f.write("9. **Suspicious Accounts**: Monitors for unauthorized user account creation\n")
        f.write("10. **Malware Indicators**: Searches for signs of malware execution\n")
        f.write("11. **Hourly Patterns**: Analyzes when attacks typically occur\n")
        f.write("12. **Weekend Anomalies**: Detects unusual weekend activity\n")
        f.write("13. **Top Attackers**: Identifies most active attacking IP addresses\n")
        f.write("14. **Attack Timeline**: Visualizes attack patterns over time\n")
        f.write("15. **Geographic Analysis**: Maps attacks by country of origin\n\n")

        f.write("## How to Use These Queries\n\n")
        f.write("1. **Import sample logs** into Splunk first\n")
        f.write("2. **Set correct source types** (auth, access_combined, firewall, syslog)\n")
        f.write("3. **Adjust time ranges** using Splunk's time picker\n")
        f.write("4. **Modify field names** if your logs use different field names\n")
        f.write("5. **Save searches** for regular monitoring\n")
        f.write("6. **Create alerts** from searches that find threats\n")

    print("✅ Query explanations saved to query_explanations.md")

if __name__ == "__main__":
    save_splunk_queries()
```

### Step 5: Splunk Dashboard Creation (1.5 hours)

**Assignment Requirement**: Build security dashboards in Splunk

```xml
<!-- dashboard_config.xml - Splunk Dashboard Configuration -->
<!-- Save this as a Simple XML dashboard in Splunk -->

<dashboard>
  <label>Security Monitoring Dashboard</label>
  <description>Real-time security event monitoring and analysis</description>

  <row>
    <panel>
      <title>Failed Login Attempts</title>
      <chart>
        <search>
          <query>
index=main sourcetype=auth "Failed password"
| timechart span=1h count by src_ip
| head 5
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>

    <panel>
      <title>Top Attacking IPs</title>
      <table>
        <search>
          <query>
index=main (sourcetype=auth "Failed password" OR sourcetype=firewall action=BLOCK)
| stats count by src_ip
| head 10
| sort -count
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Suspicious Network Connections</title>
      <chart>
        <search>
          <query>
index=main sourcetype=firewall action=BLOCK
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 3
| sort -unique_ports
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.axisY.scale">linear</option>
      </chart>
    </panel>

    <panel>
      <title>Web Attack Patterns</title>
      <chart>
        <search>
          <query>
index=main sourcetype=access_combined status>=400
| stats count by status
| sort -count
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>File Integrity Violations</title>
      <table>
        <search>
          <query>
index=main sourcetype=syslog ("/etc/passwd" OR "/etc/shadow" OR "sudo" OR "su root")
| table _time, host, message
| head 20
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>

    <panel>
      <title>User Behavior Anomalies</title>
      <table>
        <search>
          <query>
index=main sourcetype=syslog ("useradd" OR "usermod" OR "groupadd")
| rex field=message "(?&lt;action&gt;useradd|usermod|groupadd)\s+.*?(?&lt;target&gt;\w+)"
| stats count by action, target
| head 10
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
      </table>
    </panel>
  </row>

  <row>
    <panel>
      <title>Security Events Timeline</title>
      <chart>
        <search>
          <query>
index=main (sourcetype=auth "Failed password" OR sourcetype=access_combined status>=400 OR sourcetype=firewall action=BLOCK)
| timechart span=1h count by sourcetype
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="charting.chart">area</option>
        <option name="charting.chart.stackMode">stacked</option>
        <option name="charting.axisY.scale">linear</option>
        <option name="charting.legend.placement">bottom</option>
      </chart>
    </panel>
  </row>
</dashboard>
```

### Step 6: Alert Rules Configuration (30 minutes)

**Assignment Requirement**: Create alerts for common attacks

```python
# generate_alert_rules.py - Create Splunk alert configurations

def generate_alert_rules():
    """Generate Splunk alert rule configurations"""

    alerts = []

    # Alert 1: Brute Force Attack
    alerts.append({
        "name": "SSH Brute Force Attack",
        "description": "Multiple failed SSH login attempts from same IP",
        "search": 'index=main sourcetype=auth "Failed password" | stats count by src_ip | where count > 5',
        "time_range": "15m",
        "cron_schedule": "*/5 * * * *",  # Every 5 minutes
        "trigger_condition": "number of events > 0",
        "severity": "HIGH",
        "actions": [
            "Send email to security team",
            "Create incident in SOAR platform",
            "Block IP in firewall (if automated response enabled)"
        ]
    })

    # Alert 2: Privilege Escalation
    alerts.append({
        "name": "Privilege Escalation Attempt",
        "description": "Unauthorized privilege escalation detected",
        "search": 'index=main sourcetype=syslog ("sudo" AND ("/etc/passwd" OR "/etc/shadow")) | stats count',
        "time_range": "10m",
        "cron_schedule": "*/5 * * * *",
        "trigger_condition": "number of events > 0",
        "severity": "CRITICAL",
        "actions": [
            "Immediate email alert",
            "Page security on-call",
            "Create high-priority incident"
        ]
    })

    # Alert 3: Data Exfiltration
    alerts.append({
        "name": "Potential Data Exfiltration",
        "description": "Large data transfer detected",
        "search": 'index=main sourcetype=access_combined | stats sum(bytes) as total_bytes by clientip | where total_bytes > 100000000',
        "time_range": "30m",
        "cron_schedule": "*/15 * * * *",  # Every 15 minutes
        "trigger_condition": "number of events > 0",
        "severity": "HIGH",
        "actions": [
            "Send email alert",
            "Review data access logs",
            "Check for unauthorized file access"
        ]
    })

    # Alert 4: Malware Indicators
    alerts.append({
        "name": "Malware Execution Detected",
        "description": "Potential malware execution indicators",
        "search": 'index=main sourcetype=syslog ("/tmp/" AND (".sh" OR "malware" OR "backdoor"))',
        "time_range": "5m",
        "cron_schedule": "*/2 * * * *",  # Every 2 minutes
        "trigger_condition": "number of events > 0",
        "severity": "CRITICAL",
        "actions": [
            "Immediate alert",
            "Isolate affected system",
            "Start incident response procedure"
        ]
    })

    # Alert 5: Port Scanning
    alerts.append({
        "name": "Port Scanning Activity",
        "description": "Port scanning detected from external IP",
        "search": 'index=main sourcetype=firewall action=BLOCK | stats dc(dest_port) as unique_ports by src_ip | where unique_ports > 10',
        "time_range": "10m",
        "cron_schedule": "*/5 * * * *",
        "trigger_condition": "number of events > 0",
        "severity": "MEDIUM",
        "actions": [
            "Log to security database",
            "Add to threat intelligence",
            "Consider IP blocking"
        ]
    })

    # Alert 6: SQL Injection Attempts
    alerts.append({
        "name": "SQL Injection Attack",
        "description": "SQL injection patterns detected in web requests",
        "search": 'index=main sourcetype=access_combined (uri="*union*select*" OR uri="*or*1=1*" OR uri="*drop*table*")',
        "time_range": "5m",
        "cron_schedule": "*/3 * * * *",  # Every 3 minutes
        "trigger_condition": "number of events > 0",
        "severity": "HIGH",
        "actions": [
            "Block source IP in WAF",
            "Review application logs",
            "Check for successful injections"
        ]
    })

    return alerts

def save_alert_rules():
    """Save alert rules to configuration file"""
    alerts = generate_alert_rules()

    # Save as text format for assignment submission
    with open('alert_rules.txt', 'w') as f:
        f.write("# Week 7 Assignment: Splunk Alert Rules Configuration\n")
        f.write("# Security monitoring alerts for common attack patterns\n\n")

        for i, alert in enumerate(alerts, 1):
            f.write(f"## Alert {i}: {alert['name']}\n")
            f.write(f"**Description**: {alert['description']}\n")
            f.write(f"**Severity**: {alert['severity']}\n")
            f.write(f"**Search Query**: {alert['search']}\n")
            f.write(f"**Time Range**: Last {alert['time_range']}\n")
            f.write(f"**Schedule**: {alert['cron_schedule']}\n")
            f.write(f"**Trigger**: {alert['trigger_condition']}\n")
            f.write("**Actions**:\n")
            for action in alert['actions']:
                f.write(f"  - {action}\n")
            f.write("\n")

    print("✅ Alert rules saved to alert_rules.txt")

    # Save as Splunk-compatible format (simplified)
    with open('splunk_alerts_config.txt', 'w') as f:
        f.write("# Splunk Alert Configuration Commands\n")
        f.write("# Use these in Splunk Web UI or via REST API\n\n")

        for alert in alerts:
            f.write(f"# Create alert: {alert['name']}\n")
            f.write(f"# Search: {alert['search']}\n")
            f.write(f"# Schedule: {alert['cron_schedule']}\n")
            f.write(f"# Time range: -{alert['time_range']}\n")
            f.write(f"# Severity: {alert['severity']}\n")
            f.write("\n")

    print("✅ Splunk alert configuration saved to splunk_alerts_config.txt")

if __name__ == "__main__":
    save_alert_rules()
```

## 🐛 Common Issues & Solutions

### Issue: Splunk not indexing log files
**Solution**: Check source type configuration and file permissions

### Issue: SPL queries returning no results
**Solution**: Verify index name, source type, and time range settings

### Issue: Dashboard panels not loading
**Solution**: Check XML syntax and ensure searches are properly formatted

### Issue: Alert not triggering
**Solution**: Test search manually first, verify cron schedule format

## ✅ Testing Workflow (Assignment Requirements)

```bash
# 1. Generate sample log files
python generate_sample_logs.py

# 2. Import logs into Splunk
# Use Splunk Web UI: Settings > Add Data > Upload files

# 3. Test SPL queries
python -c "
from Step4_code import save_splunk_queries
save_splunk_queries()
"

# 4. Create dashboard configuration
# Copy dashboard_config.xml into Splunk dashboards

# 5. Configure alerts
python -c "
from Step6_code import save_alert_rules
save_alert_rules()
"

# 6. Create incident report
# Analyze detected incidents and document findings
```

## 📁 Expected File Structure (Assignment Requirements)
```
week07-splunk-analysis/
├── generate_sample_logs.py      # Sample log generator
├── splunk_queries.txt           # Your search queries
├── dashboard_config.xml         # Dashboard configuration
├── alert_rules.txt              # Alert configurations
├── incident_report.md           # Analysis of detected incidents
├── screenshots/                 # Dashboard and alert evidence
│   ├── dashboard_screenshot.png
│   ├── alert_example.png
│   └── search_results.png
├── sample_logs/                 # Generated sample logs
│   ├── webserver.log
│   ├── auth.log
│   ├── firewall.log
│   └── system.log
└── query_explanations.md        # Query documentation
```

## 🎯 Grading Focus Areas (from assignment)

1. **Log Analysis (10 points)**: Import logs, create search queries, identify attack patterns, build correlation rules
2. **Dashboard Creation (8 points)**: Show failed logins, suspicious connections, file integrity violations, user behavior anomalies
3. **Alert Rules (7 points)**: Detect brute force, privilege escalation, data exfiltration, malware indicators

## 💡 Pro Tips

1. **Start with Splunk Free**: Download and install before attempting assignment
2. **Import Sample Data**: Use provided logs or generate realistic test data
3. **Learn SPL Basics**: Master search, stats, timechart, and eval commands
4. **Test Queries First**: Verify searches work before building dashboards
5. **Take Screenshots**: Document your work for assignment submission

## 🔍 Key SIEM Concepts (Assignment Learning Objectives)

### Splunk SIEM Fundamentals:
- **Search Processing Language (SPL)**: Splunk's query language
- **Indexes**: Where log data is stored and searched
- **Source Types**: Define how logs are parsed and field-extracted
- **Dashboards**: Visual representation of security metrics
- **Alerts**: Automated detection and notification system

### SOC Operations:
- **Log Aggregation**: Centralized collection from multiple sources
- **Event Correlation**: Finding relationships between security events
- **Threat Detection**: Identifying malicious activity patterns
- **Incident Response**: Alerting and escalation procedures

## 🚀 Extension Ideas (Optional)

- Add GeoIP lookups for geographic analysis
- Create custom field extractions for better parsing
- Build executive summary dashboards
- Integrate with external threat intelligence feeds

## ⏱️ Time Management

- **Set up Splunk first**: Installation and basic configuration (1 hour)
- **Import and explore data**: Get familiar with logs (30 minutes)
- **Build core searches**: Focus on assignment requirements (90 minutes)
- **Create dashboards**: Use proven SPL queries (90 minutes)
- **Configure alerts**: Set up automated detection (30 minutes)

## 🔧 Debugging Helpers

**Test basic Splunk functionality:**
```spl
index=main | head 10
```

**Check source type configuration:**
```spl
| metadata type=sourcetypes index=main
```

**Test field extraction:**
```spl
index=main sourcetype=auth | eval has_src_ip=if(isnull(src_ip), "No", "Yes") | stats count by has_src_ip
```

## 📊 Sample Incident Report Structure

```markdown
# Incident Analysis Report

## Executive Summary
Overview of security incidents detected during the monitoring period.

## Detected Incidents

### 1. SSH Brute Force Attack
- **Source IP**: 192.168.1.100
- **Target**: webserver
- **Timeline**: 10:30:45 - 10:30:55
- **Details**: 5 failed login attempts followed by successful login
- **Response**: IP blocked, account password reset

### 2. Privilege Escalation Attempt
- **User**: admin
- **Target Files**: /etc/shadow, /etc/passwd
- **Timeline**: 10:34:00 - 10:34:15
- **Details**: Unauthorized sudo access to sensitive files
- **Response**: Account suspended, incident escalated

## Attack Pattern Analysis
- Most attacks occurred during business hours
- External IPs showing reconnaissance behavior
- Successful brute force led to privilege escalation

## Recommendations
1. Implement fail2ban for SSH protection
2. Require MFA for administrative accounts
3. Monitor sudo activity more closely
4. Regular security awareness training
```

Remember: This assignment teaches practical SIEM skills used in Security Operations Centers. Focus on learning Splunk's SPL language and building effective security monitoring dashboards!