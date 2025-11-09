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