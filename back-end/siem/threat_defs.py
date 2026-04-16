"""
Centralized threat definitions and detection signatures for OrionGD/AegisNet-IDS.
Used by both the Threat Simulation Engine and the Rule Generator.
"""

# Attack Categories
RECONNAISSANCE = "reconnaissance"
DOS = "denial_of_service"
EXFILTRATION = "exfiltration"
C2_BEACONING = "c2_beaconing"
WEB_ATTACK = "web_attack"

# Threat Signatures (Common patterns)
SIGNATURES = {
    WEB_ATTACK: {
        "sqli": [
            "SELECT * FROM",
            "UNION SELECT",
            "OR '1'='1'",
            "SLEEP(",
            "BENCHMARK(",
            "group_concat"
        ],
        "xss": [
            "<script>",
            "alert(",
            "onerror=",
            "javascript:",
            "document.cookie"
        ],
        "path_traversal": [
            "../../",
            "/etc/passwd",
            "C:\\windows\\win.ini",
            "/var/log/"
        ]
    },
    C2_BEACONING: {
        "user_agents": [
            "Mozilla/5.0 (compatible; EvilBot/1.0)",
            "Metasploit",
            "Empire/2.0",
            "Cobalt Strike"
        ]
    }
}

# Thresholds for Simulator & Detector
THRESHOLDS = {
    "port_scan_min_ports": 20,
    "dos_min_packets": 100,
    "exfil_min_bytes": 1000 * 1024, # 1MB
    "c2_regularity_score": 0.75
}

# Common Target Ports
TARGET_PORTS = {
    "web": [80, 443, 8080],
    "ssh": [22],
    "db": [3306, 5432, 1521, 1433],
    "dns": [53],
    "rpc": [135, 139, 445]
}
