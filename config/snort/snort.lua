-- Snort 3 Configuration for IDS and JSON alert output
-- This configuration enables comprehensive network security monitoring with JSON alert logging
-- 
-- Environment variables that can be set:
--   HOME_NET: Local network to protect (default: 192.168.1.0/24)
--   EXTERNAL_NET: External network (default: any)
--   RULE_PATH: Path to rule files (default: /etc/snort/rules)
--   ALERT_JSON_FILE: Path to alert output file (default: /var/log/snort/alert.json)

local os = require('os')

-- Network definitions
HOME_NET = os.getenv('HOME_NET') or '192.168.1.0/24'
EXTERNAL_NET = os.getenv('EXTERNAL_NET') or 'any'
rule_path = os.getenv('RULE_PATH') or '/etc/snort/rules'

-- Alert output configuration for JSON logging
alert_json = {
    file = true,
    filename = os.getenv('ALERT_JSON_FILE') or 'logs/alert.json',
    limit = 0,
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_addr src_port dst_addr dst_port action rule'
}

ips = {
    include = 'local.rules'
}


-- Network analysis settings
addresses = {
    home_net = HOME_NET,
    external_net = EXTERNAL_NET,
}

-- Stream processing and reassembly
stream = {
    max_sessions = 262144,
    max_window = 0
}

stream_tcp = {
    overlap_limit = true,
    overlap_action = 'drop_old'
}

stream_udp = {}
stream_icmp = {}
stream_ip = {}

-- HTTP protocol inspection
http_inspect = {
    server_flow_depth = 0,
    client_flow_depth = 0,
    post_depth = 65535,
    max_header_length = 750,
    max_headers = 100,
    normalize_utf = true,
    decompress_swf = true,
    decompress_pdf = true,
    inspect_gzip = true,
    max_gzip_mem = 3145728
}

-- DNS protocol inspection
dns = {
    max_length = 0
}

-- Reputation filtering (optional)
reputation = {
    blacklist = '/etc/snort/blacklist.txt',
    whitelist = '/etc/snort/whitelist.txt'
}

-- Include local rules
-- Rules are included via the ips module above

