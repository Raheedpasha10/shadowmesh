# Coding Standards & Contribution Guide

> Every team member must read this before writing any code.
> These are not suggestions. Inconsistent code wastes integration time.

---

## 1. Git Commit Messages — Conventional Commits

All commits **must** follow this format:

```
<type>(<scope>): <short description>
```

**Types:**
| Type | When to Use |
|---|---|
| `feat` | New feature or functionality |
| `fix` | Bug fix |
| `docs` | Documentation changes only |
| `refactor` | Code restructured with no behaviour change |
| `test` | Adding or updating tests |
| `chore` | Config, dependency updates, tooling |
| `perf` | Performance improvement |

**Scopes** (use the folder name):
`infra`, `agent`, `attacker`, `logging`, `generative`, `rules`

**Examples — correct:**
```
feat(agent): implement PPO observation space with 10-dimensional state vector
fix(logging): handle null command field in Cowrie session.closed events
chore(infra): pin Cowrie image to cowrie/cowrie:2.5.0
docs(rules): add Snort SID numbering convention to data_contracts
refactor(attacker): split nmap and hydra into separate modules
```

**Examples — wrong (never do these):**
```
fixed stuff
update
wip
changes
```

---

## 2. Python Code Style

### Formatter & Linter
We use **Ruff** (replaces Black + isort + Flake8 in one tool).

```bash
# Format a file
ruff format agent/environment.py

# Lint a file
ruff check agent/environment.py --fix
```

Run these before every commit. Do not commit code that fails ruff.

### Type Hints — Required on all functions

```python
# CORRECT
def calculate_reward(duration_delta: float, new_ttps: int, fingerprinted: bool) -> float:
    ...

# WRONG — no type hints
def calculate_reward(duration_delta, new_ttps, fingerprinted):
    ...
```

### Docstrings — Google style, required on all public functions

```python
def calculate_reward(duration_delta: float, new_ttps: int, fingerprinted: bool) -> float:
    """Calculate the RL agent reward for a state transition.

    Args:
        duration_delta: Seconds the attacker stayed since last observation.
        new_ttps: Number of new TTP categories observed this step.
        fingerprinted: Whether the attacker showed honeypot detection signals.

    Returns:
        Scalar reward value for the current transition.
    """
```

### Logging — Never use print()

```python
# CORRECT
import logging

logger = logging.getLogger(__name__)
logger.info("Agent action selected: %s for session %s", action_name, session_id)
logger.error("Elasticsearch query failed: %s", exc)

# WRONG
print("action:", action_name)
print("error:", exc)
```

### Environment Variables — Never hardcode

```python
# CORRECT
import os
from dotenv import load_dotenv

load_dotenv()
ES_HOST = os.getenv("ES_HOST", "localhost")

# WRONG
ES_HOST = "172.18.0.20"
```

### Exception Handling — Never bare except

```python
# CORRECT
try:
    result = es.get(index=ES_INDEX_SESSIONS, id=session_id)
except NotFoundError:
    logger.warning("Session %s not found in Elasticsearch", session_id)
    return None
except ConnectionError as exc:
    logger.error("Elasticsearch connection failed: %s", exc)
    raise

# WRONG
try:
    result = es.get(index=ES_INDEX_SESSIONS, id=session_id)
except:
    pass
```

---

## 3. File Naming Conventions

| What | Convention | Example |
|---|---|---|
| Python files | `snake_case.py` | `rule_generator.py` |
| Python classes | `PascalCase` | `class HoneypotEnv` |
| Python functions/vars | `snake_case` | `def calculate_reward()` |
| Constants | `UPPER_SNAKE_CASE` | `MAX_SESSION_DURATION = 3600` |
| Docker files | `Dockerfile` (no extension) | `infra/Dockerfile.cowrie` |
| Config files | `snake_case.yml` | `docker-compose.yml` |
| Rule output files | `session_<id>.<ext>` | `session_a3f9b2c1.rules` |

---

## 4. Folder Rules

Each team member owns one folder. **Do not edit another person's folder without telling them.**

| Folder | Owner | Contains |
|---|---|---|
| `infra/` | Saarthak | Dockerfiles, docker-compose.yml, Cowrie config, DVWA config |
| `logging/` | Parthiv | Zeek config, Elasticsearch setup, Kibana dashboards, log ingestor script |
| `agent/` | Pranathi | PPO environment, training script, model checkpoints (gitignored) |
| `attacker/` | Raheed | Attacker simulation scripts, evaluation scripts, metrics |
| `generative/` | Raheed + Pranathi | LLM content generation scripts (Month 4) |
| `rules/` | Raheed | Rule generator script, output files (gitignored) |
| `docs/` | Saarthak + Parthiv | Architecture diagrams, report sections, meeting notes |

---

## 5. Docker Standards

- **Never use `:latest` tag** — always pin to a specific version
- **Always include healthchecks** for services that others depend on
- **Always set `restart: unless-stopped`** on services
- **Never run containers as root** if avoidable
- **Always use named volumes** for persistent data (Elasticsearch, MySQL)
- Secrets go in `.env` — never hardcoded in `docker-compose.yml`

```yaml
# CORRECT
image: cowrie/cowrie:2.5.0

# WRONG
image: cowrie/cowrie:latest
image: cowrie/cowrie
```

---

## 6. Weekly Sync Rule

Every **Friday**, each member shares running output — not code, not plans, **output**:

- Saarthak: `docker-compose ps` — all containers green
- Parthiv: Kibana screenshot with at least one event
- Pranathi: agent training log showing reward per episode
- Raheed: terminal output of one complete simulated attack session

No output = work the weekend. No exceptions.

---

## 7. Branch Strategy

```
main          ← always working, always runnable
│
├── feat/infra-cowrie-setup        (Saarthak)
├── feat/logging-elasticsearch     (Parthiv)
├── feat/agent-ppo-environment     (Pranathi)
└── feat/attacker-simulation       (Raheed)
```

- Never push directly to `main`
- Open a Pull Request, one other person reviews and approves
- PR title must follow Conventional Commits format
- Merge only when `docker-compose up` on your branch produces no errors

---

## 8. What "Done" Means for a Task

A task is **done** when:
1. Code is written and works locally
2. Ruff passes with no errors
3. It's committed with a proper commit message
4. It's pushed to your branch
5. The specific integration point it touches (per `data_contracts.md`) is verified to produce correct output

"I wrote it and it seems to work" is **not done**.
