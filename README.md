# ShadowMesh

### Self-Adaptive Honeypot using Deep Reinforcement Learning and Generative AI

![Python](https://img.shields.io/badge/Python-3.10-blue?style=flat-square&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.13-005571?style=flat-square&logo=elasticsearch&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)

---

## Abstract

Traditional honeypots deploy static, fingerprint-prone decoy environments that sophisticated attackers detect and abandon within seconds. ShadowMesh addresses this limitation by combining three independently novel components into a unified, open-source framework.

A **Deep Reinforcement Learning agent** (Proximal Policy Optimization) observes attacker behaviour in real time and selects environment-modification actions designed to maximize engagement duration. A **generative content layer** driven by a high-performance cloud LLM (via OpenRouter API) continuously refreshes the honeypot filesystem, logs, and credential artifacts to prevent fingerprinting through content pattern analysis. An **automated threat intelligence pipeline** converts captured attacker TTPs directly into deployment-ready Snort and YARA detection rules, requiring no human analyst intervention.

The system is designed for deployment alongside banking and enterprise infrastructure as a parallel decoy environment, providing simultaneous attacker intelligence collection and live defensive rule generation.

---

## Architecture

```
                          ┌─────────────────────────────┐
                          │        Honeypot Network      │
                          │         172.18.0.0/24        │
                          │   ┌─────────────────────┐    │
                          │   │   Zeek (Sniffer)    │    │
                          │   └─────────────────────┘    │
  ┌───────────┐  SSH/HTTP │  ┌──────────┐  ┌─────────┐   │
  │ Attacker  │──────────►│  │  Cowrie  │  │  DVWA   │   │
  │ Container │           │  │(Fake SSH)│  │(Fake Web│   │
  └───────────┘           │  └────┬─────┘  └────┬────┘   │
                          │       │              │       │
                          │       └──────┬───────┘       │
                          │              │ raw logs       │
                          │       ┌──────▼───────┐       │
                          │       │  Log Forwarder│      │
                          │       │  (normalizes) │      │
                          │       └──────┬────────┘      │
                          │              │               │
                          │       ┌──────▼───────┐       │
                          │       │Elasticsearch  │      │
                          │       │   + Kibana    │      │
                          │       └──────┬────────┘      │
                          │    ┌─────────┼──────────┐    │
                          │    ▼         ▼           ▼    │
                          │ ┌─────┐  ┌──────┐  ┌──────┐ │
                          │ │ RL  │  │ Rule │  │Kibana│ │
                          │ │Agent│  │ Gen. │  │ Dash │ │
                          │ │(PPO)│  │      │  │      │ │
                          │ └──┬──┘  └──────┘  └──────┘ │
                          │    │ action                  │
                          │    ▼                         │
                          │ ┌──────────┐                 │
                          │ │Generative│                 │
                          │ │  Layer   │                 │
                          │ │(OpenRouter)│                 │
                          │ └──────────┘                 │
                          └─────────────────────────────┘
```

---

## Components

| Component | Technology | Description |
|---|---|---|
| Fake SSH Server | [Cowrie](https://github.com/cowrie/cowrie) | Emulates an OpenSSH server, captures all attacker interaction |
| Fake Web Application | [DVWA](https://github.com/digininja/DVWA) | Intentionally vulnerable PHP web application |
| Network Capture | [Zeek](https://zeek.org) | Passive network traffic analysis and logging |
| Log Storage | Elasticsearch 8.13 | Centralized, queryable log storage |
| Visualization | Kibana 8.13 | Real-time attack session dashboard |
| RL Agent | Stable-Baselines3 (PPO) | Adaptive environment modification via reinforcement learning |
| Generative Layer | LiteLLM + OpenRouter API | Cloud-based LLM routing for fast, hardware-agnostic fake credential and filesystem generation |
| Rule Generator | Custom Python | Converts captured TTPs to Snort / YARA detection rules |
| Attacker Simulation | Paramiko + python-nmap | Three-profile automated attack simulation for training data |

---

## Repository Structure

```
shadowmesh/
├── infra/              Infrastructure — Docker Compose, Cowrie, DVWA configuration
├── logging/            Log pipeline — Elasticsearch setup, Kibana, log forwarder
├── agent/              RL agent — PPO environment, training scripts, model checkpoints
├── attacker/           Attacker simulation — three profiles, wordlists, evaluation scripts
├── generative/         Generative layer — LLM content generation (Phase 2)
├── rules/              Rule generator — Snort/YARA output pipeline (Phase 2)
│   └── output/
├── docs/               Architecture diagrams, report sections, team notes
├── data_contracts.md   Integration specification — read before writing any code
├── pyproject.toml      Python project configuration and dependency management
└── README.md
```

---

## Prerequisites

- Docker Desktop 24.0 or later
- Docker Compose v2
- 8 GB RAM minimum (Elasticsearch and Kibana are memory-intensive)
- macOS or Linux host

---

## Getting Started

**1. Clone the repository**
```bash
git clone https://github.com/Raheedpasha10/shadowmesh.git
cd shadowmesh
```

**2. Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your preferred settings (defaults work for local development)
```

**3. Start the core stack**
```bash
cd infra
docker compose up -d
```

This starts: Cowrie (port 2222), Elasticsearch (port 9200), Kibana (port 5601), and the log forwarder.

**4. Verify everything is running**
```bash
docker compose ps
curl http://localhost:9200/_cluster/health
```

**5. Open the dashboard**

Navigate to `http://localhost:5601` to access the Kibana dashboard.

**6. Run an attack simulation**
```bash
# Single session, opportunist profile
docker compose --profile attack run --rm attacker python simulate.py --profile opportunist --sessions 1

# All three profiles, 3 sessions each
docker compose --profile attack run --rm attacker python simulate.py --sessions 3

# Continuous loop — for generating RL training data
docker compose --profile attack run --rm attacker python simulate.py --loop
```

---

## Attack Profiles

The attacker simulation implements three distinct behavioural profiles to generate diverse training data for the RL agent.

| Profile | Pace | Behaviour | Post-exploitation Commands |
|---|---|---|---|
| `scriptkiddie` | Fast, noisy | Brute forces with all passwords, no subtlety | 5 commands, basic recon |
| `opportunist` | Moderate | Tries common credentials, runs standard enumeration | 10 commands, attempts file download |
| `targeted` | Slow, deliberate | Low attempt count, mimics skilled human attacker | 18 commands, deep enumeration |

---

## Data Contract

All inter-component communication follows a strict schema defined in [`data_contracts.md`](data_contracts.md). Every field name, data type, Elasticsearch index name, Kafka topic, and Docker network address is specified before any code is written. This prevents integration failures when merging independent module contributions.

---

## Development Standards

See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for:

- Git commit message format (Conventional Commits)
- Python code style (type hints, Google docstrings, Ruff)
- Docker best practices (pinned digest, non-root user, resource limits)
- Branch strategy and definition of done

---

## Team

| Member | Role |
|---|---|
| Raheed Pasha | Attacker Simulation and Evaluation Lead |
| Pranathi C | AI/ML Lead — PPO Agent and Gymnasium Environment |
| Saarthak Singh | Infrastructure Lead — Docker, Cowrie, DVWA |
| Parthiv Banik | Data and Logging Lead — Elasticsearch, Zeek, Kibana |

**Institution:** AMC Engineering College, Bengaluru
**Department:** Computer Science and Engineering
**Academic Year:** 2026–27

---

## References

1. Păuna, A., & Bica, I. (2014). *RASSH — Reinforced Adaptive SSH Honeypot*. 2014 10th International Conference on Communications (COMM). DOI: 10.1109/ICCOMM.2014.6866707
2. Ahmed, R., et al. (2025). *SPADE: Enhancing Adaptive Cyber Deception Strategies with Generative AI and Structured Prompt Engineering*. arXiv:2501.00940.
3. JohannesLks (2024). *ADLAH: Adaptive multi-layered honeynet architecture for threat behavior analysis via machine learning, selective escalation, and deception-driven telemetry*.
4. Schulman, J., et al. (2017). *Proximal Policy Optimization Algorithms*. arXiv:1707.06347.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
