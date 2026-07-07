# ShadowMesh Evidence Workflow

This note defines the repeatable workflow we use to collect datasets, validate
offline PPO, and demonstrate the SSH-first adaptive loop in a reviewer-friendly
way.

## 1. Stable Demo Baseline

Use the local adaptive prototype as the reference implementation:

- Cowrie SSH honeypot
- live `honeypot-sessions` summaries in Elasticsearch
- deterministic baseline policy via `agent-runner`
- first adaptive actions materialized by `action-executor`

Keep the evidence and evaluation policy on:

```bash
AGENT_POLICY=show_fake_credentials_after_successful_session
```

## 2. Canonical Dataset Collection Rule

We maintain two replay datasets with the same attacker profile and session
count:

- `baseline_sessions.json`
  - run the stack without `agent-runner` and `action-executor`
- `adaptive_sessions.json`
  - run the stack with both services enabled
  - discard the first successful session as the adaptation seed/warm-up

Recommended attacker profile for both datasets:

```bash
python simulate.py --profile opportunist --sessions 25 --delay 2
```

Why the larger delay matters:

- the forwarder must finish closing and indexing the seed session
- `agent-runner` must observe the closed-session summary
- `action-executor` must materialize the next-session bait before the next login

Only export:

- completed sessions
- sessions with at least one command
- matching collection window timestamps

## 3. Export Commands

For repeatable paired collection, prefer the one-shot helper:

```bash
python -m agent.collect_evidence \
  --baseline-since <baseline_start_iso> \
  --baseline-until <baseline_end_iso> \
  --adaptive-since <adaptive_start_iso> \
  --adaptive-until <adaptive_end_iso> \
  --limit 100 \
  --min-command-count 1 \
  --output-dir scratch/evidence/latest
```

This writes:

- `baseline_sessions.json`
- `adaptive_sessions.json`
- `evaluation.md`
- `manifest.json`

If you want the lower-level manual export flow, use:

```bash
# Baseline export
python -m agent.export_sessions \
  --output scratch/session_replays/baseline_sessions.json \
  --since <baseline_start_iso> \
  --until <baseline_end_iso> \
  --limit 100 \
  --min-command-count 1

# Adaptive export
python -m agent.export_sessions \
  --output scratch/session_replays/adaptive_sessions.json \
  --since <adaptive_start_iso> \
  --until <adaptive_end_iso> \
  --limit 100 \
  --min-command-count 1
```

## 4. Reward and Policy Inspection

Inspect deterministic policy output against replay data:

```bash
python -m agent.analyze_rewards \
  --dataset scratch/session_replays/adaptive_sessions.json \
  --policy show_fake_credentials_after_successful_session \
  --limit 10
```

This prints:

- `session_id`
- contract-aligned state vector
- selected action
- computed heuristic reward

## 5. PPO Smoke Training

Start with a short offline run:

```bash
python -m agent.train \
  --dataset scratch/session_replays/adaptive_sessions.json \
  --timesteps 1000 \
  --model-name shadowmesh_ppo_smoke
```

Then run a longer pass once the smoke run is stable:

```bash
python -m agent.train \
  --dataset scratch/session_replays/adaptive_sessions.json \
  --timesteps 10000 \
  --model-name shadowmesh_ppo_adaptive
```

## 6. Offline Policy Comparison

Compare the three supported offline policies on the same replay dataset:

```bash
.venv311/bin/python -m agent.infer \
  --dataset scratch/session_replays/adaptive_sessions.json \
  --policy do_nothing \
  --limit 10

.venv311/bin/python -m agent.infer \
  --dataset scratch/session_replays/adaptive_sessions.json \
  --policy show_fake_credentials_after_successful_session \
  --limit 10

.venv311/bin/python -m agent.infer \
  --dataset scratch/session_replays/adaptive_sessions.json \
  --policy ppo \
  --model agent/models/shadowmesh_ppo_adaptive.zip \
  --limit 10
```

For a reviewer-friendly summary table, use:

```bash
MPLCONFIGDIR=scratch/mplconfig .venv311/bin/python -m agent.compare_policies \
  --dataset scratch/session_replays/adaptive_sessions.json \
  --policies do_nothing show_fake_credentials_after_successful_session ppo \
  --model agent/models/shadowmesh_ppo_adaptive.zip \
  --limit 10 \
  --format markdown \
  --output scratch/evidence/policy_comparison.md
```

## 7. Evaluation Output

Generate the final baseline-vs-adaptive comparison table:

```bash
python -m agent.evaluate \
  --baseline scratch/session_replays/baseline_sessions.json \
  --adaptive scratch/session_replays/adaptive_sessions.json \
  --format markdown \
  --output scratch/evidence/latest_evaluation.md
```

Metrics currently reported:

- average session duration
- average command count
- average unique commands
- average TTP count
- bait-access session count
- payload-attempt count

Package one evidence folder into a reviewer-friendly summary:

```bash
python -m agent.package_evidence \
  --evidence-dir scratch/evidence/july07
```

This writes `summary_report.md` inside the same evidence directory.

## 8. Canonical Live Demo Scenario

Use one deterministic demo path:

1. Start the stack.
2. Confirm `agent-runner` is using `show_fake_credentials_after_successful_session`.
3. Run one warm-up `opportunist` session that reaches login success.
4. Verify a `show_fake_credentials` action is logged for that closed session.
5. Run the next `opportunist` session.
6. Show in Kibana:
   - the new session accesses adaptive bait such as:
     - `cat /etc/passwd`
     - `grep -E 'backupsvc|cloudsync' /etc/passwd`
7. Show generated rules for the follow-up session in `honeypot-generated-rules`.

This keeps the story simple:

`seed session closes -> adaptive action materializes bait -> next session discovers bait -> rules generated`

## 9. Current Limitation

The current action bridge reliably logs adaptive decisions and materializes bait
into the shared Cowrie honeyfs volumes. However, in the present Cowrie setup,
newly created bait files are not yet being rediscovered inside the *same live
session* with full reliability.

What this means today:

- adaptive decisions are visible in `honeypot-rl-actions`
- adaptive bait files are written to the shared action volumes
- offline PPO and replay evaluation work correctly
- the most reliable measurable effect is currently **next-session adaptation**

Treat this as a known engineering limitation of the current Cowrie integration,
not as missing evidence for the rest of the adaptive pipeline.
