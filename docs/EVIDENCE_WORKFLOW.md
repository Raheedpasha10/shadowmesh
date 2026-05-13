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

Keep the live demo policy on:

```bash
AGENT_POLICY=show_fake_credentials_on_login_success
```

## 2. Canonical Dataset Collection Rule

We maintain two replay datasets with the same attacker profile and session
count:

- `baseline_sessions.json`
  - run the stack without `agent-runner` and `action-executor`
- `adaptive_sessions.json`
  - run the stack with both services enabled

Recommended attacker profile for both datasets:

```bash
python simulate.py --profile opportunist --sessions 25 --delay 1
```

Only export:

- completed sessions
- sessions with at least one command
- matching collection window timestamps

## 3. Export Commands

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
  --policy show_fake_credentials_on_login_success \
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
python -m agent.infer \
  --dataset scratch/session_replays/adaptive_sessions.json \
  --policy do_nothing \
  --limit 10

python -m agent.infer \
  --dataset scratch/session_replays/adaptive_sessions.json \
  --policy show_fake_credentials_on_login_success \
  --limit 10

python -m agent.infer \
  --dataset scratch/session_replays/adaptive_sessions.json \
  --policy ppo \
  --model agent/models/shadowmesh_ppo_adaptive.zip \
  --limit 10
```

## 7. Evaluation Output

Generate the final comparison table:

```bash
python -m agent.evaluate \
  --baseline scratch/session_replays/baseline_sessions.json \
  --adaptive scratch/session_replays/adaptive_sessions.json \
  --format markdown
```

Metrics currently reported:

- average session duration
- average command count
- average unique commands
- average TTP count
- bait-access session count
- payload-attempt count

## 8. Canonical Live Demo Scenario

Use one deterministic demo path:

1. Start the stack.
2. Confirm `agent-runner` is using `show_fake_credentials_on_login_success`.
3. Run the attacker simulator with `opportunist`.
4. Show in Kibana:
   - active session appears
   - `show_fake_credentials` action is logged
   - attacker later accesses:
     - `/home/admin/loot/system_audit.txt`
     - `/home/admin/.aws/credentials`
5. Show generated rules for that session in `honeypot-generated-rules`.

This keeps the story simple:

`attacker login -> adaptive action -> bait discovery -> rules generated`

## 9. Current Limitation

The current action bridge reliably logs adaptive decisions and materializes bait
into the shared Cowrie honeyfs volumes. However, in the present Cowrie setup,
newly created bait files are not yet being rediscovered inside the *same live
session* with full reliability.

What this means today:

- adaptive decisions are visible in `honeypot-rl-actions`
- adaptive bait files are written to the shared action volumes
- offline PPO and replay evaluation work correctly
- same-session attacker command differences are still limited

Treat this as a known engineering limitation of the current Cowrie integration,
not as missing evidence for the rest of the adaptive pipeline.
