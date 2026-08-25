# ShadowMesh Agent Guide

## Scope and boundaries

ShadowMesh is a containerized SSH deception system. Keep its independently
working services independent; the dashboard is a local control and evidence
layer, not a replacement for Cowrie, Elasticsearch, the agent, or generators.

- `infra/`: Docker Compose, Cowrie, Elasticsearch, Kibana, forwarder, agent
  runner, and action executor.
- `attacker/`: contained simulator; runs on demand under the `attack` profile.
- `logging/forwarder.py`: Cowrie JSON normalization and live session summaries.
- `agent/`: deterministic baseline policies, executor, offline PPO tooling.
- `generative/`: bait artifacts mounted into Cowrie's honey filesystem.
- `rules/`: Snort/YARA generation from closed session summaries.
- `dashboard/`: localhost-only API and React reviewer interface.

Read `data_contracts.md` before changing integration behavior. Preserve field
names and Elasticsearch index names unless the contract changes first.

## Actual event flow

`attacker simulator -> Cowrie -> cowrie.json -> forwarder -> Elasticsearch`

The forwarder writes normalized events to `honeypot-cowrie-events` and updates
`honeypot-sessions` after every Cowrie event. The agent runner reads summaries
and writes decisions to `honeypot-rl-actions`. The executor currently supports
`show_fake_file` and `show_fake_credentials`, materializing bait in mounted
Cowrie-visible files. Rules read closed summaries, write artifacts under
`rules/output/`, and index records in `honeypot-generated-rules`.

The dashboard reads these indexes/files and launches existing project commands;
it must not duplicate business logic or fabricate outcomes.

## Runtime truthfulness

Genuinely live today:

- Cowrie connection, login, command, download, and close events.
- Live session-summary updates, service state, baseline-agent decisions, bait
  file contents, and generated-rule records.
- Dashboard controls for stack start/stop, contained attacker scenarios, bait
  regeneration, and rule generation. Current source also has cancellation for
  a dashboard-launched scenario.

Inferred/presentation-only today:

- Attacker profile for historical sessions is inferred from command patterns
  unless remembered by the dashboard's local profile state.
- Failed login attempts and a successful interactive shell can have separate
  Cowrie session IDs; the dashboard may group them for a scenario story.
- Bait access is inferred from captured commands such as `cat /etc/passwd`,
  not a proof that a particular bait version was read.

Planned/not live:

- PPO as the live decision policy. The deployed path is deterministic baseline
  policy selection; offline PPO tools are not evidence of live PPO control.
- Zeek, Kafka, DVWA, or broader web/database attack surfaces in the current
  Compose runtime.

## Attacker simulator

- `scriptkiddie`: fast timing, four credential attempts, five basic recon
  commands.
- `opportunist`: moderate timing, five attempts, eleven recon/credential and
  payload-download commands.
- `targeted`: slow timing, three attempts, nineteen deeper configuration,
  persistence, and discovery commands.

After reading `/etc/passwd` or `/etc/shadow`, the simulator can issue a
follow-up grep only when it sees expected bait markers in command output.

## Dashboard rules

- Keep the API localhost-only unless scope explicitly changes.
- Use real backend state, timestamps, session IDs, job state, and index records
  in visualizations. Loading/empty/error states must remain truthful.
- Treat UI control actions as jobs: validate inputs, surface command failures,
  and do not claim a service/action succeeded without evidence.
- Reuse existing API endpoints and evidence views where possible; avoid editing
  core services while working on dashboard presentation.

## Provenance limitations

There is no indexed action-execution receipt today. The executor writes files
but does not record execution status, artifact hashes, or errors in
Elasticsearch. There is also no durable `attack_run_id` spanning simulator,
Cowrie sessions, agent decisions, executor outputs, and rule records.

Do not claim that an adaptive action caused a later attacker behavior without
explicit provenance. In particular, the default policy seeds bait for the next
session after a successful session closes; one-session demos prove the action,
not its impact.

## Non-negotiable preservation rules

- Do not rename contract fields, indexes, volumes, mounted bait paths, or
  service identifiers casually.
- Do not replace working Cowrie, logging, agent, generator, or rule behavior
  with dashboard mocks.
- Never add fake telemetry, simulated service health, fake AI decisions, fake
  execution confirmations, or unsupported “PPO-powered” claims to make the UI
  look impressive.
- Keep attack simulation contained to the documented local honeypot setup.
