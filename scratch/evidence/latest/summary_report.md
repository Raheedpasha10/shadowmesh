# ShadowMesh Evidence Summary

## Overview

- Baseline sessions analyzed: `25`
- Adaptive sessions analyzed: `25`
- Adaptive bait-follow-up sessions observed: `22`
- Baseline average command count: `8.56`
- Adaptive average command count: `11.44`

## Reviewer Summary

This evidence batch compares a static SSH honeypot run against the current adaptive ShadowMesh flow.
In the adaptive run, attackers not only logged in and performed the same baseline recon, but also followed the planted bait accounts exposed through `/etc/passwd` and `/etc/shadow`.

## Dataset Snapshot

- Baseline login-success sessions: `25`
- Adaptive login-success sessions: `23`
- Baseline average duration: `38.36` seconds
- Adaptive average duration: `49.19` seconds
- Baseline average unique commands: `8.56`
- Adaptive average unique commands: `11.44`

## Evaluation Table

| metric | baseline | adaptive | delta |
|---|---:|---:|---:|
| session_duration | 38.36 | 49.19 | +10.83 |
| command_count | 8.56 | 11.44 | +2.88 |
| unique_commands | 8.56 | 11.44 | +2.88 |
| ttp_count | 3.12 | 4.60 | +1.48 |
| bait_access_sessions | 0.00 | 22.00 | +22.00 |
| payload_attempts | 7.00 | 16.00 | +9.00 |

## Adaptive Command Highlights

- `cat /etc/passwd` appeared in `23` adaptive sessions
- `grep -E 'backupsvc|cloudsync' /etc/passwd` appeared in `22` adaptive sessions
- `cat /home/admin/loot/system_audit.txt` appeared in `19` adaptive sessions
- `cat /etc/issue` appeared in `16` adaptive sessions
- `cat /etc/shadow` appeared in `16` adaptive sessions

## Policy Comparison

| policy | sessions | avg_reward | top_action | action_breakdown |
|---|---:|---:|---|---|
| do_nothing | 10 | 20.10 | do_nothing | do_nothing:10 |
| show_fake_credentials_after_successful_session | 10 | 24.60 | show_fake_credentials | do_nothing:1, show_fake_credentials:9 |
| ppo | 10 | 22.90 | show_fake_file | open_fake_port:1, show_fake_credentials:1, show_fake_file:8 |
