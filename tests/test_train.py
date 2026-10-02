import pytest

from agent import train


def test_train_exits_with_helpful_message_when_sb3_is_missing(monkeypatch):
    original_import = __import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("stable_baselines3"):
            raise ModuleNotFoundError("No module named 'stable_baselines3'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    monkeypatch.setattr(train, "parse_args", lambda: type("Args", (), {
        "dataset": "scratch/session_replays/latest_sessions.json",
        "timesteps": 10,
        "model_name": "smoke",
        "log_actions": False,
    })())

    with pytest.raises(SystemExit) as exc:
        train.main()

    assert "stable-baselines3 is not installed" in str(exc.value)


def test_train_exits_when_dataset_is_empty(tmp_path, monkeypatch):
    empty_file = tmp_path / "empty.json"
    empty_file.write_text("[]", encoding="utf-8")

    monkeypatch.setattr(
        train,
        "parse_args",
        lambda: type(
            "Args",
            (),
            {
                "dataset": str(empty_file),
                "timesteps": 10,
                "model_name": "smoke",
                "log_actions": False,
            },
        )(),
    )

    with pytest.raises(SystemExit) as exc:
        train.main()

    assert "Replay dataset is empty" in str(exc.value)

