import importlib
import sys
from types import SimpleNamespace


def _load_generator(monkeypatch, *, model: str, fallbacks: str, openrouter_key: str = "", groq_key: str = ""):
    monkeypatch.setitem(
        sys.modules,
        "litellm",
        SimpleNamespace(completion=lambda *args, **kwargs: None),
    )
    monkeypatch.setitem(
        sys.modules,
        "dotenv",
        SimpleNamespace(load_dotenv=lambda *args, **kwargs: None),
    )
    monkeypatch.setenv("LLM_MODEL", model)
    monkeypatch.setenv("LLM_FALLBACK_MODELS", fallbacks)
    if openrouter_key:
        monkeypatch.setenv("OPENROUTER_API_KEY", openrouter_key)
    else:
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    if groq_key:
        monkeypatch.setenv("GROQ_API_KEY", groq_key)
    else:
        monkeypatch.delenv("GROQ_API_KEY", raising=False)

    sys.modules.pop("generative.generator", None)
    return importlib.import_module("generative.generator")


def test_model_normalization_preserves_explicit_provider(monkeypatch):
    generator = _load_generator(
        monkeypatch,
        model="nvidia/nemotron-3-super-120b-a12b:free",
        fallbacks="groq/openai/gpt-oss-120b",
        openrouter_key="or-key",
        groq_key="groq-key",
    )

    assert generator.MODELS == [
        "openrouter/nvidia/nemotron-3-super-120b-a12b:free",
        "groq/openai/gpt-oss-120b",
    ]


def test_provider_key_selection_uses_matching_key(monkeypatch):
    generator = _load_generator(
        monkeypatch,
        model="openrouter/meta-llama/llama-3.2-3b-instruct:free",
        fallbacks="groq/openai/gpt-oss-120b",
        openrouter_key="or-key",
        groq_key="groq-key",
    )

    assert generator._api_key_for_model("openrouter/meta-llama/llama-3.2-3b-instruct:free") == "or-key"
    assert generator._api_key_for_model("groq/openai/gpt-oss-120b") == "groq-key"


def test_missing_provider_keys_only_block_that_provider(monkeypatch):
    generator = _load_generator(
        monkeypatch,
        model="openrouter/meta-llama/llama-3.2-3b-instruct:free",
        fallbacks="groq/openai/gpt-oss-120b",
        openrouter_key="or-key",
        groq_key="",
    )

    assert generator._configured_models_with_missing_keys() == ["groq/openai/gpt-oss-120b"]
    assert generator._has_usable_model_credentials() is True


def test_generate_file_passes_configured_token_budget(monkeypatch, tmp_path):
    captured = {}

    def fake_completion(*args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="generated bait content")
                )
            ]
        )

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=fake_completion))
    monkeypatch.setitem(sys.modules, "dotenv", SimpleNamespace(load_dotenv=lambda *args, **kwargs: None))
    monkeypatch.setenv("LLM_MODEL", "groq/openai/gpt-oss-120b")
    monkeypatch.setenv("LLM_FALLBACK_MODELS", "")
    monkeypatch.setenv("GROQ_API_KEY", "groq-key")
    monkeypatch.setenv("GENERATION_MAX_TOKENS", "321")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    sys.modules.pop("generative.generator", None)
    generator = importlib.import_module("generative.generator")
    generator.CACHE_DIR = tmp_path
    generator._validate_generated_content = lambda filename, content: None

    generator.generate_file("passwd", "Generate test bait")

    assert captured["max_tokens"] == 321
