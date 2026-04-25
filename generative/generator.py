import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from litellm import completion

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("generative.generator")

# Load environment variables from the root .env file
load_dotenv(Path(__file__).parent.parent / ".env")

API_KEY = os.getenv("OPENROUTER_API_KEY")
PRIMARY_MODEL = os.getenv("LLM_MODEL", "openrouter/meta-llama/llama-3-8b-instruct:free")
FALLBACK_MODELS = [
    model.strip()
    for model in os.getenv("LLM_FALLBACK_MODELS", "").split(",")
    if model.strip()
]
REQUEST_TIMEOUT_SECONDS = float(os.getenv("GENERATION_TIMEOUT_SECONDS", "45"))
REQUEST_RETRIES = int(os.getenv("GENERATION_RETRIES", "2"))
RETRY_DELAY_SECONDS = float(os.getenv("GENERATION_RETRY_DELAY_SECONDS", "5"))


def _normalize_model_name(model_name: str) -> str:
    """Normalize model names to the OpenRouter-prefixed LiteLLM format."""
    return model_name if model_name.startswith("openrouter/") else f"openrouter/{model_name}"


MODELS = []
for candidate in [PRIMARY_MODEL, *FALLBACK_MODELS]:
    normalized = _normalize_model_name(candidate)
    if normalized not in MODELS:
        MODELS.append(normalized)

CACHE_DIR = Path(__file__).parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)
MANIFEST_PATH = CACHE_DIR / "manifest.json"

# ---------------------------------------------------------------------------
# Bait file definitions
# Each entry: filename → AI prompt
# Files are injected into STANDARD Linux filesystem paths so expert hackers
# find them naturally during their post-exploitation checklist.
# ---------------------------------------------------------------------------
FAKE_FILES = {

    # Standard Linux user database — first file every attacker reads
    "passwd": (
        "Generate exactly 14 lines of a realistic Linux /etc/passwd file for a "
        "financial technology company web server. Include: root, daemon, bin, sys, "
        "www-data, mysql, sshd as system users, and 3 realistic human employees: "
        "'jsmith' (uid 1001), 'dbadmin' (uid 1002), 'deploy' (uid 1003). "
        "Use correct /etc/passwd colon-separated format. "
        "Output ONLY the raw lines. No markdown, no explanations."
    ),

    # Shadow password file — attackers run hashcat/john on these hashes
    "shadow": (
        "Generate exactly 5 lines of a realistic Linux /etc/shadow file. "
        "Users: root, jsmith, dbadmin, deploy, www-data. "
        "Use realistic SHA-512 format: $6$<8-char-salt>$<86-char-hash>. "
        "Make the hashes look completely authentic (long random base64 strings). "
        "Dates as days-since-epoch (around 19700). "
        "Output ONLY raw /etc/shadow lines. No markdown."
    ),

    # Admin bash history — attackers hunt for accidentally typed passwords
    "bash_history.txt": (
        "Generate exactly 22 lines of a realistic Linux bash_history for a database "
        "administrator at a company called NovaPay Financial Services. "
        "Include realistic commands such as: connecting to mysql using -p with a password "
        "typed directly in the command (e.g. mysql -u root -pS3cur3P@ss2024!), "
        "mysqldump backup commands with credentials, editing /etc/mysql/my.cnf with vi, "
        "checking disk usage, restarting nginx and mysql services with systemctl, "
        "scp-ing a backup file to a remote IP, and checking system logs. "
        "Output ONLY raw bash commands exactly as they appear in .bash_history. "
        "No line numbers, no prompts, no markdown."
    ),

    # Web app database config — the primary target for credential theft
    "db_config.php": (
        "Generate a realistic PHP database configuration file for a fintech web "
        "application called 'NovaPay'. Use PHP define() statements for: "
        "DB_HOST (localhost), DB_PORT (3306), DB_NAME (novapay_production), "
        "DB_USER (novapay_svc), DB_PASSWORD (a complex 28-char password with symbols), "
        "DB_CHARSET (utf8mb4), and APP_SECRET_KEY (a long random string). "
        "Add a realistic PHP comment block at the top with the filename and date. "
        "Output ONLY raw PHP code. No markdown code fences."
    ),

    # Environment file packed with cloud credentials — maximum attacker value
    ".env": (
        "Generate a realistic .env environment file for a Node.js backend service "
        "called NovaPay. Include these exact keys with realistic fake values: "
        "NODE_ENV=production, PORT=3001, "
        "DATABASE_URL (postgres connection string with username, complex password, hostname, db name), "
        "JWT_SECRET (64-char random string), JWT_EXPIRES_IN=24h, "
        "AWS_ACCESS_KEY_ID (realistic AKIA... format, 20 chars), "
        "AWS_SECRET_ACCESS_KEY (realistic 40-char base64-looking string), "
        "AWS_REGION=us-east-1, S3_BUCKET=novapay-prod-backups, "
        "STRIPE_SECRET_KEY (realistic sk_live_... format), "
        "SENDGRID_API_KEY (realistic SG.... format), "
        "REDIS_URL=redis://:password@localhost:6379/0. "
        "Output ONLY raw KEY=VALUE pairs. No markdown, no comments."
    ),

    # RSA private key — if cracked lets attacker pivot to other servers
    "id_rsa": (
        "Generate a fake but completely realistic RSA private key in standard PEM format. "
        "Start with -----BEGIN RSA PRIVATE KEY----- on its own line. "
        "Fill the body with realistic-looking base64-encoded text at 64 chars per line "
        "for approximately 27 lines (simulating a real 2048-bit key). "
        "End with -----END RSA PRIVATE KEY----- on its own line. "
        "Output ONLY the raw PEM block. No explanations, no markdown."
    ),
}

# ---------------------------------------------------------------------------
# The exact Linux filesystem paths where each bait file will appear
# inside the Cowrie honeyfs. Attackers find these during standard recon.
# ---------------------------------------------------------------------------
HONEYFS_PATHS = {
    "passwd":          "etc/passwd",
    "shadow":          "etc/shadow",
    "bash_history.txt":"home/admin/.bash_history",
    "db_config.php":   "var/www/html/config.php",
    ".env":            "opt/novapay/.env",
    "id_rsa":          "home/admin/.ssh/id_rsa",
}

CONTENT_TYPES = {
    "passwd": "passwd",
    "shadow": "shadow",
    "bash_history.txt": "bash_history",
    "db_config.php": "db_config",
    ".env": "env",
    "id_rsa": "private_key",
}


def _strip_code_fences(content: str) -> str:
    """Remove markdown code fences if a model returns fenced output."""
    lines = content.strip().splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _sha256(content: str) -> str:
    """Return the SHA-256 checksum for generated content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _validate_generated_content(filename: str, content: str) -> None:
    """Validate generated bait files before writing them to disk."""
    lines = [line for line in content.splitlines() if line.strip()]

    if filename == "passwd":
        if len(lines) < 10 or not any(line.startswith("root:") for line in lines):
            raise ValueError("Generated passwd content is incomplete or missing root")
        if any(line.count(":") < 6 for line in lines):
            raise ValueError("Generated passwd content has malformed entries")
        return

    if filename == "shadow":
        if len(lines) < 5 or not any(line.startswith("root:") for line in lines):
            raise ValueError("Generated shadow content is incomplete or missing root")
        if not any("$6$" in line for line in lines):
            raise ValueError("Generated shadow content is missing SHA-512 hashes")
        return

    if filename == "bash_history.txt":
        if len(lines) < 12:
            raise ValueError("Generated bash history is too short")
        return

    if filename == "db_config.php":
        required_tokens = ("<?php", "DB_HOST", "DB_PASSWORD", "APP_SECRET_KEY")
        if not all(token in content for token in required_tokens):
            raise ValueError("Generated PHP config is missing required fields")
        return

    if filename == ".env":
        required_keys = (
            "NODE_ENV",
            "PORT",
            "DATABASE_URL",
            "JWT_SECRET",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_REGION",
            "S3_BUCKET",
            "STRIPE_SECRET_KEY",
            "SENDGRID_API_KEY",
            "REDIS_URL",
        )
        if not all(any(line.startswith(f"{key}=") for line in lines) for key in required_keys):
            raise ValueError("Generated .env content is missing required keys")
        malformed_lines = [line for line in lines if "=" not in line]
        if malformed_lines:
            raise ValueError("Generated .env contains malformed lines")
        return

    if filename == "id_rsa":
        if not content.startswith("-----BEGIN RSA PRIVATE KEY-----"):
            raise ValueError("Generated private key is missing BEGIN header")
        if not content.endswith("-----END RSA PRIVATE KEY-----"):
            raise ValueError("Generated private key is missing END footer")
        if len(lines) < 12:
            raise ValueError("Generated private key is unrealistically short")
        return


def _write_manifest(entries: list[dict]) -> None:
    """Write the generation manifest required by data_contracts.md."""
    manifest = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": entries,
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def generate_file(filename: str, prompt: str) -> dict:
    """Generate one bait file, validate it, and persist it to the cache."""
    display_path = f"/{HONEYFS_PATHS.get(filename, filename)}"
    logger.info("Generating %s", display_path)

    last_error: Exception | None = None

    for model_name in MODELS:
        for attempt in range(1, REQUEST_RETRIES + 1):
            try:
                response = completion(
                    model=model_name,
                    messages=[{"role": "user", "content": prompt}],
                    api_key=API_KEY,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
                content = _strip_code_fences(response.choices[0].message.content)
                _validate_generated_content(filename, content)

                output_path = CACHE_DIR / filename
                output_path.write_text(content + "\n", encoding="utf-8")

                checksum = _sha256(content)
                logger.info("Saved %s via %s", output_path.name, model_name)

                return {
                    "cowrie_path": f"/{HONEYFS_PATHS[filename]}",
                    "content_type": CONTENT_TYPES[filename],
                    "character_count": len(content),
                    "checksum": checksum,
                }
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "Generation failed for %s via %s (attempt %d/%d): %s",
                    filename,
                    model_name,
                    attempt,
                    REQUEST_RETRIES,
                    exc,
                )
                time.sleep(RETRY_DELAY_SECONDS * attempt)

        logger.warning("Switching to next fallback model after failures: %s", model_name)

    raise RuntimeError(f"Could not generate {filename}: {last_error}")


def main():
    if not API_KEY:
        logger.error("OPENROUTER_API_KEY not set in root .env — aborting.")
        raise SystemExit(1)

    logger.info("=" * 50)
    logger.info("ShadowMesh — Generative Bait File Builder")
    logger.info("=" * 50)
    logger.info("Models : %s", ", ".join(MODELS))
    logger.info("Output : %s", CACHE_DIR)
    logger.info("Files  : %d", len(FAKE_FILES))

    manifest_entries: list[dict] = []
    failures: list[str] = []
    for filename, prompt in FAKE_FILES.items():
        try:
            manifest_entries.append(generate_file(filename, prompt))
        except Exception as exc:
            failures.append(filename)
            logger.error("Failed to generate %s: %s", filename, exc)

        # Respect provider rate limits between successful and failed requests.
        time.sleep(4)

    _write_manifest(manifest_entries)
    logger.info("Manifest written to %s", MANIFEST_PATH)

    if failures:
        logger.error(
            "Generation completed with failures. Successful: %d | Failed: %d | Failed files: %s",
            len(manifest_entries),
            len(failures),
            ", ".join(failures),
        )
        raise SystemExit(1)

    logger.info("All bait files generated successfully. Restart Cowrie to pick up the new mounts.")


if __name__ == "__main__":
    main()
