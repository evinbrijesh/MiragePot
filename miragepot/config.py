"""Centralized configuration for MiragePot.

All settings are loaded from environment variables with sensible defaults.
Use a .env file or export variables before running.

Example:
    export MIRAGEPOT_SSH_PORT=2222
    export MIRAGEPOT_LLM_MODEL=phi3
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def _get_env(key: str, default: str) -> str:
    """Get environment variable with fallback."""
    return os.environ.get(key, default)


def _get_env_int(key: str, default: int) -> int:
    """Get environment variable as integer with fallback."""
    try:
        return int(os.environ.get(key, str(default)))
    except ValueError:
        return default


def _get_env_float(key: str, default: float) -> float:
    """Get environment variable as float with fallback."""
    try:
        return float(os.environ.get(key, str(default)))
    except ValueError:
        return default


def _get_env_bool(key: str, default: bool) -> bool:
    """Get environment variable as boolean with fallback."""
    val = os.environ.get(key, "").lower()
    if val in ("true", "1", "yes", "on"):
        return True
    if val in ("false", "0", "no", "off"):
        return False
    return default


# Base paths
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = DATA_DIR / "logs"


@dataclass
class SSHConfig:
    """SSH honeypot configuration."""

    host: str = field(default_factory=lambda: _get_env("MIRAGEPOT_SSH_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _get_env_int("MIRAGEPOT_SSH_PORT", 2222))
    host_key_path: Path = field(
        default_factory=lambda: Path(
            _get_env("MIRAGEPOT_HOST_KEY", str(DATA_DIR / "host.key"))
        )
    )
    banner: str = field(
        default_factory=lambda: _get_env(
            "MIRAGEPOT_SSH_BANNER", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        )
    )


@dataclass
class LLMConfig:
    """LLM/Ollama configuration."""

    model: str = field(default_factory=lambda: _get_env("MIRAGEPOT_LLM_MODEL", "phi3"))
    timeout: float = field(
        default_factory=lambda: _get_env_float("MIRAGEPOT_LLM_TIMEOUT", 30.0)
    )
    temperature: float = field(
        default_factory=lambda: _get_env_float("MIRAGEPOT_LLM_TEMPERATURE", 0.7)
    )
    max_tokens: int = field(
        default_factory=lambda: _get_env_int("MIRAGEPOT_LLM_MAX_TOKENS", 512)
    )
    check_interval: float = field(
        default_factory=lambda: _get_env_float("MIRAGEPOT_LLM_CHECK_INTERVAL", 30.0)
    )


@dataclass
class DashboardConfig:
    """Streamlit dashboard configuration."""

    host: str = field(
        default_factory=lambda: _get_env("MIRAGEPOT_DASHBOARD_HOST", "localhost")
    )
    port: int = field(
        default_factory=lambda: _get_env_int("MIRAGEPOT_DASHBOARD_PORT", 8501)
    )
    refresh_interval: int = field(
        default_factory=lambda: _get_env_int("MIRAGEPOT_DASHBOARD_REFRESH", 5)
    )


@dataclass
class LoggingConfig:
    """Logging configuration."""

    level: str = field(default_factory=lambda: _get_env("MIRAGEPOT_LOG_LEVEL", "INFO"))
    format: str = field(
        default_factory=lambda: _get_env(
            "MIRAGEPOT_LOG_FORMAT",
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    )
    file: Optional[Path] = field(
        default_factory=lambda: (
            Path(_get_env("MIRAGEPOT_LOG_FILE", ""))
            if _get_env("MIRAGEPOT_LOG_FILE", "")
            else None
        )
    )


@dataclass
class HoneypotConfig:
    """Fake system configuration for the honeypot."""

    hostname: str = field(
        default_factory=lambda: _get_env("MIRAGEPOT_HOSTNAME", "miragepot")
    )
    os_name: str = field(
        default_factory=lambda: _get_env("MIRAGEPOT_OS_NAME", "Ubuntu")
    )
    os_version: str = field(
        default_factory=lambda: _get_env("MIRAGEPOT_OS_VERSION", "20.04.6 LTS")
    )
    kernel_version: str = field(
        default_factory=lambda: _get_env(
            "MIRAGEPOT_KERNEL_VERSION", "5.15.0-86-generic"
        )
    )


@dataclass
class Config:
    """Main configuration container."""

    ssh: SSHConfig = field(default_factory=SSHConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    honeypot: HoneypotConfig = field(default_factory=HoneypotConfig)

    # Paths
    project_root: Path = PROJECT_ROOT
    data_dir: Path = DATA_DIR
    logs_dir: Path = LOGS_DIR
    cache_path: Path = field(default_factory=lambda: DATA_DIR / "cache.json")
    system_prompt_path: Path = field(
        default_factory=lambda: DATA_DIR / "system_prompt.txt"
    )


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance.

    Creates a new instance if one doesn't exist.
    Configuration is loaded from environment variables.
    """
    global _config
    if _config is None:
        _config = Config()
    return _config


def reload_config() -> Config:
    """Force reload of configuration from environment.

    Useful for testing or dynamic reconfiguration.
    """
    global _config
    _config = Config()
    return _config


# Convenience exports
def get_ssh_config() -> SSHConfig:
    """Get SSH configuration."""
    return get_config().ssh


def get_llm_config() -> LLMConfig:
    """Get LLM configuration."""
    return get_config().llm


def get_dashboard_config() -> DashboardConfig:
    """Get dashboard configuration."""
    return get_config().dashboard


def get_logging_config() -> LoggingConfig:
    """Get logging configuration."""
    return get_config().logging


def get_honeypot_config() -> HoneypotConfig:
    """Get honeypot system configuration."""
    return get_config().honeypot
