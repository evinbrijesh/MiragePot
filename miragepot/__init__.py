"""MiragePot - AI-Driven Adaptive SSH Honeypot.

A research and education-focused SSH honeypot that uses a local LLM (Phi-3 via Ollama)
to generate realistic terminal responses, keeping attackers engaged while logging
their activities for analysis.

Key components:
- server: SSH honeypot server using Paramiko
- command_handler: Hybrid cache + LLM command processing
- ai_interface: Ollama/LLM integration
- defense_module: Threat scoring and tarpit delays
- config: Centralized configuration management
"""

__version__ = "0.1.0"
__author__ = "Evin Brijesh"
__email__ = "evinbrijesh@example.com"
__license__ = "MIT"

from .config import get_config, Config

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "get_config",
    "Config",
]
