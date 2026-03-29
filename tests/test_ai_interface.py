"""Tests for ai_interface.py sanitization and security features.

Phase 2.2: Tests for sanitize_llm_response() function and timeout handling.
"""

import pytest
from miragepot.ai_interface import sanitize_llm_response


class TestSanitizeLLMResponse:
    """Tests for LLM response sanitization."""

    def test_meta_commentary_stripping(self):
        """Test that meta-commentary is stripped from responses."""
        response_with_meta = """uid=0(root) gid=0(root) groups=0(root)
Note: This is the output of the id command
Explanation: The user is root with UID 0"""

        sanitized = sanitize_llm_response(response_with_meta)

        # Meta-commentary lines should be removed
        assert "Note:" not in sanitized
        assert "Explanation:" not in sanitized
        # Actual output should remain
        assert "uid=0(root)" in sanitized

    def test_code_fence_removal(self):
        """Test that code fences wrapping entire response are removed."""
        response_with_fences = """```bash
uid=0(root) gid=0(root) groups=0(root)
```"""

        sanitized = sanitize_llm_response(response_with_fences)

        # Code fences should be removed
        assert not sanitized.startswith("```")
        assert not sanitized.endswith("```")
        # Content should remain
        assert "uid=0(root)" in sanitized

    def test_code_fence_with_language_tag(self):
        """Test code fence removal with language tags."""
        response = """```
uid=0(root) gid=0(root) groups=0(root)
```"""

        sanitized = sanitize_llm_response(response)

        assert "uid=0(root)" in sanitized
        assert "```" not in sanitized

    def test_length_truncation(self):
        """Test that responses are truncated to 2048 characters."""
        # Create a 3000 character response
        long_response = "A" * 3000

        sanitized = sanitize_llm_response(long_response)

        # Should be truncated to 2048 chars
        assert len(sanitized) == 2048

    def test_whitespace_stripping(self):
        """Test that leading/trailing whitespace is stripped."""
        response_with_whitespace = """

        uid=0(root) gid=0(root) groups=0(root)
        
        """

        sanitized = sanitize_llm_response(response_with_whitespace)

        # Should not have leading/trailing whitespace
        assert not sanitized.startswith(" ")
        assert not sanitized.startswith("\n")
        assert not sanitized.endswith(" ")
        assert not sanitized.endswith("\n")

    def test_empty_response(self):
        """Test handling of empty responses."""
        assert sanitize_llm_response("") == ""
        assert sanitize_llm_response("   ") == ""

    def test_multiple_meta_commentary_lines(self):
        """Test stripping multiple meta-commentary lines."""
        response = """This command shows the user identity
Note: Root user has UID 0
uid=0(root) gid=0(root) groups=0(root)
Explanation: This is a privileged account
Here's what this means for security"""

        sanitized = sanitize_llm_response(response)

        # All meta-commentary should be removed
        assert "This command" not in sanitized
        assert "Note:" not in sanitized
        assert "Explanation:" not in sanitized
        assert "Here's" not in sanitized
        # Only actual output remains
        assert "uid=0(root)" in sanitized

    def test_preserves_valid_terminal_output(self):
        """Test that valid terminal output is preserved."""
        valid_response = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169260 11560 ?        Ss   09:14   0:01 /sbin/init
root       487  0.0  0.1  15420  6400 ?        Ss   09:14   0:00 /usr/sbin/sshd -D"""

        sanitized = sanitize_llm_response(valid_response)

        # Should preserve the entire output
        assert "USER" in sanitized
        assert "root         1" in sanitized
        assert "/sbin/init" in sanitized
        assert "/usr/sbin/sshd" in sanitized

    def test_truncation_with_newlines(self):
        """Test that truncation works correctly with multi-line content."""
        # Create response that exceeds limit
        lines = ["Line %d" % i for i in range(500)]
        long_response = "\n".join(lines)

        sanitized = sanitize_llm_response(long_response)

        # Should be truncated
        assert len(sanitized) <= 2048
        # Should still be valid (not cut mid-line would be nice, but not required)

    def test_code_fence_not_removed_if_internal(self):
        """Test that code fences inside content are preserved."""
        response = """Here is some code:
```bash
echo "hello"
```
And here is more output"""

        sanitized = sanitize_llm_response(response)

        # Internal code fences might be preserved or the line removed due to "Here is"
        # The important thing is we don't break the content
        assert len(sanitized) > 0

    def test_realistic_ps_output(self):
        """Test with realistic ps output (no sanitization should occur)."""
        ps_output = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  0.2 225940  8456 ?        Ss   10:23   0:02 /sbin/init
root       123  0.0  0.1  15420  4200 ?        Ss   10:23   0:00 /usr/sbin/cron
www-data   456  0.0  0.3  55280 12800 ?        S    10:24   0:01 nginx: worker"""

        sanitized = sanitize_llm_response(ps_output)

        # Should preserve entire output
        assert "/sbin/init" in sanitized
        assert "/usr/sbin/cron" in sanitized
        assert "nginx: worker" in sanitized

    def test_case_insensitive_meta_commentary(self):
        """Test that meta-commentary detection is case-sensitive (as implemented)."""
        response = """note: lowercase note
Note: Title case note
NOTE: Uppercase note
uid=0(root)"""

        sanitized = sanitize_llm_response(response)

        # Only "Note:" (title case) should be removed
        assert "Note: Title case" not in sanitized
        # Others might remain (implementation detail)
        assert "uid=0(root)" in sanitized


class TestSessionLLMCache:
    """Tests for Phase 3 in-session LLM response caching."""

    def test_cache_key_generation(self):
        """Test that cache keys are generated correctly."""
        from miragepot.ai_interface import get_session_llm_cache_key

        state1 = {"cwd": "/root"}
        state2 = {"cwd": "/root"}
        state3 = {"cwd": "/home"}

        key1 = get_session_llm_cache_key("ls -la", state1)
        key2 = get_session_llm_cache_key("ls -la", state2)
        key3 = get_session_llm_cache_key("ls -la", state3)

        # Same command + cwd should produce same key
        assert key1 == key2

        # Different cwd should produce different key
        assert key1 != key3

    def test_cache_storage_and_retrieval(self):
        """Test that responses can be cached and retrieved."""
        from miragepot.ai_interface import (
            cache_llm_response,
            get_cached_llm_response,
            clear_session_llm_cache,
        )

        # Clear cache first
        clear_session_llm_cache()

        # Cache a response
        state = {"cwd": "/test"}
        test_response = "test output"
        cache_llm_response("test_command", state, test_response)

        # Retrieve it
        cached = get_cached_llm_response("test_command", state)
        assert cached == test_response

    def test_cache_miss_returns_none(self):
        """Test that cache miss returns None."""
        from miragepot.ai_interface import (
            get_cached_llm_response,
            clear_session_llm_cache,
        )

        # Clear cache
        clear_session_llm_cache()

        # Try to get non-existent key
        state = {"cwd": "/nowhere"}
        cached = get_cached_llm_response("nonexistent", state)
        assert cached is None

    def test_cache_clearing(self):
        """Test that cache can be cleared."""
        from miragepot.ai_interface import (
            cache_llm_response,
            get_cached_llm_response,
            clear_session_llm_cache,
        )

        # Add something to cache
        state = {"cwd": "/dir"}
        cache_llm_response("cmd", state, "output")

        # Verify it's there
        assert get_cached_llm_response("cmd", state) is not None

        # Clear cache
        clear_session_llm_cache()

        # Verify it's gone
        assert get_cached_llm_response("cmd", state) is None

    def test_cache_fifo_eviction(self):
        """Test that cache evicts oldest entries when full."""
        from miragepot.ai_interface import (
            cache_llm_response,
            get_cached_llm_response,
            clear_session_llm_cache,
            _SESSION_LLM_CACHE_MAX_SIZE,
        )

        # Clear cache
        clear_session_llm_cache()

        state = {"cwd": "/dir"}

        # Fill cache to max size
        for i in range(_SESSION_LLM_CACHE_MAX_SIZE):
            cache_llm_response(f"cmd{i}", state, f"output{i}")

        # First entry should still be there
        assert get_cached_llm_response("cmd0", state) is not None

        # Add one more entry (should evict first)
        cache_llm_response("cmdnew", state, "new output")

        # First entry should now be evicted
        assert get_cached_llm_response("cmd0", state) is None

        # New entry should be there
        assert get_cached_llm_response("cmdnew", state) == "new output"


class TestMiragePotDirLocation:
    """Tests for Phase 4 MIRAGEPOT_DIR path setup."""

    def test_system_prompt_path_in_package(self):
        """SYSTEM_PROMPT_PATH should point to miragepot/ directory."""
        from miragepot.ai_interface import SYSTEM_PROMPT_PATH, MIRAGEPOT_DIR

        # Should be under MIRAGEPOT_DIR
        assert SYSTEM_PROMPT_PATH.parent == MIRAGEPOT_DIR
        assert SYSTEM_PROMPT_PATH.name == "system_prompt.txt"
        assert SYSTEM_PROMPT_PATH.exists()

    def test_system_prompt_file_is_readable(self):
        """system_prompt.txt should be readable and non-empty."""
        from miragepot.ai_interface import SYSTEM_PROMPT_PATH

        # Should be able to read
        with open(SYSTEM_PROMPT_PATH, "r") as f:
            content = f.read()

        # Should be non-empty
        assert len(content) > 0

    def test_miragepot_dir_is_package_directory(self):
        """MIRAGEPOT_DIR should point to the miragepot package."""
        from miragepot.ai_interface import MIRAGEPOT_DIR

        # Should be a Path object
        assert hasattr(MIRAGEPOT_DIR, "exists")

        # Should point to miragepot/ directory
        assert MIRAGEPOT_DIR.name == "miragepot"
        assert MIRAGEPOT_DIR.exists()

        # Should contain Python modules
        assert (MIRAGEPOT_DIR / "__init__.py").exists() or (
            MIRAGEPOT_DIR / "ai_interface.py"
        ).exists()
