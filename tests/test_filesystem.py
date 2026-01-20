"""Tests for filesystem metadata and commands."""

import pytest
import time
from miragepot.filesystem import (
    FileMetadata,
    create_default_metadata,
    init_filesystem_metadata,
    format_stat_output,
    handle_stat_command,
    handle_chmod_command,
    handle_chown_command,
    handle_find_command,
    USERS,
    GROUPS,
)
from miragepot.command_handler import init_session_state, handle_command


class TestFileMetadata:
    """Tests for FileMetadata dataclass."""

    def test_default_values(self):
        """FileMetadata initializes with defaults."""
        meta = FileMetadata()
        assert meta.mode == 0o644
        assert meta.is_dir is False
        assert meta.uid == 0
        assert meta.owner == "root"

    def test_directory_defaults(self):
        """Directory metadata has correct defaults."""
        meta = FileMetadata(is_dir=True)
        assert meta.mode == 0o755  # Default dir permissions
        assert meta.nlink == 2  # . and ..

    def test_format_mode_string_file(self):
        """File mode string is formatted correctly."""
        meta = FileMetadata(mode=0o644)
        assert meta.format_mode_string() == "-rw-r--r--"

    def test_format_mode_string_dir(self):
        """Directory mode string is formatted correctly."""
        meta = FileMetadata(mode=0o755, is_dir=True)
        assert meta.format_mode_string() == "drwxr-xr-x"

    def test_format_mode_string_executable(self):
        """Executable file mode string is formatted correctly."""
        meta = FileMetadata(mode=0o755)
        assert meta.format_mode_string() == "-rwxr-xr-x"

    def test_format_mode_string_restricted(self):
        """Restricted permissions are formatted correctly."""
        meta = FileMetadata(mode=0o600)
        assert meta.format_mode_string() == "-rw-------"

    def test_format_ls_long(self):
        """ls -l format output is correct."""
        meta = FileMetadata(
            mode=0o644,
            owner="root",
            group="root",
            size=1234,
            nlink=1,
            mtime=time.time(),
        )
        output = meta.format_ls_long("test.txt")
        assert "-rw-r--r--" in output
        assert "root" in output
        assert "1234" in output
        assert "test.txt" in output

    def test_to_dict(self):
        """FileMetadata converts to dict correctly."""
        meta = FileMetadata(mode=0o755, is_dir=True, owner="admin")
        d = meta.to_dict()
        assert d["mode"] == "0o755"
        assert d["is_dir"] is True
        assert d["owner"] == "admin"

    def test_timestamps_auto_generated(self):
        """Timestamps are auto-generated if not provided."""
        meta = FileMetadata()
        assert meta.mtime > 0
        assert meta.atime > 0
        assert meta.ctime > 0
        assert meta.inode > 0


class TestCreateDefaultMetadata:
    """Tests for create_default_metadata helper."""

    def test_file_with_content(self):
        """File size is calculated from content."""
        meta = create_default_metadata(content="hello world")
        assert meta.size == 11
        assert meta.is_dir is False

    def test_directory(self):
        """Directory has correct defaults."""
        meta = create_default_metadata(is_dir=True)
        assert meta.size == 4096
        assert meta.is_dir is True
        assert meta.mode == 0o755

    def test_custom_owner(self):
        """Custom owner is set correctly."""
        meta = create_default_metadata(owner="www-data", group="www-data")
        assert meta.owner == "www-data"
        assert meta.group == "www-data"


class TestInitFilesystemMetadata:
    """Tests for filesystem metadata initialization."""

    def test_returns_dict(self):
        """Returns a dictionary of metadata."""
        metadata = init_filesystem_metadata()
        assert isinstance(metadata, dict)
        assert len(metadata) > 0

    def test_root_exists(self):
        """Root directory exists."""
        metadata = init_filesystem_metadata()
        assert "/" in metadata
        assert metadata["/"].is_dir is True

    def test_tmp_writable(self):
        """Temp directory has sticky bit."""
        metadata = init_filesystem_metadata()
        assert "/tmp" in metadata
        assert metadata["/tmp"].mode == 0o1777

    def test_user_dirs_owned_correctly(self):
        """User directories have correct ownership."""
        metadata = init_filesystem_metadata()
        assert metadata["/root"].owner == "root"
        assert metadata["/home/user"].owner == "user"


class TestStatCommand:
    """Tests for stat command handling."""

    def test_stat_file(self):
        """stat command works for files."""
        state = init_session_state()
        output = handle_stat_command("/etc/passwd", state)
        assert "File: /etc/passwd" in output
        assert "regular file" in output
        assert "Uid:" in output
        assert "Access:" in output
        assert "Modify:" in output

    def test_stat_directory(self):
        """stat command works for directories."""
        state = init_session_state()
        output = handle_stat_command("/root", state)
        assert "File: /root" in output
        assert "directory" in output

    def test_stat_nonexistent(self):
        """stat command handles nonexistent files."""
        state = init_session_state()
        output = handle_stat_command("/nonexistent", state)
        assert "No such file or directory" in output

    def test_stat_missing_operand(self):
        """stat command handles missing operand."""
        state = init_session_state()
        output = handle_stat_command("", state)
        assert "missing operand" in output


class TestChmodCommand:
    """Tests for chmod command handling."""

    def test_chmod_numeric(self):
        """chmod with numeric mode works."""
        state = init_session_state()
        # First create a file
        handle_command("touch /root/test.txt", state)
        output = handle_chmod_command("755 /root/test.txt", state)
        assert output == ""

        # Verify the change
        meta = state["file_metadata"].get("/root/test.txt")
        assert meta is not None
        assert meta.mode == 0o755

    def test_chmod_nonexistent(self):
        """chmod handles nonexistent files."""
        state = init_session_state()
        output = handle_chmod_command("755 /nonexistent", state)
        assert "No such file or directory" in output

    def test_chmod_missing_operand(self):
        """chmod handles missing operand."""
        state = init_session_state()
        output = handle_chmod_command("755", state)
        assert "missing operand" in output


class TestChownCommand:
    """Tests for chown command handling."""

    def test_chown_user(self):
        """chown changes owner."""
        state = init_session_state()
        handle_command("touch /root/test.txt", state)
        output = handle_chown_command("user /root/test.txt", state)
        assert output == ""

        meta = state["file_metadata"].get("/root/test.txt")
        assert meta.owner == "user"
        assert meta.uid == 1000

    def test_chown_user_group(self):
        """chown changes owner and group."""
        state = init_session_state()
        handle_command("touch /root/test.txt", state)
        output = handle_chown_command("www-data:www-data /root/test.txt", state)
        assert output == ""

        meta = state["file_metadata"].get("/root/test.txt")
        assert meta.owner == "www-data"
        assert meta.group == "www-data"

    def test_chown_invalid_user(self):
        """chown handles invalid user."""
        state = init_session_state()
        handle_command("touch /root/test.txt", state)
        output = handle_chown_command("invaliduser /root/test.txt", state)
        assert "invalid user" in output


class TestFindCommand:
    """Tests for find command handling."""

    def test_find_basic(self):
        """Basic find lists all files."""
        state = init_session_state()
        output = handle_find_command("/root", state)
        assert "/root" in output

    def test_find_by_name(self):
        """find -name filters by name."""
        state = init_session_state()
        output = handle_find_command("/root -name notes", state)
        assert "notes.txt" in output

    def test_find_type_directory(self):
        """find -type d filters directories."""
        state = init_session_state()
        output = handle_find_command("/ -type d -name var", state)
        assert "/var" in output
        # Should not include files
        assert ".txt" not in output

    def test_find_type_file(self):
        """find with -type f shows only files."""
        state = init_session_state()
        output = handle_find_command("/root -type f", state)
        # Should include files, verify these are actual file paths (not directories)
        lines = output.strip().split("\n") if output.strip() else []
        assert len(lines) > 0, "Should find at least one file"
        for line in lines:
            if line:
                # Should be a file path (absolute path starting with /root)
                assert line.startswith("/root"), (
                    f"Expected path under /root, got: {line}"
                )
                # Should not be a directory (we check that the output contains files)
                # Files we know exist: notes.txt, passwords.txt, .aws/credentials, .aws/config
                assert any(
                    line.endswith(ext) for ext in [".txt", "/credentials", "/config"]
                ), f"Unexpected file in output: {line}"

    def test_find_nonexistent_dir(self):
        """find handles nonexistent directory."""
        state = init_session_state()
        output = handle_find_command("/nonexistent", state)
        assert "No such file or directory" in output


class TestLsWithMetadata:
    """Tests for ls command with metadata integration."""

    def test_ls_long_shows_permissions(self):
        """ls -l shows permission strings."""
        state = init_session_state()
        output = handle_command("ls -la /etc", state)
        lines = output.split("\n")
        # Should have permission strings
        for line in lines[1:]:  # Skip "total" line
            if line.strip():
                assert line[0] in "-d"  # File or directory

    def test_ls_long_shows_owner(self):
        """ls -l shows owner information."""
        state = init_session_state()
        output = handle_command("ls -l /root", state)
        assert "root" in output

    def test_ls_long_shows_size(self):
        """ls -l shows file sizes."""
        state = init_session_state()
        output = handle_command("ls -l /root", state)
        # Should have numeric sizes
        assert any(c.isdigit() for c in output)


class TestIntegration:
    """Integration tests for filesystem features."""

    def test_create_file_then_stat(self):
        """Creating a file and stat-ing it works."""
        state = init_session_state()
        handle_command("echo 'test content' > /root/newfile.txt", state)
        output = handle_command("stat /root/newfile.txt", state)
        assert "File: /root/newfile.txt" in output

    def test_chmod_then_ls(self):
        """chmod changes are reflected in ls."""
        state = init_session_state()
        handle_command("touch /root/script.sh", state)
        handle_command("chmod 755 /root/script.sh", state)
        output = handle_command("ls -l /root/script.sh", state)
        assert "rwxr-xr-x" in output

    def test_find_created_files(self):
        """find includes dynamically created files."""
        state = init_session_state()
        handle_command("touch /tmp/testfile.txt", state)
        output = handle_command("find /tmp -name testfile.txt", state)
        assert "/tmp/testfile.txt" in output
