"""
Test suite for the ToolTracker class.

Tests the SQLite-based tool call tracking functionality including
database initialization, concurrent access, and statistics retrieval.
"""

import pytest
import os
import sqlite3
import tempfile
import threading
import sys

# Add parent directory to path to import tool_tracker
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tool_tracker import ToolTracker


class TestToolTracker:
    """Test suite for the ToolTracker class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            yield tmpdir
            os.chdir(old_cwd)

    @pytest.fixture
    def sample_tools(self):
        """Sample tool names for testing."""
        return ["list_methods", "decompile_function", "rename_function"]

    def test_initialization(self, temp_dir, sample_tools):
        """Test that ToolTracker initializes database correctly."""
        tracker = ToolTracker(sample_tools)

        # Check database file exists
        db_path = os.path.join(temp_dir, "tool_stats.db")
        assert os.path.exists(db_path), "Database file should be created"

        # Verify table structure
        with sqlite3.connect(db_path) as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='tool_calls'"
            )
            assert cursor.fetchone() is not None, "tool_calls table should exist"

    def test_initial_counts_are_zero(self, temp_dir, sample_tools):
        """Test that all tools start with count 0."""
        tracker = ToolTracker(sample_tools)
        stats = tracker.get_stats()

        assert len(stats) == len(sample_tools), "Should have all tools in stats"
        for tool_name, count in stats:
            assert count == 0, f"{tool_name} should start with count 0"

    def test_increment_single_tool(self, temp_dir, sample_tools):
        """Test incrementing a single tool's count."""
        tracker = ToolTracker(sample_tools)

        tracker.increment("list_methods")

        stats_dict = dict(tracker.get_stats())
        assert stats_dict["list_methods"] == 1, "Count should be incremented to 1"
        assert stats_dict["decompile_function"] == 0, "Other tools should remain 0"

    def test_increment_multiple_times(self, temp_dir, sample_tools):
        """Test incrementing the same tool multiple times."""
        tracker = ToolTracker(sample_tools)

        for _ in range(5):
            tracker.increment("decompile_function")

        stats_dict = dict(tracker.get_stats())
        assert stats_dict["decompile_function"] == 5, "Count should be 5 after 5 increments"

    def test_increment_multiple_tools(self, temp_dir, sample_tools):
        """Test incrementing different tools."""
        tracker = ToolTracker(sample_tools)

        tracker.increment("list_methods")
        tracker.increment("list_methods")
        tracker.increment("decompile_function")
        tracker.increment("rename_function")

        stats_dict = dict(tracker.get_stats())
        assert stats_dict["list_methods"] == 2
        assert stats_dict["decompile_function"] == 1
        assert stats_dict["rename_function"] == 1

    def test_persistence_across_instances(self, temp_dir, sample_tools):
        """Test that data persists when creating a new tracker instance."""
        # First tracker
        tracker1 = ToolTracker(sample_tools)
        tracker1.increment("list_methods")
        tracker1.increment("list_methods")
        del tracker1

        # Second tracker (should read existing database)
        tracker2 = ToolTracker(sample_tools)
        stats_dict = dict(tracker2.get_stats())
        assert stats_dict["list_methods"] == 2, "Data should persist across instances"

    def test_custom_database_path(self, temp_dir):
        """Test creating tracker with custom database path."""
        custom_path = os.path.join(temp_dir, "custom_stats.db")
        tools = ["test_tool"]

        tracker = ToolTracker(tools, db_path=custom_path)
        tracker.increment("test_tool")

        assert os.path.exists(custom_path), "Custom database path should be created"

    def test_concurrent_increments(self, temp_dir):
        """Test thread-safety with concurrent increments."""
        tools = ["concurrent_tool"]
        tracker = ToolTracker(tools)

        def increment_many(count):
            for _ in range(count):
                tracker.increment("concurrent_tool")

        # Create 5 threads, each incrementing 20 times
        threads = []
        for _ in range(5):
            t = threading.Thread(target=increment_many, args=(20,))
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        stats_dict = dict(tracker.get_stats())
        assert stats_dict["concurrent_tool"] == 100, "Should handle concurrent increments correctly"

    def test_stats_ordering(self, temp_dir, sample_tools):
        """Test that get_stats returns results ordered by count (descending)."""
        tracker = ToolTracker(sample_tools)

        tracker.increment("rename_function")
        tracker.increment("rename_function")
        tracker.increment("rename_function")
        tracker.increment("list_methods")
        tracker.increment("list_methods")

        stats = tracker.get_stats()

        # First entry should be rename_function with 3 calls
        assert stats[0] == ("rename_function", 3)
        # Second should be list_methods with 2 calls
        assert stats[1] == ("list_methods", 2)

    def test_reset_stats(self, temp_dir, sample_tools):
        """Test resetting all statistics to zero."""
        tracker = ToolTracker(sample_tools)

        # Increment some tools
        tracker.increment("list_methods")
        tracker.increment("decompile_function")

        # Reset
        tracker.reset_stats()

        # Check all are zero
        stats = tracker.get_stats()
        for tool_name, count in stats:
            assert count == 0, f"{tool_name} should be 0 after reset"

    def test_increment_nonexistent_tool(self, temp_dir, sample_tools):
        """Test that incrementing a non-existent tool doesn't crash."""
        tracker = ToolTracker(sample_tools)

        # Should not raise an exception
        tracker.increment("nonexistent_tool")

        # The tool should now exist in the database
        stats_dict = dict(tracker.get_stats())
        assert "nonexistent_tool" in stats_dict
        assert stats_dict["nonexistent_tool"] == 1

    def test_empty_tool_list(self, temp_dir):
        """Test initialization with an empty tool list."""
        tracker = ToolTracker([])

        stats = tracker.get_stats()
        assert len(stats) == 0, "Stats should be empty for empty tool list"

    def test_database_timeout_setting(self, temp_dir, sample_tools):
        """Test that database operations use the timeout setting."""
        tracker = ToolTracker(sample_tools)

        # This test verifies the tracker was created successfully
        # The actual timeout is used internally and hard to test directly
        # without causing actual blocking conditions
        assert tracker.db_path is not None
        assert os.path.exists(tracker.db_path)

    def test_increment_error_handling(self, temp_dir, sample_tools, monkeypatch):
        """Test that increment errors are handled gracefully."""
        tracker = ToolTracker(sample_tools)

        # Mock sqlite3.connect to raise an exception
        def mock_connect(*args, **kwargs):
            raise sqlite3.Error("Simulated database error")

        monkeypatch.setattr(sqlite3, "connect", mock_connect)

        # Should not raise an exception (logs warning instead)
        tracker.increment("list_methods")

    def test_get_stats_error_handling(self, temp_dir, sample_tools, monkeypatch):
        """Test that get_stats errors are handled gracefully."""
        tracker = ToolTracker(sample_tools)

        # Mock sqlite3.connect to raise an exception
        def mock_connect(*args, **kwargs):
            raise sqlite3.Error("Simulated database error")

        monkeypatch.setattr(sqlite3, "connect", mock_connect)

        # Should return empty list instead of raising
        stats = tracker.get_stats()
        assert stats == []
