"""
SQLite-based tool call tracker for GhidraMCP.

This module provides thread-safe tracking of MCP tool calls using SQLite.
The database is created in the caller's current working directory to enable
per-project tracking of tool usage.
"""

import sqlite3
import os
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)


class ToolTracker:
    """
    Thread-safe SQLite-based tracker for MCP tool calls.

    The tracker records how many times each tool is called and persists
    the data to a SQLite database. SQLite's built-in ACID properties
    ensure thread-safety for concurrent access.
    """

    def __init__(self, tool_names: List[str], db_path: Optional[str] = None):
        """
        Initialize the tool tracker.

        Args:
            tool_names: List of all available tool names to track
            db_path: Optional path to the database file. If None, creates
                    'tool_stats.db' in the caller's current working directory.
        """
        # Default to caller's current working directory
        if db_path is None:
            db_path = os.path.join(os.getcwd(), "tool_stats.db")

        self.db_path = db_path
        logger.info(f"Initializing ToolTracker with database at: {self.db_path}")

        self._init_db(tool_names)

    def _init_db(self, tool_names: List[str]):
        """
        Initialize the database schema and tool names.

        Creates the tool_calls table if it doesn't exist and inserts
        all tool names with an initial count of 0.

        Args:
            tool_names: List of tool names to initialize
        """
        try:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                # Create table if it doesn't exist
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tool_calls (
                        tool_name TEXT PRIMARY KEY,
                        call_count INTEGER DEFAULT 0
                    )
                """)

                # Initialize all tool names to 0 if not already present
                for tool_name in tool_names:
                    conn.execute("""
                        INSERT OR IGNORE INTO tool_calls (tool_name, call_count)
                        VALUES (?, 0)
                    """, (tool_name,))

                conn.commit()
                logger.info(f"Initialized tracking for {len(tool_names)} tools")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            # Don't raise - tracking failures shouldn't break the server

    def increment(self, tool_name: str):
        """
        Atomically increment the call count for a tool.

        Uses SQLite's UPSERT functionality (INSERT ... ON CONFLICT) to
        safely increment the counter even under concurrent access.

        Args:
            tool_name: Name of the tool to increment
        """
        try:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                conn.execute("""
                    INSERT INTO tool_calls (tool_name, call_count)
                    VALUES (?, 1)
                    ON CONFLICT(tool_name)
                    DO UPDATE SET call_count = call_count + 1
                """, (tool_name,))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to track call for tool '{tool_name}': {e}")
            # Don't raise - tracking failures shouldn't break tool execution

    def get_stats(self) -> List[tuple]:
        """
        Retrieve current statistics for all tools.

        Returns:
            List of (tool_name, call_count) tuples ordered by call count descending
        """
        try:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                cursor = conn.execute("""
                    SELECT tool_name, call_count
                    FROM tool_calls
                    ORDER BY call_count DESC, tool_name ASC
                """)
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to retrieve stats: {e}")
            return []

    def reset_stats(self):
        """
        Reset all call counts to zero.

        Useful for starting fresh tracking sessions.
        """
        try:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                conn.execute("UPDATE tool_calls SET call_count = 0")
                conn.commit()
                logger.info("Reset all tool call statistics")
        except Exception as e:
            logger.error(f"Failed to reset stats: {e}")
