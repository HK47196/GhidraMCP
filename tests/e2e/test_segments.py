"""End-to-end tests for segments query operations"""

import pytest
from bridge_mcp_ghidra import query


class TestSegmentsQuery:
    """Test segments query operations"""

    def test_query_segments_basic(self, ghidra_server):
        """Test listing all segments"""
        result = query(type="segments", limit=100)

        # Result is a list of lines
        assert isinstance(result, list)
        assert len(result) > 0, "Expected at least one segment"

        # Join to check content
        text = "\n".join(result)
        assert not text.startswith("Error"), f"Expected valid result, got: {text[:200]}"

    def test_query_segments_format(self, ghidra_server):
        """Test that segments are formatted correctly"""
        result = query(type="segments", limit=10)

        assert isinstance(result, list)
        assert len(result) > 0

        # Each segment should have format "NAME: START - END"
        for segment in result:
            assert ":" in segment, f"Expected colon in segment format: {segment}"
            assert " - " in segment, f"Expected ' - ' in segment format: {segment}"

    def test_query_segments_search_by_name(self, ghidra_server):
        """Test searching segments by name"""
        # First get all segments
        all_segments = query(type="segments", limit=100)
        assert isinstance(all_segments, list)
        assert len(all_segments) > 0

        # Extract the first segment name
        first_segment = all_segments[0]
        segment_name = first_segment.split(":")[0].strip()

        # Search for that segment name
        result = query(type="segments", search=segment_name, limit=100)

        assert isinstance(result, list)
        assert len(result) > 0, f"Expected to find segment matching '{segment_name}'"

        # All results should contain the search term in the segment name
        for segment in result:
            name_part = segment.split(":")[0].strip().lower()
            assert segment_name.lower() in name_part, \
                f"Segment name '{name_part}' should contain search term '{segment_name}'"

    def test_query_segments_search_case_insensitive(self, ghidra_server):
        """Test that segment search is case insensitive"""
        # Get all segments
        all_segments = query(type="segments", limit=100)
        assert isinstance(all_segments, list)
        assert len(all_segments) > 0

        # Get a segment name with letters
        segment_name = None
        for segment in all_segments:
            name = segment.split(":")[0].strip()
            if any(c.isalpha() for c in name):
                segment_name = name
                break

        if segment_name is None:
            pytest.skip("No segment with alphabetic characters found")

        # Search with different cases
        result_lower = query(type="segments", search=segment_name.lower(), limit=100)
        result_upper = query(type="segments", search=segment_name.upper(), limit=100)

        assert isinstance(result_lower, list)
        assert isinstance(result_upper, list)

        # Both should return the same results
        assert len(result_lower) == len(result_upper), \
            f"Case insensitive search failed: lower={len(result_lower)}, upper={len(result_upper)}"

    def test_query_segments_search_filters_correctly(self, ghidra_server):
        """Test that search filters on segment name, not addresses"""
        # Get all segments
        all_segments = query(type="segments", limit=100)
        assert isinstance(all_segments, list)
        assert len(all_segments) > 0

        # Search for a common hex digit that appears in addresses but likely not in names
        # This verifies the fix for filtering on name only, not addresses
        result = query(type="segments", search="fff", limit=100)

        # If we got results, verify they actually contain "fff" in the name
        if isinstance(result, list) and len(result) > 0:
            for segment in result:
                if segment.startswith("Error"):
                    continue
                name_part = segment.split(":")[0].strip().lower()
                assert "fff" in name_part, \
                    f"Search should filter on segment name only, but matched: {segment}"

    def test_query_segments_search_no_false_positives_on_addresses(self, ghidra_server):
        """Test that searching for address patterns doesn't match all segments"""
        # Get all segments
        all_segments = query(type="segments", limit=100)
        assert isinstance(all_segments, list)

        if len(all_segments) <= 1:
            pytest.skip("Need multiple segments to test false positive filtering")

        # Search for "00" which commonly appears in addresses
        result = query(type="segments", search="00", limit=100)

        assert isinstance(result, list)

        # Count segments that actually have "00" in their name
        segments_with_00_in_name = 0
        for segment in all_segments:
            name_part = segment.split(":")[0].strip().lower()
            if "00" in name_part:
                segments_with_00_in_name += 1

        # The result count should match segments with "00" in name, not all segments
        if segments_with_00_in_name == 0:
            # If no segments have "00" in name, we should get no results
            assert len(result) == 0, \
                f"Expected 0 results (no segments have '00' in name), got {len(result)}"
        else:
            # Result count should match only segments with "00" in name
            assert len(result) == segments_with_00_in_name, \
                f"Expected {segments_with_00_in_name} results, got {len(result)}"

    def test_query_segments_search_partial_match(self, ghidra_server):
        """Test that partial segment names match"""
        # Get all segments
        all_segments = query(type="segments", limit=100)
        assert isinstance(all_segments, list)
        assert len(all_segments) > 0

        # Get a segment name with at least 3 characters
        segment_name = None
        for segment in all_segments:
            name = segment.split(":")[0].strip()
            if len(name) >= 3:
                segment_name = name
                break

        if segment_name is None:
            pytest.skip("No segment with name length >= 3 found")

        # Search with partial name (first 2 characters)
        partial = segment_name[:2]
        result = query(type="segments", search=partial, limit=100)

        assert isinstance(result, list)
        assert len(result) > 0, f"Expected to find segments matching partial name '{partial}'"

        # Original segment should be in results
        found = False
        for segment in result:
            if segment_name in segment:
                found = True
                break
        assert found, f"Expected to find segment '{segment_name}' with partial search '{partial}'"

    def test_query_segments_search_empty_string_error(self, ghidra_server):
        """Test that empty search string returns error"""
        result = query(type="segments", search="", limit=100)

        assert isinstance(result, list)
        assert len(result) == 1
        assert "Error" in result[0]
        assert "query string is required" in result[0]

    def test_query_segments_search_no_match(self, ghidra_server):
        """Test searching for non-existent segment name"""
        result = query(type="segments", search="NONEXISTENT_SEGMENT_XYZ123", limit=100)

        assert isinstance(result, list)
        # Should return empty list or no results
        assert len(result) == 0 or result == [""]

    def test_query_segments_pagination(self, ghidra_server):
        """Test segments query with pagination"""
        # Get all segments
        all_segments = query(type="segments", limit=100)

        if len(all_segments) <= 1:
            pytest.skip("Need multiple segments to test pagination")

        # Get first segment
        result1 = query(type="segments", offset=0, limit=1)
        # Get second segment
        result2 = query(type="segments", offset=1, limit=1)

        assert isinstance(result1, list)
        assert isinstance(result2, list)
        assert len(result1) == 1

        if len(result2) > 0:
            assert result1[0] != result2[0], "Pagination should return different segments"

    def test_query_segments_search_with_pagination(self, ghidra_server):
        """Test segments search with pagination parameters"""
        # Get all segments
        all_segments = query(type="segments", limit=100)
        assert isinstance(all_segments, list)
        assert len(all_segments) > 0

        # Get a segment name
        segment_name = all_segments[0].split(":")[0].strip()

        # Search with pagination
        result = query(type="segments", search=segment_name, offset=0, limit=10)

        assert isinstance(result, list)
        # Should respect limit
        assert len(result) <= 10

    def test_query_segments_search_numeric_string(self, ghidra_server):
        """Test searching with numeric string"""
        # This tests that numeric searches work correctly
        result = query(type="segments", search="1", limit=100)

        assert isinstance(result, list)

        # All results should have "1" in segment name
        for segment in result:
            if segment.startswith("Error"):
                continue
            name_part = segment.split(":")[0].strip()
            assert "1" in name_part, \
                f"Segment name '{name_part}' should contain '1'"

    def test_query_segments_search_special_characters(self, ghidra_server):
        """Test searching with special characters like underscore or dot"""
        # Get all segments to find one with special chars
        all_segments = query(type="segments", limit=100)
        assert isinstance(all_segments, list)

        # Try searching for underscore (common in segment names like CODE_70)
        result = query(type="segments", search="_", limit=100)
        assert isinstance(result, list)

        # All results should have underscore in name
        for segment in result:
            if segment.startswith("Error"):
                continue
            name_part = segment.split(":")[0].strip()
            assert "_" in name_part, \
                f"Segment name '{name_part}' should contain '_'"
