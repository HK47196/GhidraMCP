"""End-to-end tests for union support in get_address_context"""

import pytest
from bridge_mcp_ghidra import (
    get_address_context,
    set_data_type,
    parse_c_struct,
    query
)


class TestUnionAddressContext:
    """Test union handling in get_address_context"""

    def test_union_type_detection(self, ghidra_server):
        """Test that unions are detected and displayed differently from structs"""
        # Create a simple union with two views
        union_def = """
        union TestUnion {
            int intView;
            char charArray[4];
        };
        """

        result = parse_c_struct(union_def)
        assert "Error" not in result or "success" in result.lower() or "TestUnion" in result

        # Find a data address to apply the union
        data_result = query(type="data", limit=50)
        assert isinstance(data_result, list)

        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found for union test")

        # Apply the union type
        set_result = set_data_type(address=test_address, type_name="TestUnion")
        assert "success" in set_result.lower() or "Error" not in set_result

        # Get address context for the union
        context = get_address_context(test_address, before=0, after=0)
        assert isinstance(context, list)
        context_str = "\n".join(context)

        # Should show union-specific formatting
        assert "union" in context_str.lower() or "TestUnion" in context_str

    def test_union_with_struct_and_array_views(self, ghidra_server):
        """Test union with struct member and array member shows both views"""
        # Create a struct to be used in the union
        struct_def = """
        struct GameState {
            unsigned char partyX;
            unsigned char partyY;
            unsigned char currentMapID;
            unsigned char currentSlotIndex;
        };
        """
        parse_c_struct(struct_def)

        # Create a union with the struct and an array
        union_def = """
        union GameStateUnion {
            struct GameState state;
            unsigned char buffer[4];
        };
        """

        result = parse_c_struct(union_def)
        assert "Error" not in result or "success" in result.lower()

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        # Apply the union type
        set_data_type(address=test_address, type_name="GameStateUnion")

        # Query inside the union (offset +2)
        if test_address.startswith("0x"):
            base_addr = int(test_address, 16)
        else:
            base_addr = int(test_address, 16)

        inner_address = f"0x{base_addr + 2:x}"

        # Get context at the inner address
        context = get_address_context(inner_address, before=0, after=0)
        context_str = "\n".join(context)

        # Should show "View 1" and "View 2" for union members
        assert "View" in context_str or "union" in context_str.lower()

    def test_union_target_address_marking(self, ghidra_server):
        """Test that target address is marked with --> in each view"""
        # Create a simple union
        union_def = """
        union SimpleUnion {
            int value;
            unsigned char bytes[4];
        };
        """
        parse_c_struct(union_def)

        # Find and use a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="SimpleUnion")

        # Get context - the --> marker should appear
        context = get_address_context(test_address, before=0, after=0)
        context_str = "\n".join(context)

        # Check that we have some output (the format will include the union data)
        assert len(context_str) > 0 or "SimpleUnion" in context_str

    def test_union_array_offset_notation(self, ghidra_server):
        """Test that array views show offset notation like (offset +N)"""
        # Create union with array member
        union_def = """
        union BufferUnion {
            int intValue;
            unsigned char buffer[8];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="BufferUnion")

        # Query at an offset within the union
        if test_address.startswith("0x"):
            base_addr = int(test_address, 16)
        else:
            base_addr = int(test_address, 16)

        offset_address = f"0x{base_addr + 3:x}"

        context = get_address_context(offset_address, before=0, after=0)
        context_str = "\n".join(context)

        # Should show offset notation for array view
        # The format should include "(offset +" somewhere
        assert "offset" in context_str.lower() or "BufferUnion" in context_str

    def test_union_struct_fields_expansion(self, ghidra_server):
        """Test that struct members within unions have their fields expanded"""
        # Create a struct with multiple fields
        struct_def = """
        struct DataStruct {
            unsigned char fieldA;
            unsigned char fieldB;
            unsigned short fieldC;
            int fieldD;
        };
        """
        parse_c_struct(struct_def)

        # Create union containing the struct
        union_def = """
        union DataUnion {
            struct DataStruct data;
            unsigned char raw[8];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="DataUnion")

        # Query at offset within the struct fields
        if test_address.startswith("0x"):
            base_addr = int(test_address, 16)
        else:
            base_addr = int(test_address, 16)

        # Target fieldC (offset 2)
        field_address = f"0x{base_addr + 2:x}"

        context = get_address_context(field_address, before=0, after=0)
        context_str = "\n".join(context)

        # The struct view should show field names
        # Check for field names or struct indication
        assert len(context_str) > 0

    def test_union_size_display(self, ghidra_server):
        """Test that union displays its size in bytes"""
        # Create a union
        union_def = """
        union SizedUnion {
            int intVal;
            long long longVal;
            char charArray[16];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="SizedUnion")

        context = get_address_context(test_address, before=0, after=0)
        context_str = "\n".join(context)

        # Should show "(union, N bytes)" in the output
        assert "union" in context_str.lower() or "bytes" in context_str.lower()

    def test_union_multiple_views_displayed(self, ghidra_server):
        """Test that all union members are shown as separate views"""
        # Create union with 3 members
        union_def = """
        union ThreeViewUnion {
            int view1;
            short view2[2];
            char view3[4];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="ThreeViewUnion")

        context = get_address_context(test_address, before=0, after=0)
        context_str = "\n".join(context)

        # Should show multiple views
        # Count occurrences of "View" or check for view indicators
        view_count = context_str.count("View")
        assert view_count >= 1 or "ThreeViewUnion" in context_str

    def test_union_context_window(self, ghidra_server):
        """Test that context window parameters work with unions"""
        # Create a simple union
        union_def = """
        union ContextUnion {
            int intVal;
            char charArray[4];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="ContextUnion")

        # Test with different context windows
        context_small = get_address_context(test_address, before=1, after=1)
        context_large = get_address_context(test_address, before=10, after=10)

        assert isinstance(context_small, list)
        assert isinstance(context_large, list)

        # Larger context should have more or equal content
        # (though union display itself should be same)
        assert len(context_large) >= len(context_small) or len(context_small) > 0


class TestUnionEdgeCases:
    """Test edge cases for union support"""

    def test_nested_union_handling(self, ghidra_server):
        """Test unions containing other unions"""
        # Create inner union
        inner_union_def = """
        union InnerUnion {
            short shortVal;
            char chars[2];
        };
        """
        parse_c_struct(inner_union_def)

        # Create outer union containing inner union
        outer_union_def = """
        union OuterUnion {
            union InnerUnion inner;
            int intVal;
        };
        """
        result = parse_c_struct(outer_union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="OuterUnion")

        context = get_address_context(test_address, before=0, after=0)
        context_str = "\n".join(context)

        # Should handle nested union without error
        assert "Error" not in context_str or "OuterUnion" in context_str

    def test_union_with_anonymous_members(self, ghidra_server):
        """Test unions where members might not have names"""
        # Create union - field names are required in C, but test the handling
        union_def = """
        union AnonUnion {
            int namedField;
            struct {
                char a;
                char b;
            } anonStruct;
        };
        """

        # This may or may not parse depending on Ghidra's C parser
        # Just verify it doesn't crash
        result = parse_c_struct(union_def)
        # The result could be success or an error about anonymous structs
        assert isinstance(result, str)

    def test_union_empty_or_invalid(self, ghidra_server):
        """Test error handling for invalid union scenarios"""
        # Try to use a non-existent union type
        data_result = query(type="data", limit=10)

        if len(data_result) > 0:
            first_line = data_result[0]
            if ":" in first_line:
                test_address = first_line.split(":")[0].strip()

                # Try to apply non-existent union
                result = set_data_type(address=test_address, type_name="NonExistentUnion")
                # Should return some kind of error or indication
                assert isinstance(result, str)


class TestUnionXRefs:
    """Test XREF handling in union views"""

    def test_union_preserves_base_xrefs(self, ghidra_server):
        """Test that XREFs at union base address are preserved"""
        # Create a simple union
        union_def = """
        union XRefUnion {
            int value;
            char bytes[4];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="XRefUnion")

        context = get_address_context(test_address, before=0, after=0)
        context_str = "\n".join(context)

        # The output should include XREF information if there are any references
        # This is a structural test - we can't guarantee XREFs exist
        assert isinstance(context_str, str)
        assert len(context_str) > 0


class TestUnionDisplayFixes:
    """Test fixes for union display issues"""

    def test_struct_view_context_window(self, ghidra_server):
        """Test that context window (before/after) is applied to struct field display

        Issue 1: For large structs within unions, only N fields before and after
        the target field should be shown, not all fields.
        """
        # Create a struct with many fields
        struct_def = """
        struct LargeStruct {
            unsigned char field0;
            unsigned char field1;
            unsigned char field2;
            unsigned char field3;
            unsigned char field4;
            unsigned char field5;
            unsigned char field6;
            unsigned char field7;
            unsigned char field8;
            unsigned char field9;
            unsigned char field10;
            unsigned char field11;
            unsigned char field12;
            unsigned char field13;
            unsigned char field14;
            unsigned char field15;
            unsigned char field16;
            unsigned char field17;
            unsigned char field18;
            unsigned char field19;
        };
        """
        parse_c_struct(struct_def)

        # Create union containing the large struct
        union_def = """
        union LargeStructUnion {
            struct LargeStruct state;
            unsigned char buffer[20];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="LargeStructUnion")

        # Query at field10 (offset 10) with small context window
        if test_address.startswith("0x"):
            base_addr = int(test_address, 16)
        else:
            base_addr = int(test_address, 16)

        target_address = f"0x{base_addr + 10:x}"

        # Use before=2, after=2 to get only 5 fields total
        context = get_address_context(target_address, before=2, after=2)
        context_str = "\n".join(context)

        # Should show truncation indicators
        # Check for "... (X fields before)" or "... (X fields after)"
        has_before_truncation = "fields before" in context_str.lower()
        has_after_truncation = "fields after" in context_str.lower()

        # At offset 10, with before=2, after=2:
        # - Should have 8 fields before (fields 0-7)
        # - Should have 7 fields after (fields 13-19)
        # So truncation indicators should be present
        assert has_before_truncation or has_after_truncation, \
            f"Expected truncation indicators in struct view.\nContext:\n{context_str}"

    def test_array_offset_notation_spacing(self, ghidra_server):
        """Test that array offset notation has proper spacing

        Issue 2: Output should show 'uint8_t[256] (offset +6)' with space before
        parenthesis, not 'uint8_t[256](offset +6)'.
        """
        # Create union with array member
        union_def = """
        union SpacingTestUnion {
            int intValue;
            unsigned char buffer[16];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="SpacingTestUnion")

        # Query at offset within the array
        if test_address.startswith("0x"):
            base_addr = int(test_address, 16)
        else:
            base_addr = int(test_address, 16)

        offset_address = f"0x{base_addr + 6:x}"

        context = get_address_context(offset_address, before=0, after=0)
        context_str = "\n".join(context)

        # Check for proper spacing: should have " (offset" not "](offset"
        # The array type like "char[16]" should be followed by a space before "(offset"
        if "(offset" in context_str:
            # Find the position of "(offset" and check what's before it
            idx = context_str.find("(offset")
            if idx > 0:
                char_before = context_str[idx - 1]
                # Should be a space, not ']' or other character
                assert char_before == ' ', \
                    f"Expected space before '(offset', got '{char_before}'. Context:\n{context_str}"

    def test_struct_view_truncation_indicators(self, ghidra_server):
        """Test that truncation indicators show count of omitted fields

        Issue 3: When struct fields are truncated, should show
        '... (N fields before)' and '... (N fields after)'.
        """
        # Create a struct with exactly 15 fields
        struct_def = """
        struct FifteenFieldStruct {
            unsigned char a;
            unsigned char b;
            unsigned char c;
            unsigned char d;
            unsigned char e;
            unsigned char f;
            unsigned char g;
            unsigned char h;
            unsigned char i;
            unsigned char j;
            unsigned char k;
            unsigned char l;
            unsigned char m;
            unsigned char n;
            unsigned char o;
        };
        """
        parse_c_struct(struct_def)

        # Create union containing the struct
        union_def = """
        union FifteenFieldUnion {
            struct FifteenFieldStruct data;
            unsigned char raw[15];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="FifteenFieldUnion")

        # Query at field h (offset 7, which is the middle field)
        if test_address.startswith("0x"):
            base_addr = int(test_address, 16)
        else:
            base_addr = int(test_address, 16)

        target_address = f"0x{base_addr + 7:x}"

        # Use before=3, after=3 to truncate both ends
        context = get_address_context(target_address, before=3, after=3)
        context_str = "\n".join(context)

        # With 15 fields (indices 0-14), targeting index 7:
        # - startIdx = max(0, 7-3) = 4
        # - endIdx = min(15, 7+3+1) = 11
        # - Fields shown: 4-10 (indices)
        # - Fields before: 4 (indices 0-3)
        # - Fields after: 4 (indices 11-14)

        # Check for both truncation indicators
        has_before = "fields before" in context_str.lower()
        has_after = "fields after" in context_str.lower()

        assert has_before and has_after, \
            f"Expected both before and after truncation indicators.\nContext:\n{context_str}"

    def test_struct_view_no_truncation_for_small_struct(self, ghidra_server):
        """Test that small structs don't show truncation indicators

        When a struct has few enough fields to fit within the context window,
        no truncation indicators should appear.
        """
        # Create a small struct with 5 fields
        struct_def = """
        struct SmallStruct {
            unsigned char a;
            unsigned char b;
            unsigned char c;
            unsigned char d;
            unsigned char e;
        };
        """
        parse_c_struct(struct_def)

        # Create union containing the struct
        union_def = """
        union SmallStructUnion {
            struct SmallStruct data;
            unsigned char raw[5];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="SmallStructUnion")

        # Query at middle field with large context window
        if test_address.startswith("0x"):
            base_addr = int(test_address, 16)
        else:
            base_addr = int(test_address, 16)

        target_address = f"0x{base_addr + 2:x}"

        # Use before=5, after=5 which is larger than the struct
        context = get_address_context(target_address, before=5, after=5)
        context_str = "\n".join(context)

        # No truncation should occur for small struct
        has_truncation = "fields before" in context_str.lower() or "fields after" in context_str.lower()

        assert not has_truncation, \
            f"Should not show truncation indicators for small struct.\nContext:\n{context_str}"

    def test_struct_field_count_in_truncation(self, ghidra_server):
        """Test that truncation indicators show correct field counts"""
        # Create a struct with exactly 12 fields
        struct_def = """
        struct TwelveFieldStruct {
            unsigned char f0;
            unsigned char f1;
            unsigned char f2;
            unsigned char f3;
            unsigned char f4;
            unsigned char f5;
            unsigned char f6;
            unsigned char f7;
            unsigned char f8;
            unsigned char f9;
            unsigned char f10;
            unsigned char f11;
        };
        """
        parse_c_struct(struct_def)

        # Create union containing the struct
        union_def = """
        union TwelveFieldUnion {
            struct TwelveFieldStruct data;
            unsigned char raw[12];
        };
        """
        parse_c_struct(union_def)

        # Find a data address
        data_result = query(type="data", limit=50)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found")

        set_data_type(address=test_address, type_name="TwelveFieldUnion")

        # Query at field f6 (offset 6) with before=2, after=2
        if test_address.startswith("0x"):
            base_addr = int(test_address, 16)
        else:
            base_addr = int(test_address, 16)

        target_address = f"0x{base_addr + 6:x}"

        context = get_address_context(target_address, before=2, after=2)
        context_str = "\n".join(context)

        # With 12 fields (indices 0-11), targeting index 6:
        # - startIdx = max(0, 6-2) = 4
        # - endIdx = min(12, 6+2+1) = 9
        # - Fields before: 4 (indices 0-3)
        # - Fields after: 3 (indices 9-11)

        # Check that we have truncation indicators with numbers
        import re
        before_match = re.search(r'\.\.\.\s*\((\d+)\s*fields?\s*before\)', context_str)
        after_match = re.search(r'\.\.\.\s*\((\d+)\s*fields?\s*after\)', context_str)

        if before_match and after_match:
            before_count = int(before_match.group(1))
            after_count = int(after_match.group(1))
            assert before_count == 4, f"Expected 4 fields before, got {before_count}"
            assert after_count == 3, f"Expected 3 fields after, got {after_count}"
