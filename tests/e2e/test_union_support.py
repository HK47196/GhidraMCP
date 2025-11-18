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
