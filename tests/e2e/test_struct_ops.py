"""End-to-end tests for struct operations"""

import pytest
from bridge_mcp_ghidra import create_struct, add_struct_field, get_struct_info


class TestStructOperations:
    """Test struct creation and manipulation"""

    def test_create_struct(self, ghidra_server):
        """Test creating a new struct"""
        result = create_struct(name="TestStruct", size=16)

        # Result is a string
        assert isinstance(result, str)

    def test_add_struct_field(self, ghidra_server):
        """Test adding a field to a struct"""
        # First create a struct
        create_result = create_struct(name="TestStructWithField", size=16)
        assert isinstance(create_result, str)

        # Add a field
        result = add_struct_field(
            struct_name="TestStructWithField",
            field_type="int",
            field_name="field1"
        )

        # Result is a string
        assert isinstance(result, str)

    def test_get_struct_info(self, ghidra_server):
        """Test getting struct information"""
        # Create struct and add field
        create_struct(name="TestStructInfo", size=16)
        add_struct_field(
            struct_name="TestStructInfo",
            field_type="int",
            field_name="field1"
        )

        # Get info
        result = get_struct_info(name="TestStructInfo")

        # Result should be a string
        assert "field1" in str(result)
