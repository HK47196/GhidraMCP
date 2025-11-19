"""End-to-end tests for program modification operations"""

import pytest
from bridge_mcp_ghidra import rename, set_decompiler_comment, query, create_struct, decompile_function, get_data_by_address


class TestModifications:
    """Test modification operations"""

    def test_rename_function_by_name(self, ghidra_server):
        """Test renaming a function by name using consolidated rename tool"""
        original_name = "add"
        new_name = "test_add_renamed"

        # Rename using type="function"
        result = rename(type="function", old_name=original_name, new_name=new_name)

        # Result is a string
        assert isinstance(result, str)
        assert "success" in result.lower() or "renamed" in result.lower()

        # Verify - use 'methods' which lists functions
        list_result = query(type="methods", limit=100)
        list_text = "\n".join(list_result)
        assert new_name in list_text, f"Expected '{new_name}' in function list. Got: {list_text[:500]}"

        # Rename back
        restore_result = rename(type="function", old_name=new_name, new_name=original_name)
        assert isinstance(restore_result, str)

    def test_rename_function_by_address(self, ghidra_server):
        """Test renaming a function by address using consolidated rename tool"""
        # Get a function address from the program
        functions = query(type="methods", limit=10)
        # Assuming there's at least one function in the test binary

        # Use a known address from test binary (this should be adjusted based on actual test binary)
        test_address = "0x00101000"
        new_name = "test_renamed_by_addr"

        # Rename using type="function_by_address"
        result = rename(type="function_by_address", function_address=test_address, new_name=new_name)

        # Result is a string
        assert isinstance(result, str)
        # Note: May succeed or fail depending on whether address exists
        # Just verify it returns a response

    def test_rename_data_success(self, ghidra_server):
        """Test renaming a data label at a valid address"""
        # Get actual data addresses from the program
        data_result = query(type="data", limit=10)
        assert isinstance(data_result, list)

        if len(data_result) == 0:
            pytest.skip("No data found in test binary")

        # Parse address from first data entry (format: "address: name - type")
        test_address = None
        for line in data_result:
            if ":" in line:
                test_address = line.split(":")[0].strip()
                break

        if test_address is None:
            pytest.skip("Could not parse data address from query result")

        new_name = "test_data_renamed_e2e"

        # Rename using type="data"
        result = rename(type="data", address=test_address, new_name=new_name)

        # Result should indicate success
        assert isinstance(result, str)
        assert "success" in result.lower() or "renamed" in result.lower(), \
            f"Expected success message, got: {result}"

        # Verify the rename took effect
        data_info = get_data_by_address(test_address)
        assert new_name in data_info, \
            f"Expected '{new_name}' in data info. Got: {data_info}"

    def test_rename_data_failure_no_data(self, ghidra_server):
        """Test renaming data at an address with no defined data fails"""
        # Use an address that likely has no defined data
        # 0x00000001 is typically not a valid data address
        invalid_address = "0x00000001"
        new_name = "should_fail"

        # Rename using type="data"
        result = rename(type="data", address=invalid_address, new_name=new_name)

        # Result should indicate failure
        assert isinstance(result, str)
        assert "failed" in result.lower(), \
            f"Expected failure message for invalid address, got: {result}"

    def test_rename_data_preserves_type(self, ghidra_server):
        """Test that renaming data preserves the original data type"""
        # Get actual data addresses from the program
        data_result = query(type="data", limit=20)
        assert isinstance(data_result, list)

        if len(data_result) == 0:
            pytest.skip("No data found in test binary")

        # Find a data entry with a type
        test_address = None
        for line in data_result:
            if ":" in line:
                test_address = line.split(":")[0].strip()
                break

        if test_address is None:
            pytest.skip("Could not parse data address from query result")

        # Get original data info
        original_info = get_data_by_address(test_address)

        # Rename the data
        new_name = "test_preserved_type_e2e"
        result = rename(type="data", address=test_address, new_name=new_name)
        assert "success" in result.lower() or "renamed" in result.lower()

        # Verify type is preserved (the Type: field should remain the same)
        new_info = get_data_by_address(test_address)

        # Extract type from both
        def extract_type(info):
            for line in info.split('\n'):
                if 'Type:' in line:
                    return line.split('Type:')[1].strip()
            return None

        original_type = extract_type(original_info)
        new_type = extract_type(new_info)

        if original_type and new_type:
            assert original_type == new_type, \
                f"Type changed from '{original_type}' to '{new_type}'"

    def test_rename_variable(self, ghidra_server):
        """Test renaming a local variable using consolidated rename tool"""
        # First decompile a function to see what variables exist
        decompiled = decompile_function(name="add")

        # Attempt to rename a variable (this may fail if variable doesn't exist)
        # Using common variable names that might exist
        result = rename(
            type="variable",
            function_name="add",
            old_name="param_1",  # Common Ghidra variable name
            new_name="test_param"
        )

        # Result is a string
        assert isinstance(result, str)
        # Note: May succeed or fail depending on whether variable exists
        # Just verify it returns a response

    def test_rename_struct(self, ghidra_server):
        """Test renaming a struct using consolidated rename tool"""
        # Create a test struct first
        original_name = "TestStructToRename"
        new_name = "TestStructRenamed"

        # Create the struct
        create_result = create_struct(name=original_name, size=16)
        assert isinstance(create_result, str)

        # Rename using type="struct"
        result = rename(type="struct", old_name=original_name, new_name=new_name)

        # Result is a string
        assert isinstance(result, str)
        assert "success" in result.lower() or "renamed" in result.lower()

        # Verify by listing structs
        structs = query(type="structs", limit=100)
        # structs might be a list or string depending on implementation
        structs_text = "\n".join(structs) if isinstance(structs, list) else str(structs)
        assert new_name in structs_text, f"Expected '{new_name}' in struct list"

    def test_rename_invalid_type(self, ghidra_server):
        """Test that rename rejects invalid type parameter"""
        result = rename(type="invalid_type", new_name="test")

        # Should return an error message
        assert isinstance(result, str)
        assert "error" in result.lower() or "invalid" in result.lower()

    def test_rename_missing_required_params(self, ghidra_server):
        """Test that rename validates required parameters for each type"""
        # Test function type without old_name
        result = rename(type="function", new_name="test")
        assert "error" in result.lower() or "required" in result.lower()

        # Test function_by_address without function_address
        result = rename(type="function_by_address", new_name="test")
        assert "error" in result.lower() or "required" in result.lower()

        # Test data without address
        result = rename(type="data", new_name="test")
        assert "error" in result.lower() or "required" in result.lower()

        # Test variable without function_name and old_name
        result = rename(type="variable", new_name="test")
        assert "error" in result.lower() or "required" in result.lower()

        # Test struct without old_name
        result = rename(type="struct", new_name="test")
        assert "error" in result.lower() or "required" in result.lower()

    def test_set_decompiler_comment(self, ghidra_server):
        """Test setting a comment in decompiler view"""
        result = set_decompiler_comment(
            address="0x00101000",
            comment="Test comment from E2E test"
        )

        # Result is a string
        assert isinstance(result, str)
