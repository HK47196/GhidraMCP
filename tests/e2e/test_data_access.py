"""End-to-end tests for data access operations"""

import pytest
from bridge_mcp_ghidra import (
    get_data_by_address,
    set_data_type,
    create_struct,
    add_struct_field,
    query
)


class TestDataByAddress:
    """Test get_data_by_address functionality"""

    def test_get_data_by_address_basic(self, ghidra_server):
        """Test getting data at a basic address"""
        # First get some data addresses from the listing
        result = query(type="data", limit=10)
        assert isinstance(result, list)

        if len(result) > 0:
            # Parse out an address from the first data item
            # Format is typically "address: name [type, size bytes] = value"
            first_line = result[0]
            if ":" in first_line:
                address = first_line.split(":")[0].strip()

                # Now test get_data_by_address
                data_result = get_data_by_address(address)
                assert isinstance(data_result, str)
                assert "Address:" in data_result
                assert "Type:" in data_result
                assert "Size:" in data_result

    def test_get_data_by_address_struct_member(self, ghidra_server):
        """Test getting data at an address inside a struct (the main fix)"""
        # Create a test struct
        struct_name = "TestDataStruct"
        create_struct(name=struct_name, size=16)

        # Add fields to the struct
        add_struct_field(struct_name=struct_name, field_type="byte", field_name="field0")
        add_struct_field(struct_name=struct_name, field_type="byte", field_name="field1")
        add_struct_field(struct_name=struct_name, field_type="byte", field_name="field2")
        add_struct_field(struct_name=struct_name, field_type="byte", field_name="field3")
        add_struct_field(struct_name=struct_name, field_type="int", field_name="field4")

        # Find an address where we can apply this struct
        # Get some data addresses to find a suitable location
        data_result = query(type="data", limit=50)
        assert isinstance(data_result, list)

        # Find an address we can use (look for undefined or small data)
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                # Use the first data address we find
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found for struct test")

        # Apply the struct type at this address
        set_result = set_data_type(address=test_address, type_name=struct_name)
        assert "success" in set_result.lower() or "Error" not in set_result

        # Now test get_data_by_address at the struct's start
        result = get_data_by_address(test_address)
        assert isinstance(result, str)
        assert "Address:" in result
        assert struct_name in result or "Type:" in result

        # Calculate an address inside the struct (offset +3 for field3)
        # Parse the hex address
        if test_address.startswith("0x"):
            base_addr = int(test_address, 16)
        else:
            base_addr = int(test_address, 16)

        member_address = f"0x{base_addr + 3:x}"

        # Test getting data at the struct member address (THIS IS THE FIX)
        member_result = get_data_by_address(member_address)
        assert isinstance(member_result, str)

        # Should NOT return an error anymore
        assert "Error: No data defined at address" not in member_result

        # Should contain information about the field
        assert "Address:" in member_result
        assert "Type:" in member_result
        assert "Size:" in member_result

        # Should show parent structure information
        assert "Parent" in member_result or "field" in member_result.lower()

    def test_get_data_by_address_array_element(self, ghidra_server):
        """Test getting data at an address inside an array"""
        # Get some data addresses
        data_result = query(type="data", limit=50)
        assert isinstance(data_result, list)

        # Find an address we can use
        test_address = None
        for line in data_result:
            if ":" in line:
                addr = line.split(":")[0].strip()
                if addr.startswith("0x") or addr.startswith("00"):
                    test_address = addr
                    break

        if test_address is None:
            pytest.skip("No suitable data address found for array test")

        # Apply an array type at this address
        set_result = set_data_type(address=test_address, type_name="byte[8]")
        assert "success" in set_result.lower() or "Error" not in set_result

        # Calculate an address inside the array (offset +4)
        if test_address.startswith("0x"):
            base_addr = int(test_address, 16)
        else:
            base_addr = int(test_address, 16)

        element_address = f"0x{base_addr + 4:x}"

        # Test getting data at the array element address
        element_result = get_data_by_address(element_address)
        assert isinstance(element_result, str)

        # Should NOT return an error
        assert "Error: No data defined at address" not in element_result

        # Should contain basic data info
        assert "Address:" in element_result
        assert "Type:" in element_result
        assert "Size:" in element_result

    def test_get_data_by_address_invalid_address(self, ghidra_server):
        """Test error handling for invalid addresses"""
        result = get_data_by_address("invalid_address")
        assert isinstance(result, str)
        assert "Error" in result or "Invalid" in result

    def test_get_data_by_address_no_data(self, ghidra_server):
        """Test error handling when no data exists at address"""
        # Use an address that's unlikely to have data
        result = get_data_by_address("0xffffffff")
        assert isinstance(result, str)
        # Should return an error since no program data exists there
        assert "Error" in result or "No data" in result


class TestDataTypes:
    """Test set_data_type functionality"""

    def test_set_data_type_basic(self, ghidra_server):
        """Test setting a basic data type"""
        # Get a data address
        data_result = query(type="data", limit=10)
        assert isinstance(data_result, list)

        if len(data_result) > 0:
            first_line = data_result[0]
            if ":" in first_line:
                address = first_line.split(":")[0].strip()

                # Set a dword type
                result = set_data_type(address=address, type_name="dword")
                assert isinstance(result, str)

                # Verify the type was set
                verify_result = get_data_by_address(address)
                assert "dword" in verify_result.lower() or "4 bytes" in verify_result
