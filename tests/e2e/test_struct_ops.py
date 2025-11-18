"""End-to-end tests for struct operations"""

import pytest
from bridge_mcp_ghidra import create_struct, add_struct_field, get_struct_info, replace_struct_field, delete_struct_field
import json


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


class TestComplexStructScenarios:
    """Test complex struct modification scenarios"""

    def test_modify_and_rebuild_struct(self, ghidra_server):
        """Test replacing field type from int to long"""
        # Create struct with field "original1" (int) at ordinal 0
        create_struct(name="ModifyRebuildStruct", size=0)
        add_struct_field(struct_name="ModifyRebuildStruct", field_type="int", field_name="original1")
        add_struct_field(struct_name="ModifyRebuildStruct", field_type="int", field_name="original2")

        # Try to replace ordinal 0 with "replaced1" (long)
        replace_struct_field(
            struct_name="ModifyRebuildStruct",
            ordinal=0,
            field_type="long",
            field_name="replaced1"
        )

        # Delete ordinal 1
        delete_struct_field(struct_name="ModifyRebuildStruct", ordinal=1)

        # Add new field
        add_struct_field(struct_name="ModifyRebuildStruct", field_type="char", field_name="new1")

        # Check result
        info = get_struct_info(name="ModifyRebuildStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        # First field should be replaced1 with type longlong (8 bytes)
        assert components[0]["name"] == "replaced1"
        assert components[0]["type"] == "longlong"
        assert components[0]["offset"] == 0
        assert components[0]["size"] == 8  # longlong is 8 bytes

        # Second field should be new1 with type char
        assert components[1]["name"] == "new1"
        assert components[1]["type"] == "char"

    def test_replace_field_with_ulong(self, ghidra_server):
        """Test replacing field type to ulong"""
        create_struct(name="UlongTestStruct", size=0)
        add_struct_field(struct_name="UlongTestStruct", field_type="int", field_name="field1")

        # Replace with ulong
        replace_struct_field(
            struct_name="UlongTestStruct",
            ordinal=0,
            field_type="ulong",
            field_name="ulongField"
        )

        info = get_struct_info(name="UlongTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "ulongField"
        assert components[0]["type"] == "ulonglong"
        assert components[0]["size"] == 8  # ulonglong is 8 bytes

    def test_replace_field_with_unsigned_long(self, ghidra_server):
        """Test replacing field type to unsigned long"""
        create_struct(name="UnsignedLongTestStruct", size=0)
        add_struct_field(struct_name="UnsignedLongTestStruct", field_type="int", field_name="field1")

        # Replace with unsigned long
        replace_struct_field(
            struct_name="UnsignedLongTestStruct",
            ordinal=0,
            field_type="unsigned long",
            field_name="unsignedLongField"
        )

        info = get_struct_info(name="UnsignedLongTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "unsignedLongField"
        assert components[0]["type"] == "ulonglong"
        assert components[0]["size"] == 8  # ulonglong is 8 bytes

    def test_replace_field_with_int(self, ghidra_server):
        """Test replacing field type to int"""
        create_struct(name="IntTestStruct", size=0)
        add_struct_field(struct_name="IntTestStruct", field_type="char", field_name="field1")

        replace_struct_field(
            struct_name="IntTestStruct",
            ordinal=0,
            field_type="int",
            field_name="intField"
        )

        info = get_struct_info(name="IntTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "intField"
        assert components[0]["type"] == "int"
        assert components[0]["size"] == 4

    def test_replace_field_with_uint(self, ghidra_server):
        """Test replacing field type to uint"""
        create_struct(name="UintTestStruct", size=0)
        add_struct_field(struct_name="UintTestStruct", field_type="char", field_name="field1")

        replace_struct_field(
            struct_name="UintTestStruct",
            ordinal=0,
            field_type="uint",
            field_name="uintField"
        )

        info = get_struct_info(name="UintTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "uintField"
        assert components[0]["type"] == "uint"
        assert components[0]["size"] == 4

    def test_replace_field_with_short(self, ghidra_server):
        """Test replacing field type to short"""
        create_struct(name="ShortTestStruct", size=0)
        add_struct_field(struct_name="ShortTestStruct", field_type="char", field_name="field1")

        replace_struct_field(
            struct_name="ShortTestStruct",
            ordinal=0,
            field_type="short",
            field_name="shortField"
        )

        info = get_struct_info(name="ShortTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "shortField"
        assert components[0]["type"] == "short"
        assert components[0]["size"] == 2

    def test_replace_field_with_ushort(self, ghidra_server):
        """Test replacing field type to ushort"""
        create_struct(name="UshortTestStruct", size=0)
        add_struct_field(struct_name="UshortTestStruct", field_type="char", field_name="field1")

        replace_struct_field(
            struct_name="UshortTestStruct",
            ordinal=0,
            field_type="ushort",
            field_name="ushortField"
        )

        info = get_struct_info(name="UshortTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "ushortField"
        assert components[0]["type"] == "ushort"
        assert components[0]["size"] == 2

    def test_replace_field_with_char(self, ghidra_server):
        """Test replacing field type to char"""
        create_struct(name="CharTestStruct", size=0)
        add_struct_field(struct_name="CharTestStruct", field_type="int", field_name="field1")

        replace_struct_field(
            struct_name="CharTestStruct",
            ordinal=0,
            field_type="char",
            field_name="charField"
        )

        info = get_struct_info(name="CharTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "charField"
        assert components[0]["type"] == "char"
        assert components[0]["size"] == 1

    def test_replace_field_with_uchar(self, ghidra_server):
        """Test replacing field type to uchar"""
        create_struct(name="UcharTestStruct", size=0)
        add_struct_field(struct_name="UcharTestStruct", field_type="int", field_name="field1")

        replace_struct_field(
            struct_name="UcharTestStruct",
            ordinal=0,
            field_type="uchar",
            field_name="ucharField"
        )

        info = get_struct_info(name="UcharTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "ucharField"
        assert components[0]["type"] == "uchar"
        assert components[0]["size"] == 1

    def test_replace_field_with_float(self, ghidra_server):
        """Test replacing field type to float"""
        create_struct(name="FloatTestStruct", size=0)
        add_struct_field(struct_name="FloatTestStruct", field_type="int", field_name="field1")

        replace_struct_field(
            struct_name="FloatTestStruct",
            ordinal=0,
            field_type="float",
            field_name="floatField"
        )

        info = get_struct_info(name="FloatTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "floatField"
        assert components[0]["type"] == "float"
        assert components[0]["size"] == 4

    def test_replace_field_with_double(self, ghidra_server):
        """Test replacing field type to double"""
        create_struct(name="DoubleTestStruct", size=0)
        add_struct_field(struct_name="DoubleTestStruct", field_type="int", field_name="field1")

        replace_struct_field(
            struct_name="DoubleTestStruct",
            ordinal=0,
            field_type="double",
            field_name="doubleField"
        )

        info = get_struct_info(name="DoubleTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "doubleField"
        assert components[0]["type"] == "double"
        assert components[0]["size"] == 8

    def test_replace_field_with_bool(self, ghidra_server):
        """Test replacing field type to bool"""
        create_struct(name="BoolTestStruct", size=0)
        add_struct_field(struct_name="BoolTestStruct", field_type="int", field_name="field1")

        replace_struct_field(
            struct_name="BoolTestStruct",
            ordinal=0,
            field_type="bool",
            field_name="boolField"
        )

        info = get_struct_info(name="BoolTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "boolField"
        assert components[0]["type"] == "bool"
        assert components[0]["size"] == 1

    def test_replace_field_with_dword(self, ghidra_server):
        """Test replacing field type using dword alias"""
        create_struct(name="DwordTestStruct", size=0)
        add_struct_field(struct_name="DwordTestStruct", field_type="char", field_name="field1")

        replace_struct_field(
            struct_name="DwordTestStruct",
            ordinal=0,
            field_type="dword",
            field_name="dwordField"
        )

        info = get_struct_info(name="DwordTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "dwordField"
        assert components[0]["type"] == "uint"
        assert components[0]["size"] == 4

    def test_replace_field_with_word(self, ghidra_server):
        """Test replacing field type using word alias"""
        create_struct(name="WordTestStruct", size=0)
        add_struct_field(struct_name="WordTestStruct", field_type="char", field_name="field1")

        replace_struct_field(
            struct_name="WordTestStruct",
            ordinal=0,
            field_type="word",
            field_name="wordField"
        )

        info = get_struct_info(name="WordTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "wordField"
        assert components[0]["type"] == "ushort"
        assert components[0]["size"] == 2

    def test_replace_field_with_byte(self, ghidra_server):
        """Test replacing field type using byte alias"""
        create_struct(name="ByteTestStruct", size=0)
        add_struct_field(struct_name="ByteTestStruct", field_type="int", field_name="field1")

        replace_struct_field(
            struct_name="ByteTestStruct",
            ordinal=0,
            field_type="byte",
            field_name="byteField"
        )

        info = get_struct_info(name="ByteTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "byteField"
        assert components[0]["type"] == "char"
        assert components[0]["size"] == 1

    def test_replace_field_with_longlong(self, ghidra_server):
        """Test replacing field type to longlong explicitly"""
        create_struct(name="LonglongTestStruct", size=0)
        add_struct_field(struct_name="LonglongTestStruct", field_type="int", field_name="field1")

        replace_struct_field(
            struct_name="LonglongTestStruct",
            ordinal=0,
            field_type="longlong",
            field_name="longlongField"
        )

        info = get_struct_info(name="LonglongTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "longlongField"
        assert components[0]["type"] == "longlong"
        assert components[0]["size"] == 8

    def test_replace_field_with_unsigned_int(self, ghidra_server):
        """Test replacing field type to unsigned int"""
        create_struct(name="UnsignedIntTestStruct", size=0)
        add_struct_field(struct_name="UnsignedIntTestStruct", field_type="char", field_name="field1")

        replace_struct_field(
            struct_name="UnsignedIntTestStruct",
            ordinal=0,
            field_type="unsigned int",
            field_name="unsignedIntField"
        )

        info = get_struct_info(name="UnsignedIntTestStruct")
        info_data = json.loads(info)

        assert info_data["success"] is True
        components = info_data["components"]

        assert components[0]["name"] == "unsignedIntField"
        assert components[0]["type"] == "uint"
        assert components[0]["size"] == 4

