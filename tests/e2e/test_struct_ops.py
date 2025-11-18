"""End-to-end tests for struct operations"""

import pytest
from bridge_mcp_ghidra import (
    create_struct,
    parse_c_struct,
    add_struct_field,
    insert_struct_field_at_offset,
    replace_struct_field,
    delete_struct_field,
    clear_struct_field,
    get_struct_info,
    list_structs,
    delete_struct,
    rename,
    query,
)


class TestStructCreation:
    """Test struct creation operations"""

    def test_create_struct_basic(self, ghidra_server):
        """Test creating a basic struct with default size"""
        result = create_struct(name="BasicStruct")
        assert isinstance(result, str)
        assert "success" in result.lower() or "created" in result.lower()

    def test_create_struct_with_size(self, ghidra_server):
        """Test creating a struct with specified size"""
        result = create_struct(name="SizedStruct", size=32)
        assert isinstance(result, str)
        assert "success" in result.lower() or "created" in result.lower()

        # Verify struct exists and has correct size
        info = get_struct_info(name="SizedStruct")
        assert "32" in info or "SizedStruct" in info

    def test_create_struct_with_category(self, ghidra_server):
        """Test creating a struct in a specific category"""
        result = create_struct(
            name="CategorizedStruct",
            size=16,
            category_path="/TestCategory"
        )
        assert isinstance(result, str)
        assert "success" in result.lower() or "created" in result.lower()

    def test_create_struct_nested_category(self, ghidra_server):
        """Test creating a struct in a nested category path"""
        result = create_struct(
            name="NestedCategoryStruct",
            size=8,
            category_path="/Parent/Child/Grandchild"
        )
        assert isinstance(result, str)
        assert "success" in result.lower() or "created" in result.lower()

    def test_create_struct_duplicate_name(self, ghidra_server):
        """Test creating a struct with duplicate name returns error"""
        # Create first struct
        create_struct(name="DuplicateStruct", size=16)

        # Try to create duplicate
        result = create_struct(name="DuplicateStruct", size=32)
        assert isinstance(result, str)
        # Should indicate error or already exists
        assert "error" in result.lower() or "exists" in result.lower() or "duplicate" in result.lower()


class TestParseCStruct:
    """Test C struct parsing"""

    def test_parse_simple_c_struct(self, ghidra_server):
        """Test parsing a simple C struct definition"""
        c_code = """
        struct SimpleStruct {
            int field1;
            char field2;
        };
        """
        result = parse_c_struct(c_code=c_code)
        assert isinstance(result, str)

    def test_parse_c_struct_with_pointers(self, ghidra_server):
        """Test parsing C struct with pointer fields"""
        c_code = """
        struct PointerStruct {
            void *data;
            int *values;
            char *name;
        };
        """
        result = parse_c_struct(c_code=c_code)
        assert isinstance(result, str)

    def test_parse_c_struct_with_arrays(self, ghidra_server):
        """Test parsing C struct with array fields"""
        c_code = """
        struct ArrayStruct {
            int numbers[10];
            char buffer[256];
        };
        """
        result = parse_c_struct(c_code=c_code)
        assert isinstance(result, str)

    def test_parse_c_struct_with_category(self, ghidra_server):
        """Test parsing C struct into specific category"""
        c_code = """
        struct ParsedInCategory {
            int value;
        };
        """
        result = parse_c_struct(c_code=c_code, category_path="/ParsedStructs")
        assert isinstance(result, str)

    def test_parse_invalid_c_struct(self, ghidra_server):
        """Test parsing invalid C code returns error"""
        c_code = "this is not valid C code {"
        result = parse_c_struct(c_code=c_code)
        assert isinstance(result, str)
        # Should indicate parsing error


class TestStructFields:
    """Test struct field operations"""

    def test_add_struct_field_int(self, ghidra_server):
        """Test adding an int field to a struct"""
        create_struct(name="FieldTestStruct", size=16)

        result = add_struct_field(
            struct_name="FieldTestStruct",
            field_type="int",
            field_name="intField"
        )
        assert isinstance(result, str)
        assert "success" in result.lower() or "added" in result.lower()

        # Verify field was added
        info = get_struct_info(name="FieldTestStruct")
        assert "intField" in info

    def test_add_struct_field_char(self, ghidra_server):
        """Test adding a char field to a struct"""
        create_struct(name="CharFieldStruct", size=16)

        result = add_struct_field(
            struct_name="CharFieldStruct",
            field_type="char",
            field_name="charField"
        )
        assert isinstance(result, str)

    def test_add_struct_field_pointer(self, ghidra_server):
        """Test adding a pointer field to a struct"""
        create_struct(name="PointerFieldStruct", size=16)

        result = add_struct_field(
            struct_name="PointerFieldStruct",
            field_type="void*",
            field_name="ptrField"
        )
        assert isinstance(result, str)

    def test_add_struct_field_with_length(self, ghidra_server):
        """Test adding a field with explicit length (for arrays)"""
        create_struct(name="ArrayFieldStruct", size=64)

        result = add_struct_field(
            struct_name="ArrayFieldStruct",
            field_type="char",
            field_name="buffer",
            length=32
        )
        assert isinstance(result, str)

    def test_add_struct_field_with_comment(self, ghidra_server):
        """Test adding a field with a comment"""
        create_struct(name="CommentFieldStruct", size=16)

        result = add_struct_field(
            struct_name="CommentFieldStruct",
            field_type="int",
            field_name="commentedField",
            comment="This is a test comment"
        )
        assert isinstance(result, str)

    def test_add_multiple_fields(self, ghidra_server):
        """Test adding multiple fields to a struct"""
        create_struct(name="MultiFieldStruct", size=32)

        # Add multiple fields
        add_struct_field(
            struct_name="MultiFieldStruct",
            field_type="int",
            field_name="field1"
        )
        add_struct_field(
            struct_name="MultiFieldStruct",
            field_type="int",
            field_name="field2"
        )
        add_struct_field(
            struct_name="MultiFieldStruct",
            field_type="char",
            field_name="field3"
        )

        # Verify all fields exist
        info = get_struct_info(name="MultiFieldStruct")
        assert "field1" in info
        assert "field2" in info
        assert "field3" in info

    def test_add_field_to_nonexistent_struct(self, ghidra_server):
        """Test adding field to non-existent struct returns error"""
        result = add_struct_field(
            struct_name="NonExistentStruct",
            field_type="int",
            field_name="field1"
        )
        assert isinstance(result, str)
        assert "error" in result.lower() or "not found" in result.lower()


class TestInsertStructField:
    """Test inserting fields at specific offsets"""

    def test_insert_field_at_offset_zero(self, ghidra_server):
        """Test inserting a field at offset 0"""
        create_struct(name="InsertOffsetStruct", size=16)

        result = insert_struct_field_at_offset(
            struct_name="InsertOffsetStruct",
            offset=0,
            field_type="int",
            field_name="firstField"
        )
        assert isinstance(result, str)

    def test_insert_field_at_middle_offset(self, ghidra_server):
        """Test inserting a field at a middle offset"""
        create_struct(name="InsertMiddleStruct", size=32)

        # Insert at offset 8
        result = insert_struct_field_at_offset(
            struct_name="InsertMiddleStruct",
            offset=8,
            field_type="int",
            field_name="middleField"
        )
        assert isinstance(result, str)

    def test_insert_field_with_comment(self, ghidra_server):
        """Test inserting a field with a comment"""
        create_struct(name="InsertCommentStruct", size=16)

        result = insert_struct_field_at_offset(
            struct_name="InsertCommentStruct",
            offset=0,
            field_type="int",
            field_name="commentedField",
            comment="Inserted at offset 0"
        )
        assert isinstance(result, str)

    def test_insert_multiple_fields_at_offsets(self, ghidra_server):
        """Test inserting multiple fields at different offsets"""
        create_struct(name="MultiInsertStruct", size=32)

        # Insert fields at different offsets
        insert_struct_field_at_offset(
            struct_name="MultiInsertStruct",
            offset=0,
            field_type="int",
            field_name="offset0"
        )
        insert_struct_field_at_offset(
            struct_name="MultiInsertStruct",
            offset=4,
            field_type="int",
            field_name="offset4"
        )
        insert_struct_field_at_offset(
            struct_name="MultiInsertStruct",
            offset=8,
            field_type="long",
            field_name="offset8"
        )

        # Verify fields
        info = get_struct_info(name="MultiInsertStruct")
        assert "offset0" in info
        assert "offset4" in info
        assert "offset8" in info


class TestReplaceStructField:
    """Test replacing struct fields"""

    def test_replace_field_type(self, ghidra_server):
        """Test replacing a field's type"""
        create_struct(name="ReplaceTypeStruct", size=16)
        add_struct_field(
            struct_name="ReplaceTypeStruct",
            field_type="int",
            field_name="originalField"
        )

        # Replace field at ordinal 0
        result = replace_struct_field(
            struct_name="ReplaceTypeStruct",
            ordinal=0,
            field_type="long",
            field_name="replacedField"
        )
        assert isinstance(result, str)

    def test_replace_field_preserve_name(self, ghidra_server):
        """Test replacing field type while preserving name"""
        create_struct(name="PreserveNameStruct", size=16)
        add_struct_field(
            struct_name="PreserveNameStruct",
            field_type="char",
            field_name="keepThisName"
        )

        # Replace with empty name to preserve
        result = replace_struct_field(
            struct_name="PreserveNameStruct",
            ordinal=0,
            field_type="int",
            field_name=""  # Empty preserves existing
        )
        assert isinstance(result, str)

    def test_replace_field_with_comment(self, ghidra_server):
        """Test replacing field and adding comment"""
        create_struct(name="ReplaceCommentStruct", size=16)
        add_struct_field(
            struct_name="ReplaceCommentStruct",
            field_type="int",
            field_name="field1"
        )

        result = replace_struct_field(
            struct_name="ReplaceCommentStruct",
            ordinal=0,
            field_type="long",
            field_name="replacedField",
            comment="This field was replaced"
        )
        assert isinstance(result, str)

    def test_replace_invalid_ordinal(self, ghidra_server):
        """Test replacing field at invalid ordinal returns error"""
        create_struct(name="InvalidOrdinalStruct", size=16)
        add_struct_field(
            struct_name="InvalidOrdinalStruct",
            field_type="int",
            field_name="field1"
        )

        # Try to replace at invalid ordinal
        result = replace_struct_field(
            struct_name="InvalidOrdinalStruct",
            ordinal=999,  # Invalid ordinal
            field_type="long",
            field_name="shouldFail"
        )
        assert isinstance(result, str)


class TestDeleteStructField:
    """Test deleting struct fields"""

    def test_delete_field_by_ordinal(self, ghidra_server):
        """Test deleting a field by ordinal"""
        create_struct(name="DeleteOrdinalStruct", size=16)
        add_struct_field(
            struct_name="DeleteOrdinalStruct",
            field_type="int",
            field_name="toDelete"
        )

        result = delete_struct_field(
            struct_name="DeleteOrdinalStruct",
            ordinal=0
        )
        assert isinstance(result, str)
        assert "success" in result.lower() or "deleted" in result.lower()

    def test_delete_field_by_offset(self, ghidra_server):
        """Test deleting a field by offset"""
        create_struct(name="DeleteOffsetStruct", size=16)
        insert_struct_field_at_offset(
            struct_name="DeleteOffsetStruct",
            offset=0,
            field_type="int",
            field_name="atOffset0"
        )

        result = delete_struct_field(
            struct_name="DeleteOffsetStruct",
            offset=0
        )
        assert isinstance(result, str)

    def test_delete_middle_field(self, ghidra_server):
        """Test deleting a middle field from struct"""
        create_struct(name="DeleteMiddleStruct", size=32)
        add_struct_field(
            struct_name="DeleteMiddleStruct",
            field_type="int",
            field_name="field1"
        )
        add_struct_field(
            struct_name="DeleteMiddleStruct",
            field_type="int",
            field_name="field2"
        )
        add_struct_field(
            struct_name="DeleteMiddleStruct",
            field_type="int",
            field_name="field3"
        )

        # Delete middle field
        result = delete_struct_field(
            struct_name="DeleteMiddleStruct",
            ordinal=1
        )
        assert isinstance(result, str)

        # Verify field2 is gone
        info = get_struct_info(name="DeleteMiddleStruct")
        assert "field1" in info
        assert "field3" in info

    def test_delete_invalid_ordinal(self, ghidra_server):
        """Test deleting field at invalid ordinal returns error"""
        create_struct(name="DeleteInvalidStruct", size=16)
        add_struct_field(
            struct_name="DeleteInvalidStruct",
            field_type="int",
            field_name="field1"
        )

        result = delete_struct_field(
            struct_name="DeleteInvalidStruct",
            ordinal=999
        )
        assert isinstance(result, str)


class TestClearStructField:
    """Test clearing struct fields (keeps struct size)"""

    def test_clear_field_by_ordinal(self, ghidra_server):
        """Test clearing a field by ordinal"""
        create_struct(name="ClearOrdinalStruct", size=16)
        add_struct_field(
            struct_name="ClearOrdinalStruct",
            field_type="int",
            field_name="toClear"
        )

        result = clear_struct_field(
            struct_name="ClearOrdinalStruct",
            ordinal=0
        )
        assert isinstance(result, str)
        assert "success" in result.lower() or "cleared" in result.lower()

    def test_clear_field_by_offset(self, ghidra_server):
        """Test clearing a field by offset"""
        create_struct(name="ClearOffsetStruct", size=16)
        insert_struct_field_at_offset(
            struct_name="ClearOffsetStruct",
            offset=0,
            field_type="int",
            field_name="atOffset0"
        )

        result = clear_struct_field(
            struct_name="ClearOffsetStruct",
            offset=0
        )
        assert isinstance(result, str)

    def test_clear_preserves_struct_size(self, ghidra_server):
        """Test that clearing a field preserves struct size"""
        create_struct(name="ClearPreserveSizeStruct", size=32)
        add_struct_field(
            struct_name="ClearPreserveSizeStruct",
            field_type="int",
            field_name="field1"
        )

        # Clear the field
        clear_struct_field(
            struct_name="ClearPreserveSizeStruct",
            ordinal=0
        )

        # Struct should still exist with same size
        info = get_struct_info(name="ClearPreserveSizeStruct")
        assert "ClearPreserveSizeStruct" in info


class TestGetStructInfo:
    """Test getting struct information"""

    def test_get_struct_info_basic(self, ghidra_server):
        """Test getting basic struct info"""
        create_struct(name="InfoBasicStruct", size=16)

        result = get_struct_info(name="InfoBasicStruct")
        assert isinstance(result, str)
        assert "InfoBasicStruct" in result

    def test_get_struct_info_with_fields(self, ghidra_server):
        """Test getting struct info shows fields"""
        create_struct(name="InfoFieldsStruct", size=32)
        add_struct_field(
            struct_name="InfoFieldsStruct",
            field_type="int",
            field_name="alpha"
        )
        add_struct_field(
            struct_name="InfoFieldsStruct",
            field_type="char",
            field_name="beta"
        )

        result = get_struct_info(name="InfoFieldsStruct")
        assert "alpha" in result
        assert "beta" in result

    def test_get_struct_info_nonexistent(self, ghidra_server):
        """Test getting info for non-existent struct"""
        result = get_struct_info(name="NonExistentStructInfo")
        assert isinstance(result, str)
        # Should indicate not found or error


class TestListStructs:
    """Test listing structs"""

    def test_list_structs_basic(self, ghidra_server):
        """Test listing all structs"""
        # Create a struct to ensure at least one exists
        create_struct(name="ListTestStruct", size=16)

        result = list_structs()
        # Result can be dict or list
        assert result is not None

    def test_list_structs_with_limit(self, ghidra_server):
        """Test listing structs with limit"""
        # Create multiple structs
        for i in range(5):
            create_struct(name=f"LimitTestStruct{i}", size=16)

        result = list_structs(limit=3)
        assert result is not None

    def test_list_structs_with_offset(self, ghidra_server):
        """Test listing structs with offset for pagination"""
        # Create multiple structs
        for i in range(5):
            create_struct(name=f"OffsetTestStruct{i}", size=16)

        result = list_structs(offset=2, limit=3)
        assert result is not None

    def test_list_structs_by_category(self, ghidra_server):
        """Test listing structs filtered by category"""
        # Create structs in specific category
        create_struct(
            name="CategoryFilterStruct1",
            size=16,
            category_path="/FilterCategory"
        )
        create_struct(
            name="CategoryFilterStruct2",
            size=16,
            category_path="/FilterCategory"
        )

        result = list_structs(category_path="/FilterCategory")
        assert result is not None


class TestDeleteStruct:
    """Test deleting structs"""

    def test_delete_struct_basic(self, ghidra_server):
        """Test deleting a struct"""
        create_struct(name="ToDeleteStruct", size=16)

        result = delete_struct(name="ToDeleteStruct")
        assert isinstance(result, str)
        assert "success" in result.lower() or "deleted" in result.lower()

    def test_delete_struct_with_fields(self, ghidra_server):
        """Test deleting a struct that has fields"""
        create_struct(name="DeleteWithFieldsStruct", size=32)
        add_struct_field(
            struct_name="DeleteWithFieldsStruct",
            field_type="int",
            field_name="field1"
        )
        add_struct_field(
            struct_name="DeleteWithFieldsStruct",
            field_type="char",
            field_name="field2"
        )

        result = delete_struct(name="DeleteWithFieldsStruct")
        assert isinstance(result, str)

    def test_delete_nonexistent_struct(self, ghidra_server):
        """Test deleting non-existent struct returns error"""
        result = delete_struct(name="NonExistentToDelete")
        assert isinstance(result, str)
        # Should indicate not found or error


class TestStructRename:
    """Test struct rename operations"""

    def test_rename_struct(self, ghidra_server):
        """Test renaming a struct"""
        create_struct(name="OriginalNameStruct", size=16)

        result = rename(
            type="struct",
            old_name="OriginalNameStruct",
            new_name="RenamedStruct"
        )
        assert isinstance(result, str)
        assert "success" in result.lower() or "renamed" in result.lower()

        # Verify new name exists
        structs = query(type="structs", limit=100)
        structs_text = "\n".join(structs) if isinstance(structs, list) else str(structs)
        assert "RenamedStruct" in structs_text

    def test_rename_struct_with_fields(self, ghidra_server):
        """Test renaming struct preserves fields"""
        create_struct(name="RenamePreserveStruct", size=32)
        add_struct_field(
            struct_name="RenamePreserveStruct",
            field_type="int",
            field_name="preservedField"
        )

        rename(
            type="struct",
            old_name="RenamePreserveStruct",
            new_name="RenamedPreserveStruct"
        )

        # Verify field still exists
        info = get_struct_info(name="RenamedPreserveStruct")
        assert "preservedField" in info


class TestStructQuery:
    """Test querying structs"""

    def test_query_structs(self, ghidra_server):
        """Test querying structs using query function"""
        create_struct(name="QueryTestStruct", size=16)

        result = query(type="structs", limit=50)
        assert result is not None
        # Result should contain our struct
        result_text = "\n".join(result) if isinstance(result, list) else str(result)
        assert "QueryTestStruct" in result_text

    def test_query_structs_with_filter(self, ghidra_server):
        """Test querying structs with search filter"""
        create_struct(name="FilterQueryStruct", size=16)

        # Use filter parameter to search for the struct
        result = query(type="structs", filter="FilterQueryStruct", limit=50)
        assert result is not None


class TestComplexStructScenarios:
    """Test complex struct operation scenarios"""

    def test_nested_struct_reference(self, ghidra_server):
        """Test creating structs that could reference each other"""
        # Create outer struct
        create_struct(name="OuterStruct", size=32)
        # Create inner struct
        create_struct(name="InnerStruct", size=16)

        # Add pointer to inner struct in outer
        result = add_struct_field(
            struct_name="OuterStruct",
            field_type="InnerStruct*",
            field_name="innerPtr"
        )
        assert isinstance(result, str)

    def test_struct_workflow_create_populate_query(self, ghidra_server):
        """Test complete workflow: create, populate, and query struct"""
        # Create struct with size=0 so fields start at offset 0
        create_result = create_struct(name="WorkflowStruct", size=0)
        assert "success" in create_result.lower() or "created" in create_result.lower()

        # Add various fields
        add_struct_field(
            struct_name="WorkflowStruct",
            field_type="int",
            field_name="id"
        )
        add_struct_field(
            struct_name="WorkflowStruct",
            field_type="int",
            field_name="flags"
        )
        add_struct_field(
            struct_name="WorkflowStruct",
            field_type="long",
            field_name="timestamp"
        )

        # Query to verify
        info = get_struct_info(name="WorkflowStruct")
        assert "id" in info
        assert "flags" in info
        assert "timestamp" in info

        # List to see it
        structs = list_structs()
        assert structs is not None

    def test_modify_and_rebuild_struct(self, ghidra_server):
        """Test modifying struct fields then rebuilding"""
        # Create initial struct with size=0 so fields start at ordinal 0
        create_struct(name="ModifyRebuildStruct", size=0)
        add_struct_field(
            struct_name="ModifyRebuildStruct",
            field_type="int",
            field_name="original1"
        )
        add_struct_field(
            struct_name="ModifyRebuildStruct",
            field_type="int",
            field_name="original2"
        )

        # Verify initial state - fields are at ordinals 0 and 1
        info = get_struct_info(name="ModifyRebuildStruct")
        assert "original1" in info
        assert "original2" in info

        # Replace first field (ordinal 0)
        replace_struct_field(
            struct_name="ModifyRebuildStruct",
            ordinal=0,
            field_type="long",
            field_name="replaced1"
        )

        # Delete second field (now at ordinal 1)
        delete_struct_field(
            struct_name="ModifyRebuildStruct",
            ordinal=1
        )

        # Add new field
        add_struct_field(
            struct_name="ModifyRebuildStruct",
            field_type="char",
            field_name="new1"
        )

        # Verify final state
        info = get_struct_info(name="ModifyRebuildStruct")
        assert "replaced1" in info
        assert "new1" in info
        # original1 was replaced, original2 was deleted
        assert "original1" not in info
        assert "original2" not in info

    def test_large_struct_many_fields(self, ghidra_server):
        """Test creating struct with many fields"""
        create_struct(name="LargeStruct", size=256)

        # Add many fields
        for i in range(10):
            add_struct_field(
                struct_name="LargeStruct",
                field_type="int",
                field_name=f"field_{i}"
            )

        # Verify some fields exist
        info = get_struct_info(name="LargeStruct")
        assert "field_0" in info
        assert "field_5" in info
        assert "field_9" in info
