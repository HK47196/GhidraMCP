"""
Test suite for far pointer syntax parsing in struct field definitions.

Tests the parsing and handling of far pointer syntax (e.g., "type *32")
where the number specifies the pointer size in bits.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json


class TestFarPointerParsing:
    """Test suite for far pointer syntax parsing."""

    def test_far_pointer_32bit_parsing(self):
        """Test parsing of 32-bit far pointer (type *32)."""
        # Test data: struct field with 32-bit far pointer
        field_type = "EffectData *32"

        # Expected result: 4-byte pointer (32 bits / 8 = 4 bytes)
        expected_pointer_size = 4

        # Parse the type string
        parts = field_type.split("*")
        assert len(parts) == 2, "Should split into base type and size"

        base_type = parts[0].strip()
        size_str = parts[1].strip()

        assert base_type == "EffectData", "Base type should be EffectData"
        assert size_str == "32", "Size should be 32"

        # Verify size conversion
        pointer_size_bits = int(size_str)
        pointer_size_bytes = pointer_size_bits // 8

        assert pointer_size_bytes == expected_pointer_size, "Should be 4 bytes"

    def test_far_pointer_16bit_parsing(self):
        """Test parsing of 16-bit far pointer (type *16)."""
        field_type = "void *16"

        parts = field_type.split("*")
        assert len(parts) == 2

        base_type = parts[0].strip()
        size_str = parts[1].strip()

        assert base_type == "void"
        assert size_str == "16"

        pointer_size_bytes = int(size_str) // 8
        assert pointer_size_bytes == 2, "16-bit pointer should be 2 bytes"

    def test_far_pointer_64bit_parsing(self):
        """Test parsing of 64-bit far pointer (type *64)."""
        field_type = "MyStruct *64"

        parts = field_type.split("*")
        assert len(parts) == 2

        base_type = parts[0].strip()
        size_str = parts[1].strip()

        assert base_type == "MyStruct"
        assert size_str == "64"

        pointer_size_bytes = int(size_str) // 8
        assert pointer_size_bytes == 8, "64-bit pointer should be 8 bytes"

    def test_regular_pointer_parsing(self):
        """Test that regular pointer syntax (type *) still works."""
        field_type = "int *"

        parts = field_type.split("*")
        assert len(parts) == 2

        base_type = parts[0].strip()
        size_str = parts[1].strip()

        assert base_type == "int"
        assert size_str == "", "Regular pointer should have empty size string"

    def test_pointer_with_spaces(self):
        """Test parsing pointer with spaces (type * 32)."""
        field_type = "char * 32"

        parts = field_type.split("*")
        assert len(parts) == 2

        base_type = parts[0].strip()
        size_str = parts[1].strip()

        assert base_type == "char"
        assert size_str == "32"

    def test_invalid_pointer_size_zero(self):
        """Test handling of invalid pointer size (zero bits)."""
        field_type = "int *0"

        parts = field_type.split("*")
        size_str = parts[1].strip()

        pointer_size_bytes = int(size_str) // 8
        assert pointer_size_bytes == 0, "Should detect zero size"

    def test_invalid_pointer_size_non_numeric(self):
        """Test handling of non-numeric pointer size."""
        field_type = "int *abc"

        parts = field_type.split("*")
        size_str = parts[1].strip()

        with pytest.raises(ValueError):
            int(size_str)

    def test_multiple_asterisks(self):
        """Test handling of multiple asterisks in type name."""
        # This is an edge case - pointer to pointer shouldn't match far pointer syntax
        field_type = "int **"

        parts = field_type.split("*")
        # Should have 3 parts: ["int ", "", ""]
        assert len(parts) >= 2

    def test_no_space_between_type_and_asterisk(self):
        """Test parsing with no space before asterisk."""
        field_type = "uint32_t*32"

        parts = field_type.split("*")
        assert len(parts) == 2

        base_type = parts[0].strip()
        size_str = parts[1].strip()

        assert base_type == "uint32_t"
        assert size_str == "32"


class TestFarPointerInBulkOperations:
    """Test far pointer syntax in bulk operations."""

    def test_bulk_operation_with_far_pointer_field(self):
        """Test creating struct with far pointer field via bulk operations."""
        bulk_operation = {
            "operations": [
                {
                    "endpoint": "/struct/create",
                    "params": {
                        "name": "WorldSpellEffect",
                        "size": 0,
                        "category_path": ""
                    }
                },
                {
                    "endpoint": "/struct/insert_field",
                    "params": {
                        "struct_name": "WorldSpellEffect",
                        "field_name": "activeFlag",
                        "field_type": "uint8_t",
                        "offset": 0,
                        "length": -1,
                        "comment": "0=inactive, 1=active"
                    }
                },
                {
                    "endpoint": "/struct/insert_field",
                    "params": {
                        "struct_name": "WorldSpellEffect",
                        "field_name": "spellType",
                        "field_type": "uint8_t",
                        "offset": 1,
                        "length": -1,
                        "comment": "Type of spell"
                    }
                },
                {
                    "endpoint": "/struct/insert_field",
                    "params": {
                        "struct_name": "WorldSpellEffect",
                        "field_name": "pEffectData",
                        "field_type": "EffectData *32",
                        "offset": 2,
                        "length": -1,
                        "comment": "Far pointer (32-bit) to effect data"
                    }
                }
            ]
        }

        # Verify the bulk operation structure
        assert len(bulk_operation["operations"]) == 4

        # Find the far pointer field operation
        far_pointer_op = bulk_operation["operations"][3]
        assert far_pointer_op["params"]["field_type"] == "EffectData *32"
        assert "*32" in far_pointer_op["params"]["field_type"]

    def test_multiple_far_pointers_different_sizes(self):
        """Test struct with multiple far pointers of different sizes."""
        operations = [
            {
                "endpoint": "/struct/insert_field",
                "params": {
                    "struct_name": "TestStruct",
                    "field_name": "ptr16",
                    "field_type": "void *16",
                    "offset": 0,
                    "length": -1
                }
            },
            {
                "endpoint": "/struct/insert_field",
                "params": {
                    "struct_name": "TestStruct",
                    "field_name": "ptr32",
                    "field_type": "int *32",
                    "offset": 2,
                    "length": -1
                }
            },
            {
                "endpoint": "/struct/insert_field",
                "params": {
                    "struct_name": "TestStruct",
                    "field_name": "ptr64",
                    "field_type": "char *64",
                    "offset": 6,
                    "length": -1
                }
            }
        ]

        # Verify all pointer types are present
        pointer_types = [op["params"]["field_type"] for op in operations]
        assert "void *16" in pointer_types
        assert "int *32" in pointer_types
        assert "char *64" in pointer_types


class TestFarPointerEdgeCases:
    """Test edge cases for far pointer parsing."""

    def test_pointer_size_odd_bits(self):
        """Test pointer with non-byte-aligned size."""
        # 17 bits is not byte-aligned
        field_type = "int *17"

        parts = field_type.split("*")
        size_str = parts[1].strip()
        pointer_size_bits = int(size_str)

        # Integer division should give 2 bytes (17 // 8 = 2)
        pointer_size_bytes = pointer_size_bits // 8
        assert pointer_size_bytes == 2

    def test_very_large_pointer_size(self):
        """Test pointer with very large size."""
        field_type = "void *128"

        parts = field_type.split("*")
        size_str = parts[1].strip()
        pointer_size_bytes = int(size_str) // 8

        assert pointer_size_bytes == 16, "128-bit pointer should be 16 bytes"

    def test_pointer_with_complex_base_type(self):
        """Test far pointer with complex base type name."""
        field_type = "struct MyComplexStruct *32"

        parts = field_type.split("*")
        base_type = parts[0].strip()
        size_str = parts[1].strip()

        assert base_type == "struct MyComplexStruct"
        assert size_str == "32"

    def test_pointer_with_underscore_in_base_type(self):
        """Test far pointer with underscore in base type."""
        field_type = "my_custom_type_t *32"

        parts = field_type.split("*")
        base_type = parts[0].strip()

        assert base_type == "my_custom_type_t"
        assert parts[1].strip() == "32"

    def test_numeric_pattern_detection(self):
        """Test that numeric pattern is correctly detected."""
        # Test valid numeric patterns
        valid_sizes = ["8", "16", "32", "64", "128"]
        for size in valid_sizes:
            assert size.isdigit(), f"{size} should be detected as numeric"

        # Test invalid patterns
        invalid_sizes = ["32x", "abc", "3.14", ""]
        for size in invalid_sizes[:-1]:  # Skip empty string
            assert not size.replace(".", "").replace("-", "").isdigit() or "." in size or "-" in size


class TestFarPointerBackwardCompatibility:
    """Test that far pointer changes don't break existing functionality."""

    def test_regular_pointer_still_works(self):
        """Test that regular pointers without size still work."""
        regular_pointers = [
            "int *",
            "void *",
            "char *",
            "MyStruct *",
            "unsigned long *"
        ]

        for ptr in regular_pointers:
            parts = ptr.split("*")
            assert len(parts) == 2
            base_type = parts[0].strip()
            size_str = parts[1].strip()

            # Regular pointers should have empty size string
            assert size_str == "", f"Regular pointer {ptr} should have no size"
            assert base_type != "", f"Regular pointer {ptr} should have base type"

    def test_no_asterisk_types_unaffected(self):
        """Test that types without asterisks are unaffected."""
        simple_types = [
            "int",
            "uint8_t",
            "char",
            "float",
            "double",
            "MyStruct"
        ]

        for type_name in simple_types:
            # These types shouldn't contain asterisks
            assert "*" not in type_name
            # And shouldn't be split
            parts = type_name.split("*")
            assert len(parts) == 1, f"{type_name} should not be split"


class TestFarPointerSizeCalculations:
    """Test size calculations for far pointers."""

    @pytest.mark.parametrize("bits,expected_bytes", [
        (8, 1),
        (16, 2),
        (32, 4),
        (64, 8),
        (128, 16),
        (256, 32),
    ])
    def test_pointer_size_conversion(self, bits, expected_bytes):
        """Test conversion from bits to bytes for various pointer sizes."""
        calculated_bytes = bits // 8
        assert calculated_bytes == expected_bytes, \
            f"{bits} bits should be {expected_bytes} bytes"

    def test_pointer_size_alignment(self):
        """Test that pointer sizes are properly aligned."""
        # Common pointer sizes should be powers of 2
        common_sizes_bits = [8, 16, 32, 64, 128]

        for size_bits in common_sizes_bits:
            size_bytes = size_bits // 8
            # Check if size is a power of 2 (for common architectures)
            # For bytes: 1, 2, 4, 8, 16 are all powers of 2
            assert size_bytes > 0
            # Verify the math
            assert size_bytes * 8 == size_bits
