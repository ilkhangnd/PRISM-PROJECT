"""Tests for the Data Masking module."""

import tempfile
from pathlib import Path

from src.security.data_masking import DataMasker, MaskMapping

SAMPLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MyToken {
    mapping(address => uint256) public balances;
    address public owner;
    string public tokenName;

    constructor(string memory _name) {
        owner = msg.sender;
        tokenName = _name;
    }

    function deposit() public payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}
"""


class TestMaskMapping:
    def test_add_and_lookup(self):
        mapping = MaskMapping()
        masked = mapping.add("myFunction")
        assert masked is not None
        assert mapping.get_masked("myFunction") == masked
        assert mapping.get_original(masked) == "myFunction"

    def test_deterministic(self):
        mapping = MaskMapping()
        m1 = mapping.add("transfer")
        m2 = mapping.add("transfer")
        assert m1 == m2

    def test_save_and_load(self):
        mapping = MaskMapping()
        mapping.add("funcA")
        mapping.add("funcB")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)

        mapping.save(path)
        loaded = MaskMapping.load(path)

        assert loaded.get_original(mapping.get_masked("funcA")) == "funcA"
        assert loaded.get_original(mapping.get_masked("funcB")) == "funcB"
        path.unlink()


class TestDataMasker:
    def test_keywords_preserved(self):
        masker = DataMasker()
        masked = masker.mask_source(SAMPLE_CONTRACT)
        assert "contract" in masked
        assert "function" in masked
        assert "require" in masked
        assert "public" in masked
        assert "msg.sender" in masked or "msg" in masked

    def test_identifiers_masked(self):
        masker = DataMasker()
        masked = masker.mask_source(SAMPLE_CONTRACT)
        # User-defined names should be masked
        assert "MyToken" not in masked
        assert "tokenName" not in masked

    def test_mapping_populated(self):
        masker = DataMasker()
        masker.mask_source(SAMPLE_CONTRACT)
        mapping = masker.get_mapping()
        assert len(mapping.original_to_masked) > 0

    def test_roundtrip(self):
        masker = DataMasker()
        masker.mask_source(SAMPLE_CONTRACT)
        mapping = masker.get_mapping()

        # Every masked identifier should map back
        for original, masked_name in mapping.original_to_masked.items():
            assert mapping.get_original(masked_name) == original
