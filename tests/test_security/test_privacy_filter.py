"""Tests for the Privacy Filter module."""

from src.security.privacy_filter import PrivacyFilter

SAMPLE_WITH_SECRETS = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecretContract {
    // privateKey: 0x4c0883a69102937d6231471b5dbb6204fe512961708279f24d62f515000000ab
    address constant DEPLOYER = 0xdEADBEEF00000000000000000000000000000001;
    string constant RPC = "https://mainnet.infura.io/v3/abc123def456";
    string constant API = "sk-abcdefghijklmnopqrstuvwxyz12345";

    // password: superSecret123
    function transfer() public {}
}
"""


class TestPrivacyFilter:
    def test_detects_address(self):
        pf = PrivacyFilter()
        assert pf.is_sensitive("0xdEADBEEF00000000000000000000000000000001")

    def test_redacts_address(self):
        pf = PrivacyFilter()
        result = pf.filter(SAMPLE_WITH_SECRETS)
        assert "0xdEADBEEF" not in result.filtered_code
        assert result.has_redactions

    def test_redacts_api_key(self):
        pf = PrivacyFilter()
        result = pf.filter(SAMPLE_WITH_SECRETS)
        assert "sk-abcdefghijklmnopqrstuvwxyz12345" not in result.filtered_code

    def test_redacts_sensitive_comments(self):
        pf = PrivacyFilter()
        result = pf.filter(SAMPLE_WITH_SECRETS)
        assert "superSecret123" not in result.filtered_code

    def test_preserves_normal_code(self):
        pf = PrivacyFilter()
        result = pf.filter(SAMPLE_WITH_SECRETS)
        assert "function" in result.filtered_code
        assert "contract" in result.filtered_code

    def test_no_false_positives_on_clean_code(self):
        clean = """
        pragma solidity ^0.8.20;
        contract Clean {
            function foo() public pure returns (uint256) {
                return 42;
            }
        }
        """
        pf = PrivacyFilter()
        result = pf.filter(clean)
        assert result.total_redacted == 0
