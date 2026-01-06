"""Unit tests for AWS policy document enforcement."""
import unittest
from unittest.mock import patch

class TestPolicyValidity(unittest.TestCase):
    """Test cases for policy validation function."""

    def setUp(self):
        """Set up test fixtures with mocked environment variables."""
        self.operator_patcher = patch('main.C_OPERATOR', 'StringEquals')
        self.key_patcher = patch('main.C_KEY', 'aws:PrincipalOrgID')
        self.value_patcher = patch('main.C_VALUE', 'o-example123')
        self.operator_patcher.start()
        self.key_patcher.start()
        self.value_patcher.start()
        from main import is_invalid
        self.is_invalid = is_invalid

    def tearDown(self):
        """Clean up test fixtures."""
        self.operator_patcher.stop()
        self.key_patcher.stop()
        self.value_patcher.stop()

    def test_valid_policy_with_condition(self):
        """Test valid policy with correct condition."""
        statements = [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example123"}}}]
        self.assertFalse(self.is_invalid(statements))

    def test_invalid_policy_missing_condition(self):
        """Test invalid policy missing required condition."""
        statements = [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}}]
        self.assertTrue(self.is_invalid(statements))

    def test_invalid_policy_wrong_condition_value(self):
        """Test invalid policy with wrong condition value."""
        statements = [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-wrong123"}}}]
        self.assertTrue(self.is_invalid(statements))

    def test_valid_policy_with_list_principals(self):
        """Test valid policy with list of principals."""
        statements = [{"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::123456789012:root", "arn:aws:iam::987654321098:role/some-role"]}, "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example123"}}}]
        self.assertFalse(self.is_invalid(statements))

    def test_ignore_cloudfront_oai_principals(self):
        """Test that CloudFront OAI principals are ignored."""
        statements = [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123456789"}}]
        self.assertFalse(self.is_invalid(statements))

    def test_ignore_deny_statements(self):
        """Test that Deny statements are ignored."""
        statements = [{"Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}}]
        self.assertFalse(self.is_invalid(statements))

    def test_valid_policy_with_list_condition_values(self):
        """Test valid policy with list of condition values."""
        statements = [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Condition": {"StringEquals": {"aws:PrincipalOrgID": ["o-example123", "o-other456"]}}}]
        self.assertFalse(self.is_invalid(statements))


if __name__ == '__main__':
    unittest.main()