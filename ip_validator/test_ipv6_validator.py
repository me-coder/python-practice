import unittest
from ipv6_validator import IPv6Validator
from json import load


class TestIPv6Validator(unittest.TestCase):
    """
    Test cases for the IPv6Validator class.
    """

    def test_valid_ipv6_addresses(self):
        with open("ipv6_samples.json", "r") as fjson:
            for ip in load(fjson)["valid_data"].keys():
                ret_val = IPv6Validator(ip).validate()
                # print(f"{ip=} => {ret_val=}")
                self.assertTrue(ret_val)


    def test_invalid_ipv6_addresses(self):
        """
        Test cases for invalid IPv6 addresses using the data in data/ipv6_samples.json
        """
        with open("ipv6_samples.json", "r") as fjson:
            for ip in load(fjson)["invalid_data"].keys():
                ret_val = IPv6Validator(ip).validate()
                # print(f"{ip=} => {ret_val=}")
                self.assertFalse(ret_val)


    def test_edge_cases(self):
        """
        Test cases for edge cases
        """
        self.assertFalse(IPv6Validator(123).validate())  # Non string input
        self.assertFalse(IPv6Validator(None).validate())  # Non string input


if __name__ == "__main__":
    unittest.main()
