import unittest
from ipv4_validator import IPv4Validator
from json import load


class TestIPv4Validator(unittest.TestCase):

    def test_valid_ipv4_addresses(self):
        """
        Test with valid IPv4 addresses from ipv4_samples.json.
        Asserts that the validator returns True for each valid IP.
        """
        with open("ipv4_samples.json", "r") as fjson:  # Open the JSON file containing sample data
            for ip in load(fjson)["valid_data"].keys():  # Iterate through valid IP addresses
                # Create an IPv4Validator instance and validate the IP
                ret_val = IPv4Validator(ip).validate()
                # The following line can be uncommented to print the IP and validation result for debugging
                # print(f"{ip=} => {ret_val=}")
                # Assert that the validation result is True for valid IPs
                self.assertTrue(ret_val)

    def test_invalid_ipv4_addresses(self):
        """
        Test with invalid IPv4 addresses from ipv4_samples.json.
        Asserts that the validator returns False for each invalid IP.
        """
        with open("ipv4_samples.json", "r") as fjson:  # Open the JSON file containing sample data
            for ip in load(fjson)["invalid_data"].keys():  # Iterate through invalid IP addresses
                # Create an IPv4Validator instance and validate the IP
                ret_val = IPv4Validator(ip).validate()
                # The following line can be uncommented to print the IP and validation result for debugging
                # print(f"{ip=} => {ret_val=}")
                # Assert that the validation result is False for invalid IPs
                self.assertFalse(ret_val)

    def test_edge_cases(self):
        """
        Test with edge cases like non-string input.
        Asserts that the validator returns False for these cases.
        """
        # Test with an integer input (non-string)
        self.assertFalse(IPv4Validator(123).validate())

        # Test with a None input (non-string)
        self.assertFalse(IPv4Validator(None).validate())


if __name__ == "__main__":
    unittest.main()
