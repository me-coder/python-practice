import re
import sys

from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, AddressValueError
from threading import Lock


class IPv6Validator:
    def __init__(self, ip_to_validate: str):
        """Initialize IPv6Validator with the IP address to validate.

        Args:
            ip_to_validate: The IPv6 address to validate.
        """
        # if not isinstance(ip_to_validate, str):
        #     raise TypeError(
        #         "ip_to_validate is expected to be a string."
        #         f"{type(ip_to_validate)} received."
        #     )
        self.ipv6_addr = ip_to_validate
        self.is_valid_ipv6_ip = True
        self.lock = Lock()

    def normalize_hextets(self, hextets: list):
        """Normalize the hextets of the IPv6 address.

        This method fills in any missing hextets with "0000" and
        pads any short hextets with leading zeros.
        """
        if len(hextets) > 8 or ("" not in hextets and len(hextets) < 8):
            # There were no blanks to fill
            # and provoded IPv6 address has less than 8 segments
            self.is_valid_ipv6_ip = False
            return

        # Fill the blank hextets with dummys
        while len(hextets) < 8 and "" in hextets:
            hextets.insert(hextets.index(""), "")
        # update elements of input list
        for idx, hextet in enumerate(hextets):
            if len(hextet) < 4:
                hextets[idx] = "0" * (4 - len(hextet)) + hextet

    def validate_hextet(self, hextet: str):
        """Validate a single hextet of the IPv6 address.

        This method checks that the hextet is 4 characters long and
        contains only valid hexadecimal digits.
        """
        # print(f"\n{hextet=}")
        if len(hextet) != 4:
            raise Exception("A hextet shoud have 4 characters in string.")

        for char in hextet:
            try:
                char_int = int(char, 16)
                # print(f"{char=}::{char_int=}")
                if 0 > char_int or 15 < char_int:
                    # print(f"{(0 > char_int or 15 < char_int)=}")
                    with self.lock:
                        self.is_valid_ipv6_ip = False
            except ValueError as type_err:
                # print(f"{type_err=}")
                with self.lock:
                    self.is_valid_ipv6_ip = False
                break
        # print(f"{self.is_valid_ipv6_ip=}")

    def validate(self):
        """Validate the IPv6 address.

        This method checks that the IPv6 address is valid according to RFC 4291.
        """
        # Check if it is a valid IPv6 candidate (container ':' separator)
        if (
            not isinstance(self.ipv6_addr, str)
            or ":" not in self.ipv6_addr
            or 1 < len(re.findall("(?=(::))", self.ipv6_addr))
        ):
            self.is_valid_ipv6_ip = False
            # print(
            #     f"IP address {self.ipv6_addr} validity as IPv6 address:"
            #     f"{self.is_valid_ipv6_ip}"
            # )
            return self.is_valid_ipv6_ip

        # Check for IPv4-mapped IPv6 address
        # Pattern to check "::ffff:<some_valid_ipv4_address>"
        if "::ffff:" in self.ipv6_addr:
            try:
                IPv4Address(self.ipv6_addr.split(":")[-1])
            except AddressValueError:
                self.is_valid_ipv6_ip = False
            finally:
                # print(
                #     f"IP address {self.ipv6_addr} validity as IPv6 address:"
                #     f"{self.is_valid_ipv6_ip}"
                # )
                return self.is_valid_ipv6_ip

        # Split the string at ':' to hextets
        hextets = self.ipv6_addr.split(":")
        # print(f"{hextets=}")
        self.normalize_hextets(hextets)
        # print(f"Normalized: {hextets}")

        # for hextet in hextets:
        #     self.validate_hextet(hextet)

        # Utilize ThreadPoolExecutor to validate hextets concurrently
        # max_workers is set to 4, which could be adjusted based on the system
        # and the expected number of hextets. This can improve performance,
        # especially for a large number of IP addresses to validate.
        with ThreadPoolExecutor(max_workers=4) as executor:
            executor.map(self.validate_hextet, hextets)

        # print(
        #     f"IP address {self.ipv6_addr} validity as IPv6 address:"
        #     f"{self.is_valid_ipv6_ip}"
        # )
        return self.is_valid_ipv6_ip


def main(args):
    # print(f"{args=}")
    for ip_to_validate in args:
        # print(f"{ip_to_validate=}")
        ipv6_validator = IPv6Validator(ip_to_validate)
        result = ipv6_validator.validate()
        print(f"IP address {ip_to_validate} validity as IPv6 address:" f"{result}")


if __name__ == "__main__":
    main(sys.argv[1:])
