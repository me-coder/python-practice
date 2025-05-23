import sys

# from concurrent.futures import ThreadPoolExecutor
# from threading import Lock


class IPv4Validator:
    def __init__(self, ip_to_validate: str):
        """
        Initialize the IPv4Validator with the IP address to validate.
        """
        self.ipv4_addr = ip_to_validate
        self.is_valid_ipv4_ip = True
        # self.lock = Lock()
        # print(f"IPv4 address {self.ipv4_addr=}")

    def validate_octet(self, octet):
        """
        Validate a single octet of the IP address.

        Args:
            octet: The octet to validate.
        """
        try:
            int_octet = int(octet, 10)
            if octet != str(int_octet) or 0 > int_octet or 255 < int_octet:
                self.is_valid_ipv4_ip = False
                # with self.lock:
                #     self.is_valid_ipv4_ip = False
        except (TypeError, ValueError) as err:
            self.is_valid_ipv4_ip = False
            # with self.lock:
            #     self.is_valid_ipv4_ip = False
            # print(f"Error: {err}")

    def validate(self):
        """
        Validate the entire IP address.

        Returns:
            True if the IP address is valid, False otherwise.
        """

        if (
            not isinstance(self.ipv4_addr, str)
            or "." not in self.ipv4_addr
            or 3 != self.ipv4_addr.count(".")
        ):
            self.is_valid_ipv4_ip = False
            # print(f"{self.is_valid_ipv4_ip=}")
            return self.is_valid_ipv4_ip

        for octet in self.ipv4_addr.split("."):
            # print(f"{octet=}")
            self.validate_octet(octet)

        # Use a ThreadPoolExecutor to validate each octet concurrently.
        # This can improve performance, especially for a large number of IPs.
        # max_workers=4 is used to limit the number of threads to 4,
        # which is a reasonable number for most systems.
        # with ThreadPoolExecutor(max_workers=4) as executor:
        #     # executor.map applies the validate_octet function
        #     # to each octet in the IP address.
        #     executor.map(self.validate_octet, self.ipv4_addr.split("."))

        # print(
        #     f"IP address {self.ipv4_addr} validity as IPv4 address:"
        #     f"{self.is_valid_ipv4_ip}"
        # )
        return self.is_valid_ipv4_ip


def main(args):
    """
    Main function to process command line arguments and validate IP addresses.

    Args:
        args: A list of IP addresses to validate.
    """
    for ip_to_validate in args:
        # print(f"{ip_to_validate=}")
        ipv4_validator = IPv4Validator(ip_to_validate)
        result = ipv4_validator.validate()
        print(f"IP address {ip_to_validate} validity as IPv4 address:" f"{result}")


if __name__ == "__main__":
    main(sys.argv[1:])
