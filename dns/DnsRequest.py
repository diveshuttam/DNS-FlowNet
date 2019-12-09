# DummyDNS request
import pydig
import sys

if __name__ == '__main__':
    print(f"Usage: {sys.argv[0]} DNS_SERVER_IP HOSTNAME")
    server_ip = sys.argv[1]

    resolver = pydig.Resolver(
        executable='/usr/bin/dig',
        nameservers=[
            server_ip
        ]
    )

    print(f"querrying '{sys.argv[2]}.example.com'")
    print(resolver.query(f'{sys.argv[2]}.example.com', 'A'))
