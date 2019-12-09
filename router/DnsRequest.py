# DummyDNS request
import pydig
import sys
server_ip = "localhost"

resolver = pydig.Resolver(
    executable='/usr/bin/dig',
    nameservers=[
        server_ip
    ]
)

if __name__ == '__main__':
    print(f"querrying '{sys.argv[1]}.example.com'")
    print(resolver.query(f'{sys.argv[1]}.example.com', 'A'))
