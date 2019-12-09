import ipaddress
import yaml
import sys
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)
unicode = str
#router configuraion information
r1 = {
    "name": "r1",
    "id": 4,
    "interfaces": [
        {
          "port": 1,
          "mac": "00:00:00:00:01:01",
          "ip": "10.0.1.1",
          "mask": "255.255.255.0"
        },
        {
          "port": 2,
          "mac": "00:00:00:00:01:02",
          "ip": "192.168.200.1",
          "mask": "255.255.255.0"
        }       
    ],
    "routes": [
        {
            "network": "192.168.30.0/24",
            "nexthop": "192.168.200.2"
        },
        {
            "network": "172.0.1.0/24",
            "nexthop": "192.168.200.2"
        }
    ]
}


r2 = {
    "name": "r2",
    "id": 5,
    "interfaces": [
        {
          "port": 1,
          "mac": "00:00:00:00:02:01",
          "ip": "192.168.30.1",
          "mask": "255.255.255.0"
        },
        {
          "port": 2,
          "mac": "00:00:00:00:02:02",
          "ip": "192.168.202.2",
          "mask": "255.255.255.0"
        }       
    ],
    "routes": [
        {
            "network": "10.0.1.0/24",
            "nexthop": "192.168.202.1"
        },
        {
            "network": "172.0.1.0/24",
            "nexthop": "192.168.202.1"
        }
    ]
}



r3 = {
    "name": "r3",
    "id": 6,
    "interfaces": [
        {
          "port": 1,
          "mac": "00:00:00:00:03:01",
          "ip": "172.0.1.1",
          "mask": "255.255.255.0"
        },
        {
          "port": 2,
          "mac": "00:00:00:00:03:02",
          "ip": "192.168.204.2",
          "mask": "255.255.255.0"
        }       
    ],
    "routes": [
        {
            "network": "10.0.1.0/24",
            "nexthop": "192.168.204.1"
        },
        {
            "network": "192.168.30.0/24",
            "nexthop": "192.168.204.1"
        }
    ]
}



r4 = {
    "name": "r4",
    "id": 7,
    "interfaces": [
        {
          "port": 1,
          "mac": "00:00:00:00:04:01",
          "ip": "192.168.200.2",
          "mask": "255.255.255.0"
        },
        {
          "port": 2,
          "mac": "00:00:00:00:04:02",
          "ip": "192.168.202.1",
          "mask": "255.255.255.0"
        },
        {
          "port":3,
          "mac": "00:00:00:00:04:03",
          "ip": "192.168.201.1",
          "mask": "255.255.255.0"
        }
    ],
    "routes": [
        {
            "network": "10.0.1.0/24",
            "nexthop": "192.168.200.1"
        },
        {
            "network": "192.168.30.0/24",
            "nexthop": "192.168.202.2"
        },
        {
            "network": "172.0.1.0/24",
            "nexthop": "192.168.201.2"
        }
    ]
}




r5 = {
    "name": "r5",
    "id": 8,
    "interfaces": [
        {
          "port": 1,
          "mac": "00:00:00:00:05:01",
          "ip": "192.168.201.2",
          "mask": "255.255.255.0"
        },
        {
          "port": 2,
          "mac": "00:00:00:00:05:02",
          "ip": "192.168.203.1",
          "mask": "255.255.255.0"
        }       
    ],
    "routes": [
        {
            "network": "10.0.1.0/24",
            "nexthop": "192.168.201.1"
        },
        {
            "network": "192.168.30.0/24",
            "nexthop": "192.168.201.1"
        },
        {
            "network": "172.0.1.0/24",
            "nexthop": "192.168.203.2"
        }
    ]
}


r6 = {
    "name": "r6",
    "id": 9,
    "interfaces": [
        {
          "port": 1,
          "mac": "00:00:00:00:06:01",
          "ip": "192.168.204.1",
          "mask": "255.255.255.0"
        },
        {
          "port": 2,
          "mac": "00:00:00:00:06:02",
          "ip": "192.168.203.2",
          "mask": "255.255.255.0"
        }       
    ],
    "routes": [
        {
            "network": "10.0.1.0/24",
            "nexthop": "192.168.203.1"
        },
        {
            "network": "192.168.30.0/24",
            "nexthop": "192.168.203.1"
        },
        {
            "network": "172.0.1.0/24",
            "nexthop": "192.168.204.2"
        }
    ]
}


# global data structure to store the routes config information
rts = {}
rts["router"] = []
rts["router"].append(r1)
rts["router"].append(r2)
rts["router"].append(r3)
rts["router"].append(r4)
rts["router"].append(r5)
rts["router"].append(r6)


def network_match(network, ip):
    '''
    utility function to match the destination ip is part of the network.
    Ex: network: 10.2.1.0/24,  destination ip:10.2.1.1
    '''
    result = ipaddress.ip_address(unicode(ip)) in ipaddress.ip_network(unicode(network))
    #result = ipaddress.ip_address(ip) in ipaddress.ip_network(network)
    return result


class router_mgr(object):
    '''
    Router Manager class, which holds multiple router objects. key is routerid
    '''
    def __init__(self):
        '''
        initialize the router objects (read the global router configuration and initialize it)
        '''
        self.routers = {}
        try:
            for r in rts["router"]:
                rid = r['id']
                self.routers[rid] = router_lib(r)

        except Exception as e:
            log.error("Error reading input file %s", e.__doc__)
            sys.exit(1)
            return

    def get_router(self, rid):
        '''
        return the router object for the given router id
        '''
        log.info("Querying router object %d", rid)
        if rid in self.routers:
            return self.routers[rid]
        else:
            log.error("router object not found ")
            return None

    def get_routers(self):
        return self.routers

    def print_router(self):
        #log.info("---------print routers -----------")
        for k in self.routers:
            log.info("---------------------------------")
            r = self.routers[k]
            log.info("router_id :  %s ", k)
            log.info("ips : %s ", r.ips)
            log.info("interface : %s ", r.router_if)
            log.info("arp tables : %s ", r.arp_tables)

class router_lib(object):
    '''
    router library class. 
    1. interface information, 
    2. arp(neighbor details) table
    3. routing table
    '''
    def __init__(self, data):
        '''
        init routine, initialize the interface able, routes.
        '''
        self.routes = []
        self.arp_tables = []
        self.router_if = []
        self.ips = []
        self.tdata = data
        self.id = self.tdata['id']
        self.router_if = self.tdata['interfaces']
        for i in self.router_if:
            self.ips.append(i["ip"])

        # populating the routes from interface table & static routes
        self.populate_routes()
        log.info("Started Router with interface  %s ", self.router_if)
        log.info("Routing Table  %s ", self.routes)

    def add_neighbor(self, mac, ip):
        '''
        add the neighbor in to neighbor table
        '''
        log.info("Adding neighbor... mac %s ip %s ", mac, ip)
        for entry in self.arp_tables:
            if entry["mac"] == mac:
                return
        self.arp_tables.append({"mac": mac, "ip": ip})
        self.print_neighbor()

    def get_neighbor(self, ip):
        '''
        return the neighbor mac entry for the given ip.
        '''
        log.info("Get neighbor... %s ", ip)
        for arp_entry in self.arp_tables:
            if arp_entry["ip"] == ip:
                return arp_entry["mac"]
        return None

    def print_neighbor(self):
        log.info("neighbor tables %s ", self.arp_tables)

    def populate_routes(self):
        '''
        populate the routing table from
        - connected interfaces
        - static routes
        '''
        # connected interfaces
        for i in self.router_if:
            a = ipaddress.ip_network(unicode(i["ip"] + '/' + i["mask"]),
                                     strict=False)
            #a = ipaddress.ip_network(i["ip"] + '/' + i["mask"],
            #                         strict=False)           
            network = str(a.network_address) + "/" + str(a.prefixlen)
            self.routes.append({"network": network, "port": i["port"],
                                "scope": "link", "nexthop": None})
        # static routes
        if "routes" in self.tdata:
            for route in self.tdata["routes"]:
                # need to find the port number of the nexthop
                self.routes.append({"network": route["network"], 
                                    "port": self.get_port_no_for_ip(route["nexthop"]),
                                    "scope": "static", "nexthop": route["nexthop"]})

    def lookup_routing_table(self, destip):
        '''
        check the routing table for the given destination ip, 
        if route exists, return the route
        Note: This is getting called to add flow in datapath(when packet comes/packet_in)
        '''
        for route in self.routes:
            if network_match(route["network"], destip):
                if "port" in route:
                    log.info("lookup_routing_table %s ",route)
                    return route
                else:
                    route["port"] = self.get_port_no_for_ip(route["nexthop"])
                    log.info("lookup_routing_table %s ",route)
                    return route
        return None

    def get_port_data(self, portno):

        '''
        reads the router_if list and
        returns the entry for matching port no
        '''
        for i in self.router_if:
            if i["port"] == portno:
                return i
        return None

    def get_mac_for_ip(self, ip):
        '''
        reads the router_if list and
        returns the mac address of the given input ip
        '''
        for i in self.router_if:
            if i["ip"] == ip:
                return i["mac"]
        return None

    def get_port_no_for_ip(self, ip):
        ''' returns the port number for the given ip
        '''
        for i in self.routes:
            if network_match(i["network"], ip):
                return i["port"]
        return None

