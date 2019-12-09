#!/usr/bin/python

"""Routing Topology
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController

class RoutingTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1',dpid='1', failMode='standalone')
        s2 = self.addSwitch('s2',dpid='2', failMode='standalone')
        s3 = self.addSwitch('s3',dpid='3', failMode='standalone')

        r1 = self.addSwitch('r1',dpid='4')
        r2 = self.addSwitch('r2',dpid='5')
        r3 = self.addSwitch('r3',dpid='6')
        r4 = self.addSwitch('r4',dpid='7')
        r5 = self.addSwitch('r5',dpid='8')
        r6 = self.addSwitch('r6',dpid='9')        

        h1 = self.addHost('h1', mac="00:00:00:00:00:01", ip="10.0.1.2/24", defaultRoute="via 10.0.1.1")
        h2 = self.addHost('h2', mac="00:00:00:00:00:02", ip="10.0.1.3/24", defaultRoute="via 10.0.1.1")
        h3 = self.addHost('h3', mac="00:00:00:00:00:03", ip="10.0.1.4/24", defaultRoute="via 10.0.1.1")

        h4 = self.addHost('h4', mac="00:00:00:00:00:04", ip="192.168.30.2/24", defaultRoute="via 192.168.30.1")
        h5 = self.addHost('h5', mac="00:00:00:00:00:05", ip="192.168.30.3/24", defaultRoute="via 192.168.30.1")
        h6 = self.addHost('h6', mac="00:00:00:00:00:06", ip="192.168.30.4/24", defaultRoute="via 192.168.30.1")

        h7 = self.addHost('h7', mac="00:00:00:00:00:07", ip="172.0.1.2/24", defaultRoute="via 172.0.1.1")
        h8 = self.addHost('h8', mac="00:00:00:00:00:08", ip="172.0.1.3/24", defaultRoute="via 172.0.1.1")
        h9 = self.addHost('h9', mac="00:00:00:00:00:09", ip="172.0.1.4/24", defaultRoute="via 172.0.1.1")

        #addlink(hostname,switchname,hostport,switchport)                       
        self.addLink(h1, s1, 1, 1)
        self.addLink(h2, s1, 1, 2)
        self.addLink(h3, s1, 1, 3)

        self.addLink(h4, s2, 1, 1)
        self.addLink(h5, s2, 1, 2)
        self.addLink(h6, s2, 1, 3)

        self.addLink(h7, s3, 1, 1)
        self.addLink(h8, s3, 1, 2)
        self.addLink(h9, s3, 1, 3)


        self.addLink(r1, s1, 1, 4)
        self.addLink(r2, s2, 1, 4)
        self.addLink(r3, s3, 1, 4)

        self.addLink(r1, r4, 2, 1)
        self.addLink(r2, r4, 2, 2)
        self.addLink(r3, r6, 2, 1)

        self.addLink(r4, r5, 3, 1)
        self.addLink(r6, r5, 2, 2)

if __name__ == '__main__':
    setLogLevel('info')
    topo = RoutingTopo()

    net = Mininet(topo=topo, build=False)
    # C0 is the wan controller 
    c0 = net.addController(name='c0',controller=RemoteController,
                           ip='127.0.0.1', protocol='tcp', port=6653)
    # c1 is the lan controller
    c1 = net.addController(name='c1',controller=RemoteController,
                           ip='127.0.0.1', protocol='tcp', port=6654)

    net.start()

    for controller in net.controllers:
        controller.start()


    net.get('s1').start([c1])
    net.get('s2').start([c1])
    net.get('s3').start([c1])

    net.get('r1').start([c0])
    net.get('r2').start([c0])
    net.get('r3').start([c0])
    net.get('r4').start([c0])
    net.get('r5').start([c0])
    net.get('r6').start([c0])
    CLI(net)
    net.stop()
