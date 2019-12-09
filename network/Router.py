from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
import FlowNetApi
import chardet

from router_lib import router_mgr
#initialze the routermgr 
routermgr = router_mgr()

class Router13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # install dns entry for responses
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src = 53)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 100, match, actions)

        # install dns entry for requests
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst = 53)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 100, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)



    def arp_process(self, rtr, msg, datapath, eth, a, in_port):
        '''
        Receive ARP packets.
        1. ARP Request to the Router IPs(broadcast).
            - update the neighbor informaion to the neighbor table
            - construct and send ARP REPLY Packet
        2. ARP Reply to the Router IPs(unicast).
            - update the neighbor table
        '''
        # Log the ARP packet
        self.logger.info("Received ARP Packet: Opcode %d srcmac: %s dstmac %s srcip %s dstip %s", 
                         a.opcode, a.src_mac, a.dst_mac, a.src_ip, a.dst_ip)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # is this for this router?
        if a.dst_ip in rtr.ips:
            r = rtr.get_mac_for_ip(a.dst_ip)
            if r:
                if(a.opcode == 1):  
                    '''
                    ARP Request Packet received
                    '''
                    self.logger.info("Received ARP Request Packet for this Router... IP %s ", a.dst_ip)
                    rtr.add_neighbor(a.src_mac, a.src_ip)
                    # construct response packet and send it
                    arp_resp = packet.Packet()
                    arp_resp.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                                                            dst=eth.src, src=r))
                    arp_resp.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                                      src_mac=r, src_ip=a.dst_ip,
                                                      dst_mac=a.src_mac,
                                                      dst_ip=a.src_ip))
                    arp_resp.serialize()
                    actions = []
                    actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
                    parser = datapath.ofproto_parser  
                    ofproto = datapath.ofproto
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_resp)
                    datapath.send_msg(out)
                    self.logger.info("Sending ARP Response packet to  %s ",a.src_ip)
                elif(a.opcode == 2):
                    '''
                    ARP Response Packet received
                    '''
                    self.logger.info("Received ARP Reply Packet for this Router...IP %s ", a.dst_ip)
                    rtr.add_neighbor(a.src_mac, a.src_ip)
        else:
            # ignore this ARP REQUEST. its not for this router.
            self.logger.debug("Ignore this ARP Request packet, not for this router")
            return

    def send_arp_request(self, datapath, ethsrc, srcip, dstip, outport):
        '''
        Send ARP Request packet.
        - Generate the ARP Request packet
        '''
        arp_req = packet.Packet()
        arp_req.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP,
                                               dst="ff:ff:ff:ff:ff:ff", src=ethsrc))
        arp_req.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                             src_mac=ethsrc, src_ip=srcip,
                             dst_mac="ff:ff:ff:ff:ff:ff", dst_ip=dstip))
        arp_req.serialize()
        actions = []
        actions.append(datapath.ofproto_parser.OFPActionOutput(outport))
        parser = datapath.ofproto_parser  
        ofproto = datapath.ofproto
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_req)
        datapath.send_msg(out)
        self.logger.info("Generated ARP Request packet, as neighbor details not found.. Who is %s ", dstip)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Get the router object
        rtr = routermgr.get_router(datapath.id)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        srcip = None
        dstip = None
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_port.setdefault(dpid, {})

        # DNS CHECK for flownet
        try:
            pkt_ethernet = eth
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if pkt_ipv4:
                if pkt_ipv4.proto == inet.IPPROTO_UDP:
                    pkt_udp = pkt.get_protocol(udp.udp)
                    data = msg.data
                    is_dns_flow = self._handler_dns(datapath,pkt_ethernet,in_port,pkt_ipv4,pkt_udp,data)
        except BaseException as e:
            raise

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # Check whether is it arp packet, if yes process it 
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            a = pkt.get_protocol(arp.arp)
            self.arp_process(rtr, msg, datapath, eth, a, in_port)
            return

        # check whether is it IP packet?
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
            self.ip_to_port[dpid][srcip] = in_port

            # check whether this packet is for router- destination ip is router ip(mgmt plane)?
            if (dstip in rtr.ips) and (ip.proto == 1):
                ic = pkt.get_protocol(icmp.icmp)
                if ic.type == icmp.ICMP_ECHO_REQUEST:
                    self.logger.info("Received the ICMP Request for this router  %s , we dont handle this currently..dropping the packet ", srcip)
                    return
            else:
                # its a ip forwarding packet 
                self.logger.info("IP PACKET IN -  %s %s", srcip, dstip)
                # Lookup the route for the destination IP
                route = rtr.lookup_routing_table(dstip)
                # if route present, process the packet, else ignore it
                self.logger.info("route details - %s", route)
                if route:
                    # get the forwarding port details
                    outport = route["port"]
                    # identify the src mac for MAC rewriting
                    ethsrc = rtr.get_port_data(outport)["mac"]
                    # get the destination mac. (two case, either directly connected or nexthop)
                    if route["nexthop"]:
                        ethdst = rtr.get_neighbor(route["nexthop"])
                        #print ethdst
                        if ethdst is None:
                            # ethdst is not available in table, generate the ARP Request
                            sip = rtr.get_port_data(outport)["ip"]                           
                            self.send_arp_request(datapath, ethsrc, sip, route["nexthop"], outport)
                            return
                    elif route["scope"] == "link":
                        ethdst = rtr.get_neighbor(dstip)
                        if ethdst is None:
                            # ethdst is not available in table, generate the ARP Request
                            sip = rtr.get_port_data(outport)["ip"]
                            self.send_arp_request(datapath, ethsrc, sip, dstip, outport)
                            return

                    actions = []
                    # build the match for this packet
                    match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip,
                                            ipv4_dst=dstip
                                            )
                    # actions for rewriting the mac
                    actions.append(parser.OFPActionSetField(eth_src=ethsrc))
                    actions.append(parser.OFPActionSetField(eth_dst=ethdst))
                    # decrement TTL
                    actions.append(parser.OFPActionDecNwTtl())

                    # actions for output port
                    actions.append(parser.OFPActionOutput(outport))

                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)

                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
    
    def _handler_dns(self,datapath,pkt_ethernet,port,pkt_ipv4,pkt_udp,data):
        print("***in handle dns***")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt_len = len(data)
        flag = data[42:44]
        dns_id=int.from_bytes(flag,"big",signed=False)
        mac_src = pkt_ethernet.src
        mac_dst = pkt_ethernet.dst
        ip_src = pkt_ipv4.dst
        ip_dst = pkt_ipv4.src
        src_port = pkt_udp.src_port
        dst_port = pkt_udp.dst_port

        if(src_port == 53 or dst_port == 53): 
            ## DNS Packet
            print("****dns packet ***")
            if(dst_port==53): #request
                FlowNetApi.add_request(dns_id, ip_src, ip_dst, mac_src, mac_dst)
            if(src_port==53): #response
                FlowNetApi.add_response(dns_id, ip_src, ip_dst, mac_src, mac_dst)
            return True
        
        return False