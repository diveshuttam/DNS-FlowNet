from json import JSONEncoder,dumps
class Dict2Obj(object):
    """
    Turns a dictionary into a class
    """
 
    def __init__(self, dictionary):
        """Constructor"""
        for key in dictionary:
            setattr(self, key, dictionary[key])
 
    def __repr__(self):
        """"""
        attrs = str([x for x in self.__dict__])
        return "<Dict2Obj: %s>" % attrs
 
class GraphEncoder(JSONEncoder):
    def default(self, o):
        return o.obj()

class Node:
    def __init__(self,next_=None,previous=None,parent=None,children=[]):
        self.next=next_
        self.previous=previous
        self.parent=parent
        self.children=children
    
    def add_child(self,child_node):
        if(len(self.children)==0):
            self.children=[child_node]
        else:
            self.children.append(child_node)
    
    def set_next(self, next_):
        self.next=next_
    
    def set_previous(self, previous_):
        self.previous=previous_
    
    def set_parent(self, parent):
        self.parent=parent
    
    def obj(self):
        return ""


class DNSNode(Node):
    def __init__(self,flow):
        assert flow.dns_type in ['request','response']
        super().__init__()
        self.type=flow.dns_type
        self.dns_id = flow.dns_id
        self.add(packet=flow)

    def obj(self):
        j = {
            "innerHTML":f"dns_id:{self.dns_id}<br/>type:{self.type}",
            "collapsed":False,
            "children": self.children,
            "HTMLclass": "dns"
        }

        return j

    def add(self, packet, prop_below=False):
        if(prop_below==True):
            self.children[-1].add(packet)
        else:
            ip_node = IPNode(packet)
            self.add_child(ip_node)

class IPNode(Node):
    def __init__(self,packet):
        super().__init__()
        self.ip_src = packet.ip_src 
        self.ip_dst = packet.ip_dst 
        self.add(packet)
    
    def obj(self):
        j = {
            "innerHTML":f"ip_src:{self.ip_src}<br/>ip_dst:{self.ip_dst}",
            "collapsed":False,
            "children":self.children,
            "HTMLclass":"ip"
        }
        return j
    def add(self,packet):
        mac_node=MACNode(packet)
        self.add_child(mac_node)

class MACNode(Node):
    def __init__(self,packet):
        super().__init__()
        self.mac_src=packet.mac_src
        self.mac_dst=packet.mac_dst
    

    def obj(self):
        j = {
            "innerHTML":f"mac_src:{self.mac_src}<br/>mac_dst:{self.mac_dst}",
            "collapsed":False,
            "children":self.children,
            "HTMLclass":"mac"
        }
        return j

class FlowNet():
    def __init__(self,name):
        self.name=name
        self.nodes=[]
        self.flow_map={}
        Host.ip_list=set()

    def add(self,flow):
        dns_node = DNSNode(flow)
        self.nodes.append(dns_node)
        return dns_node

    def obj(self):
        j={
            "text":{
                "name":self.name,
            },
            "children":self.nodes
        }
        return j

"""
all requests and responses for a single ip
"""
class Host():
    ip_list=set()
    def __init__(self, ip):
        ip_list=Host.ip_list
        if ip not in ip_list:
            self.ip=ip
            ip_list.add(ip)
            self.requests_made_map = {}
            self.responses_given_map = {}
            # self.responses_recieved_map = {}
            # self.requests_received_map = {}
        else:
            raise("IP already in IPMap")
    
    def add(self, flow, dns_node):
        if(flow.dns_type=='request'):
            self.add_in_request(flow,dns_node)
        elif(flow.dns_type=='response'):
            self.add_in_response(flow,dns_node)

    def find(self,flow):
        if(flow.dns_type=='request'):
            self.find_in_request(flow)
        elif(flow.dns_type=='response'):
            self.find_in_response(flow)

    def find_in_request(self,flow):
        if flow.ip_dst in self.requests_made_map:
            flows_bw_hostpair = self.requests_made_map[flow.ip_dst]
            if(flow.dns_id in flows_bw_hostpair):
                return flows_bw_hostpair[flow.dns_id]
        return None

    def find_in_response(self,flow):
        if flow.ip_src in self.responses_given_map:
            flows_bw_hostpair = self.responses_given_map[flow.ip_dst]
            if(flow.dns_id in flows_bw_hostpair):
                return flows_bw_hostpair[flow.dns_id]
        return None

    def add_in_request(self,flow,dns_node):
        if(flow.ip_dst not in self.requests_made_map):
            self.requests_made_map[flow.ip_dst]={}
        self.requests_made_map[flow.ip_dst][flow.dns_id]=dns_node

    def add_in_response(self,flow,dns_node):
        if(flow.ip_src not in self.responses_given_map):
            self.requests_made_map[flow.ip_src]={}
        self.requests_made_map[flow.ip_src][flow.dns_id]=dns_node

    def __hash__(self):
        return self.ip

class DNSFlowNet():
    def __init__(self,):
        self.request_flownet = FlowNet("request_net") # according to source
        self.response_flownet = FlowNet("response_net") # according to destination
        self.ip_map={}

    def add(self,packet):
        existing_flow_node = None
        if(packet.dns_type=='request'):
            # get host
            if packet.ip_src in self.ip_map:
                host=self.ip_map[packet.ip_src]
                existing_flow_node = host.find_in_request(packet)
            else:
                host=self.ip_map[packet.ip_src]=Host(packet.ip_src)

            if(existing_flow_node is None):
                node = self.request_flownet.add(packet)
                host.add_in_request(flow=packet,dns_node=node)
            else:
                prop_below = False if "new_ip" in dir(packet) else True
                existing_flow_node.add(packet, prop_below=prop_below)

        if(packet.dns_type=='response'):
            # get host
            if packet.ip_dst in self.ip_map:
                host=self.ip_map[packet.ip_dst]
                existing_flow_node = host.find_in_response(packet)
            else:
                host=self.ip_map[packet.ip_dst]=Host(packet.ip_dst)

            if(existing_flow_node is None):
                node = self.response_flownet.add(packet)
                host.add_in_response(flow=packet,dns_node=node)
            else:
                prop_below = False if "new_ip" in dir(packet) else True
                existing_flow_node.add(packet, prop_below=prop_below)


    def obj(self,):
        j = {
            "nodeStructure":{
                "text":{
                    "name":"flownet"
                },
                "children":[
                    self.request_flownet,
                    self.response_flownet
                ]
            }
        }
        return j

    def json(self,):
        s=dumps(self,cls=GraphEncoder,indent=4)
        print(s)
        return s