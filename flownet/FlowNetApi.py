import requests

ip = 'localhost'
port = 5000

flownet_server = f"http://{ip}:{port}"
def add_request(dns_id, ip_src, ip_dst, mac_src, mac_dst):
    d = {
        "dns_type":"request",
        "dns_id":dns_id,
        "ip_src":ip_src,
        "ip_dst":ip_dst,
        "mac_src":mac_src,
        "mac_dst":mac_dst
    }
    requests.post(flownet_server+"/api/new/",data=d)

def add_response(dns_id, ip_src, ip_dst, mac_src, mac_dst):
    d = {
        "dns_type":"request",
        "dns_id":dns_id,
        "ip_src":ip_src,
        "ip_dst":ip_dst,
        "mac_src":mac_src,
        "mac_dst":mac_dst
    }
    requests.post(flownet_server+"/api/new/",data=d)

def clear():
    requests.get(flownet_server+"/api/clear/")
