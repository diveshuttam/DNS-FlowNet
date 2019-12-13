# Run all the following in different terminals

## run the LAN(Switch) and WAN(Router) controller in different terminals
cd network
ryu-manager --ofp-tcp-listen-port 6654 --app-lists=Swtich.py
ryu-manager --ofp-tcp-listen-port 6653 --app-lists=Router.py

## run the flownet server
cd flownet
python3 server.py

## run the mininet
// this is the onlypart written in python2 as mininet is python2 one  
cd network  
sudo python2 topology_sw.py  

## run pingall on minnet shell
pingall # creates entries in routers 

## run dns server in mininet shell
h9 sudo python3 ../dns/DnsServer.py h9 & 

## create requests on mininet shell or the web
h1  python3 ../dns/DnsRequest.py h9 "h2" 

## visualize flownet
open http://localhost:5000/visualise in a browser  
