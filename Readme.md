# This is code for my Lab-Oriented Project (LOP) at BITS Pilani
I wish I could have documented this better (PS : As of writing this README It has been 5 years I last touched this). 
The overall gist was that we wanted to detect DDoS attacks in Software Defined Networks (SDN). THe particular ones we were interested in were DNS flood and DNS amplification attacks. For this we sample requests and track them end to end at APPLICATION, IP, MAC levels (which can be used later to penalize the actor). This particularly seems possible with SDN. 
This lab project does the tracking part of the requests that flow through a test network created in mininet.
See docs folder for more details.

<img width="680" alt="Screenshot 2024-06-17 at 3 28 44 AM" src="https://github.com/diveshuttam/DNS-FlowNet/assets/20728015/87fba57a-51cf-4d69-bad7-270370d5ca0d">




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
