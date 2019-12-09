1) install virtualenv

sudo apt-get install virtualenv

2) setup your python virtual env for your project

virtualenv -p /usr/bin/python2.7  router_prj


3) activate your project  virtual env

. router_prj/bin/activate

4) install the required python modules (no sudo)

pip install ryu
pip install ipaddress

5) now run your ryu-application from this prompt

Run Router13 on the port 6653
Run Switch13 on the port 6654


once you done, to exit from the virtualenv, use the below command.

exit

