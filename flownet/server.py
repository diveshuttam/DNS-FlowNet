from flask import Flask, escape, request, render_template, Markup, redirect, url_for
from FlowNet import FlowNet, DNSFlowNet, GraphEncoder, Dict2Obj
from collections import namedtuple
app = Flask(__name__)

root=DNSFlowNet()

@app.route('/api/new/',methods=['POST'])
def api_add_flow():
    flow = Dict2Obj(request.form)
    print(flow)
    root.add(flow)
    return redirect(url_for('add_flow'))

@app.route('/api/clear/',methods=['GET'])
def clear():
    global root
    root=DNSFlowNet()
    response=root.json()
    print(response)
    return response

@app.route('/api/flownetdata/',methods=['GET'])
def get_flow_net_data():
    response=root.json()
    return response

@app.route('/', methods=['GET'])
def index():
    return render_template('./index.html')

@app.route('/new',methods=['GET'])
def add_flow():
    return render_template('./new.html')
    
@app.route('/visualize',methods=['GET'])
def view_flow_net():
    response=root.json()
    return render_template('./visualize.html', data=Markup(response), timeout=10000)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000,debug=True)