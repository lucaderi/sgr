"""Traffic flow REST API module

@autor: Alessandro Ambrogini

"""
import sys
import flask
from flask import jsonify
import threading
import modules.config as config

app = flask.Flask("Traffic Flow Collector API")

@app.route('/', methods=['GET'])
def api():
    retlist = []
    tempdata = config.data
    config.data = {}
    if bool(tempdata):
        for key, value in tempdata.items():
            value['name'] = "flow"
            retlist.append(value)
    
    return jsonify(retlist)

def run():
    app.run(host='0.0.0.0', port=8000, debug=True, use_reloader=False)
   
def run_rest_api():
    t_webApp = threading.Thread(target=run)
    t_webApp.setDaemon(True)
    t_webApp.start()