"""Flask service with the usual bad habits."""
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    output = os.system("ping -c 1 " + request.args.get("host"))  # aegis:expect command-injection
    return str(output)


app.run(host="0.0.0.0", debug=True)  # aegis:expect flask-debug-enabled
