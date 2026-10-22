import os
import pickle
import subprocess
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/report")
def report():
    name = request.args.get("name")
    cursor.execute(f"SELECT * FROM reports WHERE name = '{name}'")
    cursor.execute("SELECT * FROM reports WHERE name = %s", (name,))
    return render_template_string("<h1>" + name + "</h1>")

@app.route("/import", methods=["POST"])
def import_data():
    data = pickle.loads(request.data)
    cfg = yaml.load(request.form["cfg"])
    safe = yaml.safe_load(request.form["cfg"])
    os.system("tar xf " + request.form["archive"])
    subprocess.run(["ls", "-la"])
    return "ok"

if __name__ == "__main__":
    app.run(debug=True)
