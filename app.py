#!/usr/bin/python3
from flask import Flask, abort, make_response, request
import json
app = Flask(__name__)
tasks = [
    {
        "id":1,
        "title": u"buy groceries",
        "description": u"milk,cheese,pizza",
        "done": False
    },
    {
        "id": 2,
        "title": u"learn python",
        "description": u"need to go out and find a good tutorial",
        "done": False
    }
]

@app.route("/api/tasks",methods=["GET"])
def get_tasks():
    return json.dumps({"tasks": tasks})

@app.route("/api/tasks/<int:task_id>", methods=["GET"])
def get_task(task_id):
    task = [task for task in tasks if task["id"] == task_id]
    if len(task) == 0:
        abort(404)
    return json.dumps({"task":task[0]})

@app.route("/api/tasks",methods=["POST"])
def create_task():
    if not request.json or not "title" in request.json:
        abort(400)
    task = {
        "id": tasks[-1]["id"] + 1,
        "title": request.json["title"],
        "description": request.json.get("description", ""),
        "done": False
    }
    tasks.append(task)
    return json.dumps({"task":task}),201
    
@app.errorhandler(404)
def not_found(error):
    return make_response(json.dumps({"error":"not found"}),404)

if __name__ == "__main__":
    app.run(debug=True)
