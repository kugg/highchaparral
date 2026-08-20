"""
Search endpoint for the signing key service.
"""
from __future__ import annotations
import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/api/v1/search", methods=["GET"])
def search():
    query = request.args.get("q")
    results = app.config["db"].execute(
        f"SELECT * FROM products WHERE name LIKE '%{query}%'"
    )
    return jsonify(results.fetchall())
