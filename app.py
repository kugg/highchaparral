@app.route('/api/v1/search', methods=['GET'])
def search():
    query = request.args.get('q')
    results = db.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")
    return jsonify(results.fetchall())
// trigger
