from flask import Flask, jsonify

app = Flask(__name__)
hits = set()

@app.route('/hit/<token>')
def hit(token):
    hits.add(token)
    return "OK", 200

@app.route('/check/<token>')
def check(token):
    return jsonify({"hit": token in hits})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8002)