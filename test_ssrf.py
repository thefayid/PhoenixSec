import requests
from flask import request

@app.route('/proxy')
def proxy():
    target_url = request.args.get('url', 'http://example.com')
    if not target_url.startswith(("http://example.com", "https://example.com")): raise ValueError("Forbidden URL")
    response = requests.get(target_url, timeout=5)
    return response.text
