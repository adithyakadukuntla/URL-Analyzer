import socket
from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse
import json

app = Flask(__name__)

def analyze_url(url):
    try:
        response = requests.get(url)
        parsed_uri = urlparse(url)
        domain = '{uri.netloc}'.format(uri=parsed_uri)
        ip_address = socket.gethostbyname(domain)
        whois_response = requests.get(f'http://whois.arin.net/rest/ip/{ip_address}.json')
        whois_data = json.loads(whois_response.text)
        serverN = whois_data['net']['orgRef']['@name']
        server_host = response.headers.get('server')
        http_headers = response.headers
        status_code = response.status_code
        return ip_address, serverN, server_host, http_headers, status_code
    except Exception as e:
        return str(e), None, None, {}, None

@app.route('/')
def index():
    return render_template('index3.html')

@app.route('/', methods=['POST'])
def analyze():
    url = request.form['url']
    ip_address, serverN, server_host, http_headers, status_code = analyze_url(url)
    return render_template('result.html', url=url, ip=ip_address, server=serverN, host=server_host, headers=http_headers, status_code=status_code)

if __name__ == '__main__':
    app.run(debug=True)
