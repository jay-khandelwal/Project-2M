import http.server
import socketserver
import ssl
import requests
from urllib.parse import urlsplit

PORT = 8080

class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        url_components = urlsplit(self.path)
        target_url = f"{url_components.scheme}://{url_components.netloc}{url_components.path}"

        if url_components.query:
            target_url += f"?{url_components.query}"

        # Log the request details
        print(f"Request URL: {target_url}")
        print(f"Request Method: {self.command}")
        print("Request Headers:", self.headers)

        # Read the request body if present
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else None

        try:
            # Forward the request to the target server
            if self.command == 'GET':
                response = requests.get(target_url, headers=self.headers, stream=True)
            elif self.command == 'POST':
                response = requests.post(target_url, headers=self.headers, data=post_data, stream=True)

            # Log the response details
            print("Response Status Code:", response.status_code)
            print("Response Headers:", response.headers)

            # Send the response back to the client
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                if key.lower() not in ['content-encoding', 'transfer-encoding', 'content-length']:
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(response.content)))
            self.end_headers()

            self.wfile.write(response.content)
        except requests.RequestException as e:
            print(f"Error fetching {target_url}: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Error fetching the URL.')

def run_proxy_server(port, use_https=False):
    handler = ProxyHTTPRequestHandler
    httpd = socketserver.TCPServer(("", port), handler)

    if use_https:
        httpd.socket = ssl.wrap_socket(httpd.socket,
                                       server_side=True,
                                       certfile='./cert.pem',  # Replace with your path
                                       keyfile='./key.pem',    # Replace with your path
                                       ssl_version=ssl.PROTOCOL_TLS)

    print(f"Starting proxy server on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    use_https = False  # Set to True to enable HTTPS support
    run_proxy_server(PORT, use_https)
