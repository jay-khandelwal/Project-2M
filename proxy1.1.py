import http.server
import socketserver
import ssl
import requests

PORT = 8080

class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        target_url = self.path

        # Log the request details
        print(f"Request URL: {target_url}")
        print(f"Request Method: {self.command}")
        print("Request Headers:", self.headers)

        # Read and log the request body if present
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length else None
        if post_data:
            print("Request Body:", post_data.decode('utf-8'))

        # Forward the request to the target server
        try:
            if self.command == 'GET':
                response = requests.get(target_url, headers=self.headers)
            elif self.command == 'POST':
                response = requests.post(target_url, headers=self.headers, data=post_data)

            # Log the response details
            print("Response Status Code:", response.status_code)
            print("Response Headers:", response.headers)
            print("Response Content:", response.text[:500], "...")  # Print first 500 characters

            # Send the response back to the client
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                self.send_header(key, value)
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
                                       certfile='./cert.pem',
                                       keyfile='./key.pem',
                                       ssl_version=ssl.PROTOCOL_TLS)

    print(f"Starting proxy server on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    # Set to True if you want to enable HTTPS support (and provide the correct paths to your cert and key files)
    use_https = False
    run_proxy_server(PORT, use_https)
