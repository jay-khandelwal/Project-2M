import asyncio
import aiohttp
from aiohttp import web
import ssl
from urllib.parse import urlparse

PORT = 8080

async def handle_request(request):
    # Construct the target URL from the incoming request
    url = urlparse(str(request.url))
    target_url = url._replace(scheme=url.scheme or 'http', path=url.path or '/').geturl()

    # Log the request details
    print(f"Request URL: {target_url}")
    print(f"Request Method: {request.method}")
    print("Request Headers:", request.headers)

    # Read the request body if present
    post_data = await request.read()

    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=request.method,
                url=target_url,
                headers=request.headers,
                data=post_data,
                allow_redirects=False,
            ) as response:

                # Log the response details
                print("Response Status Code:", response.status)
                print("Response Headers:", response.headers)

                # Prepare the response
                headers = {k: v for k, v in response.headers.items() if k.lower() not in ['content-encoding', 'transfer-encoding', 'content-length']}
                body = await response.read()

                # Send the response back to the client
                return web.Response(
                    status=response.status,
                    headers=headers,
                    body=body
                )
    except aiohttp.ClientError as e:
        print(f"Error fetching {target_url}: {e}")
        return web.Response(status=500, text='Error fetching the URL.')

async def init_app():
    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', handle_request)
    return app

def run_proxy_server(port, use_https=False):
    app = asyncio.run(init_app())
    if use_https:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile='path/to/cert.pem', keyfile='path/to/key.pem')
        web.run_app(app, port=port, ssl_context=ssl_context)
    else:
        web.run_app(app, port=port)

if __name__ == "__main__":
    use_https = False  # Set to True to enable HTTPS support
    run_proxy_server(PORT, use_https)
