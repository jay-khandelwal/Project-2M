"""
INFO: request-parser1.2
Parse the request to dictionary where all the headers are key and their value is value

FIX: In case of cookie all the cookies are consider as a seperate item. 
In order to put something so that we can find if it is a cookie i have added a prefix `COOKIE__{cookie name}` to each cookie name

Like:

{
    "method": "GET",
    "path": "/about-us/",
    "http-version": "1.1",
    "COOKIE___ga": "GA1.2.663031338.1715958926",
    "COOKIE___ga_VQ1QGHKQ93": "GS1.2.1719936889.5.0.1719936889.0.0.0",
    "COOKIE___ga_3DSEMMB7M5": "GS1.2.1719936890.5.0.1719936890.0.0.0",
    "COOKIE____uxq412__id.7679": "61bdbd5c-f14e-4236-93bb-e0b65a3612e0.1715958940.11.1719936890.1719137578.3e18da3e-3616-4c99-822a-7764419480e4",
    "COOKIE__sp": "bd2a27b8-ad23-43b8-940a-704927cf350c",
    "COOKIE___gcl_au": "1.1.363373584.1715959118",
    "COOKIE___ga_M7VXWVP0TD": "GS1.1.1716027412.3.1.1716028079.0.0.0",
    "COOKIE___ga_ES3HMQNR8X": "GS1.1.1716027246.4.0.1716027246.0.0.0",
    "COOKIE__contrast": "false",
    "Host": "www.dyfolabs.com",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://www.dyfolabs.com/contact-us/",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Priority": "u=1",
    "Te": "trailers",
    "Connection": "keep-alive",
}

"""


def parse_http_request(request_string):
    lines = request_string.strip().split("\n")
    
    # Parse the request line
    request_line = lines[0].split()
    method = request_line[0]
    path = request_line[1]
    http_version = request_line[2].split('/')[1]
    
    # Initialize dictionary with basic information
    request_info = {
        "method": method,
        "path": path,
        "http-version": http_version,
    }
    
    # Parse the headers
    headers = {}
    for line in lines[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value
            
            # Handle cookies separately
            if key.lower() == "cookie":
                cookies = value.split("; ")
                for cookie in cookies:
                    cookie_name, cookie_value = cookie.split("=", 1)
                    request_info[f"COOKIE__{cookie_name}"] = cookie_value

    # Add headers to request info (excluding cookies as they are already added)
    for key, value in headers.items():
        if key.lower() != "cookie":
            request_info[key] = value
    
    return request_info

# Example usage
request_string = """GET /about-us/ HTTP/1.1
Host: www.dyfolabs.com
Cookie: _ga=GA1.2.663031338.1715958926; _ga_VQ1QGHKQ93=GS1.2.1719936889.5.0.1719936889.0.0.0; _ga_3DSEMMB7M5=GS1.2.1719936890.5.0.1719936890.0.0.0; __uxq412__id.7679=61bdbd5c-f14e-4236-93bb-e0b65a3612e0.1715958940.11.1719936890.1719137578.3e18da3e-3616-4c99-822a-7764419480e4; sp=bd2a27b8-ad23-43b8-940a-704927cf350c; _gcl_au=1.1.363373584.1715959118; _ga_M7VXWVP0TD=GS1.1.1716027412.3.1.1716028079.0.0.0; _ga_ES3HMQNR8X=GS1.1.1716027246.4.0.1716027246.0.0.0; contrast=false
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://www.dyfolabs.com/contact-us/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Priority: u=1
Te: trailers
Connection: keep-alive"""

parsed_request = parse_http_request(request_string)
print(parsed_request)
