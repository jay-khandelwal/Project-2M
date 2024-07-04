"""
INFO: request-parser1.1
Parse the request to dictionary where all the headers are key and their value is value

ISSUE: In case of cookie all the cookies are consider as one item

Like:

{
    "method": "GET",
    "path": "/js/module/widgets/dist/latest/evergreen.q4Slideshow.min.js",
    "http-version": "2",
    "Host": "www.expediagroup.com",
    "Cookie": "_ga=GA1.2.663031338.1715958926; _ga_VQ1QGHKQ93=GS1.2.1719936889.5.0.1719936889.0.0.0; _ga_3DSEMMB7M5=GS1.2.1719936890.5.0.1719936890.0.0.0; __uxq412__id.7679=61bdbd5c-f14e-4236-93bb-e0b65a3612e0.1715958940.11.1719936890.1719137578.3e18da3e-3616-4c99-822a-7764419480e4; sp=bd2a27b8-ad23-43b8-940a-704927cf350c; _gcl_au=1.1.363373584.1715959118; _ga_M7VXWVP0TD=GS1.1.1716027412.3.1.1716028079.0.0.0; _ga_ES3HMQNR8X=GS1.1.1716027246.4.0.1716027246.0.0.0; contrast=false",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://www.expediagroup.com/home/default.aspx",
    "Sec-Fetch-Dest": "script",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Site": "same-origin",
    "If-Modified-Since": "Fri, 21 Jun 2024 15:29:18 GMT",
    "If-None-Match": '"97f15e28b437423806470fcfa767baf2"',
    "Priority": "u=2",
    "Te": "trailers",
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

    # Add headers to request info
    request_info.update(headers)
    
    return request_info

request_string = '''GET /js/module/widgets/dist/latest/evergreen.q4Slideshow.min.js HTTP/2
Host: www.expediagroup.com
Cookie: _ga=GA1.2.663031338.1715958926; _ga_VQ1QGHKQ93=GS1.2.1719936889.5.0.1719936889.0.0.0; _ga_3DSEMMB7M5=GS1.2.1719936890.5.0.1719936890.0.0.0; __uxq412__id.7679=61bdbd5c-f14e-4236-93bb-e0b65a3612e0.1715958940.11.1719936890.1719137578.3e18da3e-3616-4c99-822a-7764419480e4; sp=bd2a27b8-ad23-43b8-940a-704927cf350c; _gcl_au=1.1.363373584.1715959118; _ga_M7VXWVP0TD=GS1.1.1716027412.3.1.1716028079.0.0.0; _ga_ES3HMQNR8X=GS1.1.1716027246.4.0.1716027246.0.0.0; contrast=false
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://www.expediagroup.com/home/default.aspx
Sec-Fetch-Dest: script
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
If-Modified-Since: Fri, 21 Jun 2024 15:29:18 GMT
If-None-Match: "97f15e28b437423806470fcfa767baf2"
Priority: u=2
Te: trailers
'''

parsed_request = parse_http_request(request_string)
print(parsed_request)
