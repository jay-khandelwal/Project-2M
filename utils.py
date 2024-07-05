import csv
import json
import os
from urlparse import urlparse, parse_qs
# from openpyxl import Workbook, load_workbook
# from openpyxl.utils import get_column_letter

def parse_http_request(request_string):
    lines = request_string.strip().split("\n")
    
    # Parse the request line
    request_line = lines[0].split()
    method = request_line[0]
    full_path = request_line[1]
    http_version = request_line[2].split('/')[1]
    
    # Parse the path and query parameters separately
    parsed_url = urlparse(full_path)
    path = parsed_url.path
    query_params = parse_qs(parsed_url.query)
    
    # Initialize dictionary with basic information
    request_info = {
        "method": method,
        "path": path,
        "query_params": query_params,
        "http-version": http_version,
    }

    # Parse the headers
    headers = {}
    for line in lines[1:]:
        line = line.replace('\r', '')
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value
            
            # Handle cookies separately
            if key.lower() == "cookie":
                cookies = value.split("; ")
                for cookie in cookies:
                    cookie_name, cookie_value = cookie.split("=", 1)
                    request_info["COOKIE__{}".format(cookie_name)] = cookie_value

    # Add headers to request info (excluding cookies as they are already added)
    for key, value in headers.items():
        if key.lower() != "cookie":
            request_info[key] = value
        
    url_path = urlparse(path).path
    file_extension = os.path.splitext(url_path)[1][1:]  # Get extension without the dot
    request_info["file_extension"] = file_extension
    
    return request_info


def update_json(json_filename, data_dict):
    if os.path.isfile(json_filename):
        with open(json_filename, 'r+') as file:
            try:
                data = json.load(file)
            except ValueError:
                data = []
            
            data.append(data_dict)
            file.seek(0)  # Move the cursor to the beginning of the file
            json.dump(data, file, indent=2)
            file.truncate()  # Truncate remaining content (in case new data is smaller)

    else:
        with open(json_filename, 'w') as file:
            json.dump([data_dict], file, indent=2)