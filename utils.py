import csv
import os
# from openpyxl import Workbook, load_workbook
# from openpyxl.utils import get_column_letter

def parse_http_request(request_string):
    lines = request_string.strip().split("\n")
    
    # Parse the request line
    request_line = lines[0].split()
    method = request_line[0]
    full_path = request_line[1].split('?')
    http_version = request_line[2].split('/')[1]
    
    # Initialize dictionary with basic information
    request_info = {
        "method": method,
        "path": full_path[0],
        "query_param": full_path[1] if len(full_path)>1 else None,
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
    
    return request_info



def update_csv(file_name, new_data):
    file_exists = os.path.isfile(file_name)
    headers = set(new_data.keys())
    
    # If the file exists, read existing headers
    if file_exists:
        with open(file_name, mode='rU') as file:
            reader = csv.DictReader(file)
            existing_headers = reader.fieldnames
            headers.update(existing_headers)
    
    headers = list(headers)
    
    # Open the file in write mode to update it
    with open(file_name, mode='a') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        
        # Write the header if the file does not exist
        if not file_exists:
            writer.writeheader()
        
        # Write the new data
        writer.writerow(new_data)
        
        # Rewrite the file to add any new headers to existing rows
        if file_exists and headers != existing_headers:
            with open(file_name, mode='rU') as read_file:
                rows = list(csv.DictReader(read_file))
            
            with open(file_name, mode='w') as write_file:
                writer = csv.DictWriter(write_file, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)
                writer.writerow(new_data)


# def update_excel(workbook_name, data_dict):
#     try:
#         wb = load_workbook(workbook_name)
#     except FileNotFoundError:
#         wb = Workbook()

#     # Assuming we are working with the active sheet
#     sheet = wb.active

#     # Update headers if new keys are found
#     for key in data_dict.keys():
#         if key not in sheet[1]:
#             col_idx = sheet.max_column + 1
#             col_letter = get_column_letter(col_idx)
#             sheet['{}1'.format(col_letter)] = key

#     # Append data to next available row
#     next_row = sheet.max_row + 1
#     for col_idx, key in enumerate(data_dict.keys(), start=1):
#         col_letter = get_column_letter(col_idx)
#         sheet['{}{}'.format(col_letter, next_row)] = data_dict[key]

#     # Save workbook
#     wb.save(workbook_name)
#     print("Updated {} with new data.".format(workbook_name))

    # print(f"Updated {workbook_name} with new data.")



# def update_csv_2(csv_filename, data_dict):
#     # Check if file exists, if not, create it and write headers
#     try:
#         with open(csv_filename, 'r') as file:
#             reader = csv.reader(file)
#             headers = next(reader, [])  # Read headers if file exists
#     except IOError:
#         headers = []

#     with open(csv_filename, 'a') as file:
#         writer = csv.DictWriter(file, fieldnames=headers + list(data_dict.keys()))

#         if not headers:
#             writer.writeheader()  # Write headers if file was just created

#         writer.writerow(data_dict)

    # print(f"Updated {csv_filename} with new data.")

# import csv
# import os

# def update_csv_2(csv_filename, data_dict):
#     file_exists = os.path.isfile(csv_filename)
    
#     # Determine all unique keys from existing headers and current data_dict
#     headers = set()
#     if file_exists:
#         with open(csv_filename, 'r', newline='') as file:
#             reader = csv.reader(file)
#             headers = set(next(reader, []))  # Read existing headers if file exists

#     # Union of current headers and keys from data_dict
#     headers = list(headers.union(data_dict.keys()))

#     # Write data to CSV
#     with open(csv_filename, 'a', newline='') as file:
#         writer = csv.DictWriter(file, fieldnames=headers)
        
#         if not file_exists:
#             writer.writeheader()  # Write headers only if the file is newly created
            
#         writer.writerow(data_dict)

#     print("Updated {} with new data.".format(csv_filename))


import json
import os

def update_json(json_filename, data_dict):
    if os.path.isfile(json_filename):
        with open(json_filename, 'r+') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = []
            
            data.append(data_dict)
            file.seek(0)  # Move the cursor to the beginning of the file
            json.dump(data, file, indent=2)
            file.truncate()  # Truncate remaining content (in case new data is smaller)

    else:
        with open(json_filename, 'w') as file:
            json.dump([data_dict], file, indent=2)

    # print(f"Updated {json_filename} with new data.")
