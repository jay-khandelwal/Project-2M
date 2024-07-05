import csv
import os

_dict = [
{
    "method": "GET",
    "path": "/feed/ContentAsset.svc/GetContentAssetList?LanguageId=1&assetType=Home%20cta&pageSize=-1&pageNumber=0&tagList=&includeTags=true&year=-1&excludeSelection=1",
    "http-version": "2",
    "COOKIE___ga": "GA1.2.663031338.1715958926",
    "COOKIE___ga_VQ1QGHKQ93": "GS1.2.1720101644.7.1.1720101920.0.0.0",
    "COOKIE___ga_3DSEMMB7M5": "GS1.2.1720101644.7.1.1720101920.0.0.0",
    "COOKIE____uxq412__id.7679": "61bdbd5c-f14e-4236-93bb-e0b65a3612e0.1715958940.13.1720101920.1720098788.95af7c2d-6993-4c8d-a117-11767dc731cd",
    "COOKIE__sp": "bd2a27b8-ad23-43b8-940a-704927cf350c",
    "COOKIE___gcl_au": "1.1.363373584.1715959118",
    "COOKIE___ga_M7VXWVP0TD": "GS1.1.1716027412.3.1.1716028079.0.0.0",
    "COOKIE___ga_ES3HMQNR8X": "GS1.1.1716027246.4.0.1716027246.0.0.0",
    "COOKIE__contrast": "false",
    "COOKIE___gid": "GA1.2.311308865.1720098757",
    "COOKIE____uxq412__ses.7679": "*",
    "COOKIE___gat": "1",
    "COOKIE___gat_Client": "1",
    "Host": "www.expediagroup.com",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "If-None-Match": '"345a0002b6797962f178ea06492e67d4"',
    "Priority": "u=6",
    "Cache-Control": "max-age=0",
    "Te": "trailers",
},
{
    "method": "GET",
    "path": "/about-us/",
    "http-version": "1.1",
    "COOKIE__csrftoken": "z7ZFtRm3oQFwDdn8cZp4C7Vh23mFTJm2ItqjQjA6TazPE8FuZs91YxY7Cf84UefW",
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
]



def update_csv(file_name, new_data):
    file_exists = os.path.isfile(file_name)
    headers = set(new_data.keys())
    
    # If the file exists, read existing headers
    if file_exists:
        with open(file_name, mode='r', newline='') as file:
            reader = csv.DictReader(file)
            existing_headers = reader.fieldnames
            headers.update(existing_headers)
    
    headers = list(headers)
    
    # Open the file in write mode to update it
    with open(file_name, mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        
        # Write the header if the file does not exist
        if not file_exists:
            writer.writeheader()
        
        # Write the new data
        writer.writerow(new_data)
        
        # Rewrite the file to add any new headers to existing rows
        if file_exists and headers != existing_headers:
            with open(file_name, mode='r', newline='') as read_file:
                rows = list(csv.DictReader(read_file))
            
            with open(file_name, mode='w', newline='') as write_file:
                writer = csv.DictWriter(write_file, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)
                writer.writerow(new_data)

for i in _dict:
    update_csv("new.csv", i)