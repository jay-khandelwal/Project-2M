'''
Just for testing burp extension for first time.

Put all the request/response in a CSV in asshole manner
'''

import os
from burp import IBurpExtender
from burp import IHttpListener
import csv

class BurpExtender(IBurpExtender, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Request Logger")

        # Create CSV file for logging
        self.csv_file = "burp_requests.csv"
        print("Current Working Directory:", os.getcwd())
        try:
            with open(self.csv_file, 'w') as file:
                writer = csv.writer(file)
                writer.writerow(["URL", "Method", "Request", "Response"])
        except Exception as e:
            print("Error creating CSV file: {}".format(e))

        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            print("yep....")
            try:
                url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
                method = self._helpers.analyzeRequest(messageInfo).getMethod()
                request = self._helpers.bytesToString(messageInfo.getRequest())
                response = self._helpers.bytesToString(messageInfo.getResponse())

                with open(self.csv_file, 'a') as file:
                    writer = csv.writer(file)
                    writer.writerow([url, method, request, response])
            except Exception as e:
                print("Error processing HTTP message: {}".format(e))
