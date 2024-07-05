
import os
from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JPanel, JButton, JScrollPane, JTextArea, BoxLayout

import csv

from utils import parse_http_request, update_json

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Request Logger 1.2")


        # Set up the GUI
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        self.button = JButton("Enable Logging", actionPerformed=self.toggle_logging)
        self.panel.add(self.button)

        self.log_area = JTextArea(10, 30)
        self.log_area.setEditable(False)
        self.scroll_pane = JScrollPane(self.log_area)
        self.panel.add(self.scroll_pane)

        # Add the custom tab to Burp Suite
        callbacks.customizeUiComponent(self.panel)
        callbacks.addSuiteTab(self)

        # Set the initial state
        self.logging_enabled = True

        callbacks.registerHttpListener(self)



    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self.logging_enabled and not messageIsRequest:
            print("yep....")
            try:
                request = self._helpers.bytesToString(messageInfo.getRequest())
                request_dict = parse_http_request(request)
                # url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
                # method = self._helpers.analyzeRequest(messageInfo).getMethod()
                # response = self._helpers.bytesToString(messageInfo.getResponse())

                response = messageInfo.getResponse()
                mime_type = self.get_mime_type(response)

                request_dict['mime_type'] = mime_type

                update_json("data.json", request_dict)

                # with open(self.csv_file, 'a') as file:
                #     writer = csv.writer(file)
                #     writer.writerow([url, method, request, response])
            except Exception as e:
                print("Error processing HTTP message: {}".format(e))
    
    def getTabCaption(self):
        return "Request Logger"

    def getUiComponent(self):
        return self.panel

    def toggle_logging(self, event):
        self.logging_enabled = not self.logging_enabled
        self.button.setText("Disable Logging" if self.logging_enabled else "Enable Logging")
        self.log_area.append("Logging {}\n".format("enabled" if self.logging_enabled else "disabled"))


    def get_mime_type(self, response_bytes):
        response_info = self._helpers.analyzeResponse(response_bytes)
        headers = response_info.getHeaders()
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":")[1].strip()
        return "unknown"
