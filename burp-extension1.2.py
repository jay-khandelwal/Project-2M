from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JButton, JPanel
import csv

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Request Logger")

        # Create GUI components
        self.panel = JPanel()
        self.button = JButton("Enable Logging", actionPerformed=self.toggle_logging)
        self.panel.add(self.button)

        callbacks.customizeUiComponent(self.panel)

        # Create CSV file for logging
        self.csv_file = "burp_requests.csv"
        with open(self.csv_file, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["URL", "Method", "Request", "Response"])

        callbacks.registerHttpListener(self)

    def toggle_logging(self, event):
        if self.button.getText() == "Enable Logging":
            self.button.setText("Disable Logging")
            self.logging_enabled = True
        else:
            self.button.setText("Enable Logging")
            self.logging_enabled = False

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self.logging_enabled and not messageIsRequest:
            url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
            method = self._helpers.analyzeRequest(messageInfo).getMethod()
            request = self._helpers.bytesToString(messageInfo.getRequest())
            response = self._helpers.bytesToString(messageInfo.getResponse())

            with open(self.csv_file, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([url, method, request, response])

    def getTabCaption(self):
        return "Request Logger"

    def getUiComponent(self):
        return self.panel
