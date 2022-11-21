from burp import IBurpExtender
from burp import IProxyListener

class BurpExtender(IBurpExtender, IProxyListener):

  def registerExtenderCallbacks(self, callbacks):
    self.helpers = callbacks.getHelpers()
    self.callbacks = callbacks
    callbacks.setExtensionName('Highlight scope') 
    callbacks.registerProxyListener(self)
    return

  def processProxyMessage(self, messageIsRequest, message):
    if not messageIsRequest:
      return

    message_info = message.getMessageInfo()
    url = self.helpers.analyzeRequest(message_info).getUrl()
    
    if self.callbacks.isInScope(url):
      message_info.setHighlight("green")