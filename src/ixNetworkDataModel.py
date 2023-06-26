""" 
ixNetworkDataModel.py

Description:
   This is the entry point file containing IxNetwork API executions
   in which it uses the ixnetwork_restpy package to execute ReST-APIs.
   
   This app takes in an user input data-model file that describes  
   how to configure IxNetwork.
   You can find examples of the data-model file in any of the Applets in
   the ConfigParameters folder.

Requirements:
   - Runs on Linux OS only.
   - pip install requests, PyYaml
   - data-model yml config file

   - Optional: pip install ixnetwork_restpy
      - This ixNetworkDataModel package comes with ixnetwork_restpy.
        You should see the ixnetwork_restpy folder in the same 
        path location as this file.

   For port capturing requirements:
      - IxNetwork Wireshark installed
      - Linux OS wireshark installed
      - sudo chmod o+x /usr/bin/dumpcap (For redhat distributions)
      - sudo chmod o+x /usr/sbin/dumpcap (For ubuntu distributions)
        
Tested with:
   - IxNetwork Windows and Linux API server: 9.30
   - IxVM 9.30
"""
from port import Ports, PortCapture
from trafficItem import TrafficItem
from ngpf import NGPF

from ixnetwork_restpy import SessionAssistant

class ConfigIxNetworkRestPy:
    def __init__(self, dataModelFile: str=None, dataModelObj: object=None, 
                 sessionName: str=None, sessionId: int=None, 
                 apiKey: str=None, clearConfig: bool=True,
                 logLevel: str='info', logFilename: str='test.log', keystackObj: object=None) -> None:
        """
        This class uses RestPy to configure IxNetwork based on a data model yml config file
        that the user must provide.  The data model follows the IxNetwork API architectural
        design.
        
        Requirements:
            - Data model yml file
             
        Parameters:
           dataModelFile: The config yml file containing user inputs to configure IxNetwork
           dataModelObj:  The data model object in a dict format
           sessionName:   For Linux API server. Naming your session.
           sessionId:     For Linux API server. The existing sessionId to connect to.
           apiKey:        For Linux API server. The API-Key to use for REST calls
           clearConfig:   Defaults to True. Start a new configuration from blank.
           logLevel:      Log verbosity. info, warning, debug, failed
           logFilename:   The name of the log file
           keystackObj:   Keystack integration object
        """
        if keystackObj:
            self.keystackObj = keystackObj
            self.configs = keystackObj.testcaseConfigParams['configParams']
        else:
            self.keystackObj = None
            if dataModelFile: 
                self.configs = utilities.readYamlFile(yamlFile=dataModelFile)
            elif dataModelObj:
                self.configs = dataModelObj
            else:
                raise("You must provide either a data-model file or a data-model object")
          
        self.session = SessionAssistant(IpAddress=self.configs['ixNetworkApiServerIp'], 
                                        RestPort=self.configs.get('restPort', None), 
                                        UserName=self.configs['username'], Password=self.configs['password'],
                                        SessionName=sessionName, SessionId=sessionId, ApiKey=apiKey, ClearConfig=clearConfig, 
                                        LogLevel=logLevel,
                                        LogFilename=logFilename)
        
        self.restpy = self.session.Ixnetwork
        self.ngpf = NGPF(self) 
        self.trafficItem = TrafficItem(self)
        self.portCapture = PortCapture(self)
        self.ports = Ports(self)

    def deleteSession(self) -> None:
        """
        For Linux API server only.  Delete the session.
        """
        self.logInfo('Releasing session')
        self.session.Session.remove()
        
    def closeAllTabs(self) -> None:
        """ 
        Close all previous packet captures
        """
        self.logInfo(f'Close all tabs')
        self.restpy.CloseAllTabs()

    def logInfo(self, msg):
        self.restpy.info(msg)
        if self.keystackObj:
            self.keystackObj.logInfo(msg)

    def logWarning(self, msg):
        self.restpy.warn(msg)
        if self.keystackObj:
            self.keystackObj.logWarning(msg)

    def logDebug(self, msg):
        self.restpy.debug(msg)
        if self.keystackObj:
            self.keystackObj.logDebug(msg)

    def logFailed(self, msg):
        self.restpy.warn(msg)
        if self.keystackObj:
            self.keystackObj.logFailed(msg)

    def logError(self, msg):
        self.restpy.warn(msg)
        if self.keystackObj:
            self.keystackObj.logError(msg)


                
                

                    
