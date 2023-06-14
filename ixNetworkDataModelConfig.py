""" 
ixNetworkDataModelConfig.py

Description:
   Library file containing IxNetwork-Restpy API executions.
   This app takes in an user input data-model file that describes  
   how to configure IxNetwork.

version: 1.2.0

Release notes:
    - Enhanced getDataPlaneCaptureFile() to include writing captured packets to txt file.  
    - Added keystackObj to integrate testing with Keystack framework

Requirements:
   - pip install ixnetwork_restpy
   - IxNetwork Wireshark installed
   - Linux OS wireshark installed
   - sudo chmod o+x /usr/bin/dumpcap (For redhat distributions)
   - sudo chmod o+x /usr/sbin/dumpcap (For ubuntu distributions)
   - data-model yml config file
        
Tested with:
   - IxNetwork Windows and Linux API server: 9.30
   - IxVM 9.30
   
"""
import sys, os, yaml, time, traceback, subprocess, datetime, platform
from pathlib import Path

from ixnetwork_restpy import SessionAssistant

currentDir = os.path.abspath(os.path.dirname(__file__))


def readYamlFile(yamlFile:str) -> dict:
    with open(yamlFile, mode='r', encoding='utf8') as yamlData:
        try:
            # For yaml version >5.1
            return yaml.load(yamlData, Loader=yaml.FullLoader)
        except yaml.YAMLError as exception:
            # Show the Yaml syntax error
            raise exception
        except:
            return yaml.safe_load(yamlData) 

def getTimestamp(includeMillisecond: bool=False) -> str:
    now = datetime.datetime.now()

    if includeMillisecond:
        timestamp = now.strftime('%m-%d-%Y-%H:%M:%S:%f')
    else:
        timestamp = now.strftime('%m-%d-%Y-%H:%M:%S')

    return timestamp

def enterLinuxCmd(command: list, shell: bool=True) -> None:
    """
    Enter Linux commands on the local host
    
    If setting shell=True, the command parameter needs to be a string.
    If setting shell=False, the command parameter needs to be a list.
    
    Returns the stdout for parsing
    """
    result = subprocess.Popen(command, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=shell)
    result,err = result.communicate()

    for line in result.decode('utf-8').split('\n'):
        if line:
            if type(line) is bytes:
                line = line.decode('utf-8')

            print('-> ', line)

    return result.decode('utf-8')

  
class ConfigIxNetworkRestPy:
    def __init__(self, dataModelFile: str, sessionName: str=None, sessionId: int=None, 
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
            self.configs = readYamlFile(yamlFile=dataModelFile)
        
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


class Ports:
    def __init__(self, mainObj):
        self.mainObj = mainObj
                                                   
    def getPortList(self) -> list:
        """ 
        Helper function to get the portList in a certain format
        """
        portList = []
        for port in self.mainObj.configs['ports']:
            name = port['name']
            chassis = port['port'].split(',')[0]
            slot = port['port'].split(',')[1]
            portNum = port['port'].split(',')[2]
            portList.append([chassis, slot, portNum, name])

        return portList

    def assignPorts(self) -> dict:
        """ 
        Assign physical ports to a virtual port
        """
        try:
            portMap = self.mainObj.session.PortMapAssistant()
            self.vport = dict()
            for index,port in enumerate(self.getPortList()):
                portName = port[3]
                self.mainObj.logInfo(f'Creating vport: {portName}')
                self.vport[portName] = portMap.Map(IpAddress=port[0], CardId=port[1], PortId=port[2], Name=portName)
                
            self.mainObj.logInfo(f'Configuring port mapping')
            portMap.Connect(self.mainObj.configs.get('forceTakePortOwnership', True))
            return self.vport
        except:
            raise

    def releasePorts(self) -> None:
        for vport in self.mainObj.restpy.Vport.find():
            self.mainObj.logInfo(f'Releasing port: {vport.Name}')
            vport.ReleasePort()
            

class PortCapture:
    def __init__(self, mainObj: object) -> None:
         self.mainObj = mainObj
                     
    def configure(self) -> None:
        """    
        Enable packet capturing
        
        {'name': 'Host1', 'port': '192.168.28.5, 1, 1', 
         'packetCapture': {'enable': False, 'rxMode': 'captureAndMeasure', 'controlPlane': True, 'dataPlane': True}
        """        
        for eachPort in self.mainObj.configs['ports']:
            if eachPort['packetCapture'].get('enable', False):
                self.mainObj.logInfo(f'Enabling port capturing on port: {eachPort["name"]}   {eachPort["port"]}')
                vportCapture = self.mainObj.restpy.Vport.find(Name=eachPort['name'])
                vportCapture.RxMode = eachPort['packetCapture']['rxMode']
                vportCapture.Capture.SoftwareEnabled = eachPort['packetCapture']['controlPlane']
                vportCapture.Capture.HardwareEnabled = eachPort['packetCapture']['dataPlane']
                vportCapture.Capture.SliceSize = eachPort['packetCapture']['sliceSize']
        
    def getDataPlaneCaptureFile(self, convertPcapToTxt: bool=False, writeCaptureToFile: bool=False,
                                amountOfPacketsToWrite: int=10, captureFileDestPath: str=None) -> None:
        """
        Download the packet capture files to local host
        
        Notes: 
            tshark -r test.pcap -T fields -e frame.number -e eth.src -e eth.dst -e ip.src -e ip.dst -e frame.len > test1.csv

            tshark -r test.pcap -T fields -e frame.number -e eth.src -e eth.dst -e ip.src -e ip.dst -e frame.len -E header=y -E separator=, > test2.csv

            tshark -r test.pcap -R "frame.number>40" -T fields -e frame.number -e frame.time -e frame.time_delta -e frame.time_delta_displayed -e frame.time_relative -E header=y > test3.csv

            tshark -r test.pcap -R "wlan.fc.type_subtype == 0x08" -T fields -e frame.number -e wlan.sa -e wlan.bssid > test4.csv

            tshark -r test.pcap -R "ip.addr==192.168.1.6 && tcp.port==1696 && ip.addr==67.212.143.22 && tcp.port==80" -T fields -e frame.number -e tcp.analysis.ack_rtt -E header=y > test5.csv

            tshark -r test.pcap -T fields -e frame.number -e tcp.analysis.ack_rtt -E header=y > test6.csv
        """
        self.mainObj.logInfo('Getting port captures')
        
        if platform.system() == 'Linux':
            if captureFileDestPath is None:
                captureFileDestPath = currentDir
                
            capturedFilesPath = f'{captureFileDestPath}/CapturedFiles'
            
        if os.path.exists(capturedFilesPath) == False:
            enterLinuxCmd(f'mkdir {capturedFilesPath}', shell=True)

        if self.mainObj.session.TestPlatform.Platform == 'linux':
            remotePath = '/root/.local/share/Ixia/IxNetwork'
        else:    
            # C:\Users\hgee\AppData\Local\Ixia\IxNetwork
            remotePath = self.mainObj.restpy.Globals.PersistencePath
        
        # ['C:\\Users\\hgee\\AppData\\Local\\Ixia\\IxNetwork\\Host1_HW_dataPlane.cap' 
        #  'C:\\Users\\hgee\\AppData\\Local\\Ixia\\IxNetwork\\Host2_HW_dataPlane.cap']
        # ['/root/.local/share/Ixia/IxNetwork/Host1_HW_dataPlane_05-26-2023-10-41-02.cap', 
        #  '/root/.local/share/Ixia/IxNetwork/Host2_HW_dataPlane_05-26-2023-10-41-02.cap']
        self.mainObj.logInfo(f'Saving captured files: from:{remotePath}')
        self.mainObj.logInfo('This will take some time to complete depending on the size of the capture file ...')
        currentCaptureFilename = f'_dataPlane_{getTimestamp().replace(":", "-")}'
        remoteCaptureFiles = self.mainObj.restpy.SaveCaptureFiles(remotePath, currentCaptureFilename)
        
        self.mainObj.logInfo(f'remoteCaptureFiles: {remoteCaptureFiles}')
        
        for remoteFile in remoteCaptureFiles:            
            # IxNetwork API server OS
            if self.mainObj.session.TestPlatform.Platform == 'linux':
                filename = remoteFile.split('/')[-1]
            else:
                filename = remoteFile.split('\\')[-1]

            localFilePath = str(Path(f"{capturedFilesPath}/{filename}"))
            
            self.mainObj.logInfo(f'Download capture file to local host: {remoteFile} -> {localFilePath}')
            self.mainObj.session.Session.DownloadFile(remoteFile, localFilePath) 

            if writeCaptureToFile:
                for port in self.mainObj.configs['ports']:
                    if port['packetCapture']['enable'] and port['packetCapture']['dataPlane']:
                        vport = self.mainObj.restpy.Vport.find(Name=port['name'])
                        filename = localFilePath.replace("cap", "txt")
                        self.mainObj.logInfo(f'Port:{port["name"]}   Writing capture to text file: {filename}')
                        totalCapturedPackets = vport.Capture.DataCapturedPacketCounter
                        self.mainObj.logInfo(f'Total captured data packets : {totalCapturedPackets}')

                        if amountOfPacketsToWrite > totalCapturedPackets:
                            getPackets = totalCapturedPackets
                        else:
                            getPackets = amountOfPacketsToWrite
                                                    
                        with open(filename, 'w') as fileObj:
                            for packetNumber in range(0, amountOfPacketsToWrite):
                                # Note: GetPacketFromDataCapture() will create the packet header fields
                                try:
                                    vport.Capture.CurrentPacket.GetPacketFromDataCapture(Arg2=packetNumber)
                                    packetHeaderStacks = vport.Capture.CurrentPacket.Stack.find()
                            
                                    self.mainObj.logInfo(f'Vport:{vport.Name}  packetHeaderStack:{packetHeaderStacks}')
                                    fileObj.write(f'\nVport:{vport.Name}  packetHeaderStack:{packetHeaderStacks}\n')
                                    
                                    for packetHeader in packetHeaderStacks.find():
                                        self.mainObj.logInfo(f'\nPacketHeaderName: {packetHeader.DisplayName}')
                                        for field in packetHeader.Field.find():
                                            self.mainObj.logInfo(f'\t{field.DisplayName}: {field.FieldValue}') 
                                            fileObj.write(f'\t{field.DisplayName}: {field.FieldValue}\n')
                                            
                                except Exception as errMsg:
                                    self.mainObj.logInfo(errMsg)
                              
            if convertPcapToTxt:
                # tshark -i - < f"{currentDir}/CapturedFiles/{filename}" f"{currentDir}/CapturedFiles/{filename}.txt"
                # tshark -x -r filePath  > f"{currentDir}/CapturedFiles/{filename}.txt"
                #enterLinuxCmd(['tshark', '-i', '-', '<', localFilePath, '>', f"{localFilePath}.txt"])  
                #enterLinuxCmd(['tshark', '-x', '-r', localFilePath, '>', f"{localFilePath}.txt"]) 
                enterLinuxCmd(f'tshark -i - < {localFilePath} > {localFilePath}.txt', shell=True)

        enterLinuxCmd(f'chmod -R 777 {capturedFilesPath}', shell=True)
        
                        
    def getControlPlaneCaptureFile(self) -> None:
        self.mainObj.logInfo('Getting port captures')
        for port in self.mainObj.configs['ports']:
            if port['packetCapture']['enable'] and port['packetCapture']['controlPlane']:
                vport = self.mainObj.restpy.Vport.find(Name=port['name'])
                filename = f'{currentDir}/{port["name"]}_controlPlane_portCaptures'
                
                with open(filename, 'w') as fileObj:
                    for packetNumber in range(1, 2):
                        # Note: GetPacketFromDataCapture() will create the packet header fields
                        try:
                            vport.Capture.CurrentPacket.GetPacketFromControlCapture(Arg2=packetNumber)
                            packetHeaderStacks = vport.Capture.CurrentPacket.Stack.find()
                            self.mainObj.logInfo(f'\nVport:{vport.Name}  packetHeaderStack:{packetHeaderStacks}')
                            for packetHeader in packetHeaderStacks.find():
                                self.mainObj.logInfo(f'\nPacketHeaderName: {packetHeader.DisplayName}')
                                for field in packetHeader.Field.find():
                                    self.mainObj.logInfo(f'\t{field.DisplayName}: {field.FieldValue}') 
                                    
                        except Exception as errMsg:
                            self.rmainObj.logInfo(errMsg)
                
                result = subprocess.Popen(['chmod', '777', filename]).communicate()

    def start(self) -> None:
        self.mainObj.logInfo(f'Start port capturing')
        self.mainObj.restpy.StartCapture()

    def stop(self) -> None:
        self.mainObj.logInfo(f'Stop port capturing')
        self.mainObj.restpy.StopCapture()

        
class TrafficItem:
    def __init__(self, mainObj: object) -> None:
        self.mainObj = mainObj
        
    def generateAll(self) -> None:
        for trafficItem in self.mainObj.restpy.Traffic.TrafficItem.find():
            self.mainObj.logInfo(f'Regenerating traffic item: {trafficItem.Name}')
            trafficItem.Generate()
                            
    def apply(self) -> None:
        # Applying traffic will also stop all current captures    
        self.mainObj.logInfo(f'Apply Traffic')
        self.mainObj.restpy.Traffic.Apply()
        
    def start(self) -> None:
        self.mainObj.logInfo(f'Starting traffic')
        self.mainObj.restpy.Traffic.Start()
    
    def stop(self) -> None:
        self.mainObj.logInfo(f'Stopping traffic')
        self.mainObj.restpy.Traffic.Stop()        
            
    def configRawTrafficItems(self, ngpfMacAddresses: dict=None) -> None:
        """ 
        Configure raw traffic items
        This could automatically get NGPF dest mac from resolvedGatewayMac or you could 
        state the src/dst mac to use in the data model yml config file
        
        ngpfMacAddresses:
            {'host1': {'resolvedGatewayMac': ['00:0c:29:3a:86:b5'], 'srcMac': ['00:11:01:00:00:01']}, 
             'host2': {'resolvedGatewayMac': ['00:0c:29:3a:86:ab'], 'srcMac': ['00:12:01:00:00:01']}
            }
        """
        self.mainObj.logInfo(ngpfMacAddresses)
        for endpoint in self.mainObj.configs['trafficItems']:
            if endpoint.get('enable', True) == False:
                continue
            
            srcPortName = endpoint['srcPortName']
            
            if ngpfMacAddresses:
                srcPortMacAddress = ngpfMacAddresses[srcPortName]['srcMac'][0]
                srcPortDestMac    = ngpfMacAddresses[srcPortName]['resolvedGatewayMac'][0]
            else:
                srcPortMacAddress = self.mainObj.configs['trafficItems']['packetHeaders']['ethernet']['src']['startValue']
                srcPortDestMac    = self.mainObj.configs['trafficItems']['packetHeaders']['ethernet']['dst']['startValue']
                                
            self.mainObj.logInfo(f'srcPortName: {srcPortName}')
            self.mainObj.logInfo(f'srcPortMac: {srcPortMacAddress}')
            self.mainObj.logInfo(f'srcPortDestMac: {srcPortDestMac}')
            
            self.mainObj.logInfo(f'Create a raw traffic item: {endpoint["name"]}')
            rawTrafficItemObj = self.mainObj.restpy.Traffic.TrafficItem.add(Name=endpoint["name"], 
                                                                       BiDirectional=endpoint['biDirection'],
                                                                       TrafficType=endpoint['trafficType'])
            self.mainObj.logInfo('Add source and destination endpoints')
            rawTrafficItemObj.EndpointSet.add(Sources=self.mainObj.ports.vport[endpoint['srcPortName']].Protocols.find(),
                                              Destinations=self.mainObj.ports.vport[endpoint['destPortName']].Protocols.find())
            rawTrafficItemObj.Tracking.find().TrackBy = ['trackingenabled0']
            
            configElement = rawTrafficItemObj.ConfigElement.find()[0]
            configElement.FrameRate.update(Type=endpoint['frameRate']['type'], Rate=endpoint['frameRate']['rate'])
            configElement.TransmissionControl.update(Type=endpoint['transmissionControl']['type'],
                                                     FrameCount=endpoint['transmissionControl']['frameCount'])
            configElement.FrameSize.FixedSize = endpoint['frameSize']
            
            # The Ethernet packet header doesn't need to be created.
            # It is there by default. Just do a find for the Ethernet stack object.
            if endpoint['packetHeaders'].get('ethernet', None):
                ethernetStackObj = self.mainObj.restpy.Traffic.TrafficItem.find(Name=endpoint["name"]).ConfigElement.find()[0].Stack.find(StackTypeId='ethernet$') 
                
                # NOTE: If you are using virtual ports (IxVM), you must use the VM Destination MAC address  
                #       for the Ixia Rx port from your virtual host (ESX-i host or KVM)
                self.mainObj.logInfo('Configuring Ethernet packet header')
                ethernetDstField = ethernetStackObj.Field.find(DisplayName='Destination MAC Address')
                ethernetDstField.ValueType  = endpoint['packetHeaders']['ethernet']['dst']['valueType']
                ethernetDstField.StartValue = srcPortDestMac
                ethernetDstField.StepValue  = endpoint['packetHeaders']['ethernet']['dst']['stepValue']
                ethernetDstField.CountValue = endpoint['packetHeaders']['ethernet']['dst']['count']

                ethernetSrcField = ethernetStackObj.Field.find(DisplayName='Source MAC Address')
                ethernetSrcField.ValueType  = endpoint['packetHeaders']['ethernet']['src']['valueType']
                ethernetSrcField.StartValue = srcPortMacAddress
                ethernetSrcField.StepValue  = endpoint['packetHeaders']['ethernet']['src']['stepValue']
                ethernetSrcField.CountValue = endpoint['packetHeaders']['ethernet']['src']['count']

            # TODO: VLAN
            if endpoint['packetHeaders'].get('vlan', None):
                vlanFieldObj = self.createPacketHeader(rawTrafficItemObj, packetHeaderToAdd='^vlan$', appendToStack='ethernet$')
                vlanIdField = vlanFieldObj.find(DisplayName='VLAN-ID')
                vlanIdField.SingleValue = 103
                    
                vlanPriorityField = vlanFieldObj.find(DisplayName='VLAN Priority')
                vlanPriorityField.Auto = False
                vlanPriorityField.SingleValue = 3

            # TODO: PFC QUEUE
            if endpoint['packetHeaders'].get('pfcPause', None):
                pfcQueueObj = ethernetStackObj.Field.find(DisplayName='PFC Queue')
                pfcQueueObj.ValueType = 'valueList'
                pfcQueueObj.ValueList = [1, 3, 5, 7]

                # PFC PAUSE: PFC PAUSE (802.1Qbb)
                pauseFrameObj = self.createPacketHeader(rawTrafficItemObj, packetHeaderToAdd='pfcPause', appendToStack='ethernet$')
                pauseFrameField = pauseFrameObj.find(DisplayName='Control opcode')
                pauseFrameField.ValueType = 'singleValue'
                pauseFrameField.SingleValue = 103

                pauseFrameQueue0 = pauseFrameObj.find(DisplayName='PFC Queue 0')
                pauseFrameQueue0.ValueType = 'singleValue'
                pauseFrameQueue0.SingleValue = 'abcd'

                pauseFrameQueue1 = pauseFrameObj.find(DisplayName='PFC Queue 1')
                pauseFrameQueue2 = pauseFrameObj.find(DisplayName='PFC Queue 2')
                pauseFrameQueue3 = pauseFrameObj.find(DisplayName='PFC Queue 3')
                pauseFrameQueue4 = pauseFrameObj.find(DisplayName='PFC Queue 4')
                pauseFrameQueue5 = pauseFrameObj.find(DisplayName='PFC Queue 5')
                pauseFrameQueue6 = pauseFrameObj.find(DisplayName='PFC Queue 6')

            # IPv4
            if endpoint['packetHeaders'].get('ipv4', None):
                ipv4FieldObj = self.createPacketHeader(rawTrafficItemObj, packetHeaderToAdd='ipv4',
                                                appendToStack=f'^{endpoint["packetHeaders"]["ipv4"]["appendToStack"]}$')
                ipv4SrcField = ipv4FieldObj.find(DisplayName='Source Address')
                ipv4SrcField.ValueType = endpoint["packetHeaders"]["ipv4"]["src"]["valueType"]
                ipv4SrcField.StartValue = endpoint["packetHeaders"]["ipv4"]["src"]["startValue"]
                ipv4SrcField.StepValue = endpoint["packetHeaders"]["ipv4"]["src"]["stepValue"]
                ipv4SrcField.CountValue = endpoint["packetHeaders"]["ipv4"]["src"]["count"] 

                ipv4DstField = ipv4FieldObj.find(DisplayName='Destination Address')
                ipv4DstField.ValueType = endpoint["packetHeaders"]["ipv4"]["dst"]["valueType"]
                ipv4DstField.StartValue = endpoint["packetHeaders"]["ipv4"]["dst"]["startValue"]
                ipv4DstField.StepValue = endpoint["packetHeaders"]["ipv4"]["dst"]["stepValue"]
                ipv4DstField.CountValue = endpoint["packetHeaders"]["ipv4"]["dst"]["count"] 

            if endpoint['packetHeaders'].get('udp', None):
                udpFieldObj = self.createPacketHeader(rawTrafficItemObj, packetHeaderToAdd='^udp$', appendToStack='ipv4')
                udpSrcField = udpFieldObj.find(DisplayName='UDP-Source-Port')
                udpSrcField.Auto = False
                udpSrcField.SingleValue = endpoint["packetHeaders"]["udp"]["srcPort"]["startValue"] 

                udpDstField = udpFieldObj.find(DisplayName='UDP-Dest-Port')
                udpDstField.Auto = False
                udpDstField.SingleValue = endpoint["packetHeaders"]["udp"]["dstPort"]["startValue"] 
                    
            # TODO: DSCP configurations and references
            if endpoint['packetHeaders'].get('ipPrecedence', None):
                # For IPv4 TOS/Precedence:  Field/4
                #    000 Routine, 001 Priority, 010 Immediate, 011 Flash, 100 Flash Override,
                #    101 CRITIC/ECP, 110 Internetwork Control, 111 Network Control
                ipv4PrecedenceField = ipv4FieldObj.find(DisplayName='Precedence')
                ipv4PrecedenceField.ActiveFieldChoice = True
                ipv4PrecedenceField.FieldValue = '011 Flash'

                # For IPv4 Raw priority: Field/3
                #ipv4RawPriorityField = ipv4FieldObj.find(DisplayName='Raw priority')
                #ipv4RawPriorityField.ActiveFieldChoice = True
                #ipv4RawPriorityField.ValueType = 'increment'
                #ipv4RawPriorityField.StartValue = 3
                #ipv4RawPriorityField.StepValue = 1
                #ipv4RawPriorityField.CountValue = 9

                # For IPv4 Default PHB
                #   Field/10: Default PHB
                #   Field/12: Class selector PHB
                #   Field/14: Assured forwarding PHB
                #   Field/15: Expedited forwarding PHB
                #
                #   For Class selector, if singleValue: Goes by 8bits:
                #       Precedence 1 = 8
                #       Precedence 2 = 16
                #       Precedence 3 = 24
                #       Precedence 4 = 32
                #       Precedence 5 = 40
                #       Precedence 6 = 48
                #       Precedence 7 = 56
                #
                # DisplayName options: 
                #     'Default PHB' = Field/10 
                #     'Class selector PHB' = Field/12
                #     'Assured forwarding PHB" = Field/14
                #     'Expedited forwarding PHB" = Field/16 
                #ipv4DefaultPHBField = ipv4FieldObj.find(DisplayName='Class selector')
                ipv4DefaultPHBField = ipv4FieldObj.find(DisplayName='Default PHB')
                ipv4DefaultPHBField.ActiveFieldChoice = True
                ipv4DefaultPHBField.ValueType = 'singleVaoue' ;# singleValue, increment
                ipv4DefaultPHBField.SingleValue = 56
                # Below is for increment 
                #ipv4DefaultPHBField.StartValue = 3
                #ipv4DefaultPHBField.StepValue = 1
                #ipv4DefaultPHBField.CountValue = 9
                
    def createPacketHeader(self, trafficItemObj: object, packetHeaderToAdd: str=None, appendToStack: str=None) -> object:
        """ 
        Create packet headers for traffic items
        """ 
        configElement = trafficItemObj.ConfigElement.find()[0]

        # Do the followings to add packet headers on the new traffic item

        # Uncomment this to show a list of all the available protocol templates to create (packet headers)
        # for protocolHeader in ixNetwork.Traffic.ProtocolTemplate.find():
        #     ixNetwork.info('Protocol header: --{}--'.format(protocolHeader.StackTypeId))

        # 1> Get the <new packet header> protocol template from the ProtocolTemplate list.
        packetHeaderProtocolTemplate = self.mainObj.restpy.Traffic.ProtocolTemplate.find(StackTypeId=packetHeaderToAdd)
        #ixNetwork.info('protocolTemplate: {}'.format(packetHeaderProtocolTemplate))

        # 2> Append the <new packet header> object after the specified packet header stack.
        appendToStackObj = configElement.Stack.find(StackTypeId=appendToStack)
        self.mainObj.logInfo('appendToStackObj: {}'.format(appendToStackObj))
        appendToStackObj.Append(Arg2=packetHeaderProtocolTemplate)

        # 3> Get the new packet header stack to use it for appending an IPv4 stack after it.
        # Look for the packet header object and stack ID.
        packetHeaderStackObj = configElement.Stack.find(StackTypeId=packetHeaderToAdd)
        
        # 4> In order to modify the fields, get the field object
        packetHeaderFieldObj = packetHeaderStackObj.Field.find()
        #ixNetwork.info('packetHeaderFieldObj: {}'.format(packetHeaderFieldObj))
        
        # 5> Save the above configuration to the base config file.
        #ixNetwork.SaveConfig(Files('baseConfig.ixncfg', local_file=True))

        return packetHeaderFieldObj
                        
    def waitForTrafficCompletion(self, maxCounter:int=10) -> None:
        """ 
        Wait for traffic to complete sending and receiving
        """
        self.mainObj.logInfo(f'Check traffic for completion ...')
        for x in range(1, maxCounter+1):
            trafficItemtatistics = self.mainObj.session.StatViewAssistant('Traffic Item Statistics')
            monitorFlag = []
            
            for rowNumber,trafficItemStats in enumerate(trafficItemtatistics.Rows):
                self.mainObj.logInfo(trafficItemStats)
                self.mainObj.logInfo(f'TrafficItem Name:{trafficItemStats["Traffic Item"]}  Tx:{trafficItemStats["Tx Frames"]}  Rx:{trafficItemStats["Rx Frames"]}')
                
                configsTrafficItemIndex = [index for index,ti in enumerate(self.mainObj.configs['trafficItems']) if ti['name'] == trafficItemStats["Traffic Item"]]
                currentConfigsTrafficItem = self.mainObj.configs['trafficItems'][configsTrafficItemIndex[0]]
                
                if int(trafficItemStats["Tx Frames"]) < currentConfigsTrafficItem['transmissionControl']['frameCount'] or \
                    int(trafficItemStats["Rx Frames"]) < currentConfigsTrafficItem['transmissionControl']['frameCount']:
                    monitorFlag.append(rowNumber)

            if monitorFlag == []:
                self.mainObj.logInfo('All Traffic Items finished sending fixed frame count')
                break
            else:
                self.mainObj.logInfo(f'Traffic Item "{trafficItemStats["Traffic Item"]}" is not done Tx/Rx fixed frame count.  {x}/10...')
                time.sleep(3)
                
                
class NGPF:
    def __init__(self, mainObj: object) -> None:
        self.mainObj = mainObj
                
    def configure(self) -> None: 
        """  
        Configure NGPF topologies
        """   
        for topologyObj in self.mainObj.configs['topologies']:
            self.mainObj.logInfo(f'Creating Topology Group: {topologyObj["name"]}')
            topology = self.mainObj.restpy.Topology.add(Name=topologyObj["name"],
                                                   Ports=[self.mainObj.ports.vport[eachPort] for eachPort in topologyObj["ports"]])
            
            for deviceGroupObj in topologyObj['deviceGroups']:
                self.mainObj.logInfo(f'Creating Device Group: {deviceGroupObj["name"]}')
                deviceGroup = topology.DeviceGroup.add(Name=deviceGroupObj['name'], Multiplier=deviceGroupObj['multiplier'])
                ethernet = deviceGroup.Ethernet.add(Name=deviceGroupObj['ethernet']['name'])
                # ethernet1.Mac.Increment(start_value='00:01:01:01:00:01', step_value='00:00:00:00:00:01')
                # ethernet1.EnableVlans.Single(True)
                # ixNetwork.info('Configuring vlanID')
                # vlanObj = ethernet1.Vlan.find()[0].VlanId.Increment(start_value=103, step_value=0)

                ipv4 = ethernet.Ipv4.add(Name=deviceGroupObj['ipv4']['name'])
                ipv4.Address.Increment(start_value=deviceGroupObj['ipv4']['ipStartValue'], 
                                       step_value=deviceGroupObj['ipv4']['ipStepValue'])
                ipv4.GatewayIp.Increment(start_value=deviceGroupObj['ipv4']['ipGatewayStartValue'], 
                                         step_value=deviceGroupObj['ipv4']['ipGatewayStepValue'])
    
    def startAllProtocols(self) -> None:
        self.mainObj.logInfo(f'Start all NGPF protocols')
        self.mainObj.restpy.StartAllProtocols(Arg1='sync')
                            
    def verifyProtocolsUp(self) -> None:
        """ 
        Verify all NGPF protocols in the UP state
        """
        self.mainObj.logInfo('Verify protocol sessions\n')
        protocolSummary = self.mainObj.session.StatViewAssistant('Protocols Summary')
        protocolSummary.CheckCondition('Sessions Not Started', protocolSummary.EQUAL, 0)
        protocolSummary.CheckCondition('Sessions Down', protocolSummary.EQUAL, 0)
        self.mainObj.logInfo(protocolSummary)

    def getNgpfLearnedMacAddresses(self) -> dict:
        """ 
        Get NGPF resolve gateway Mac addresses and also get the src mac
        This is mainly used for raw traffic items that requires inserting
        the src/dst mac addresses.
        """
        ngpfMacAddresses = {}
        for topologyObj in self.mainObj.configs['topologies']:
            for deviceGroupObj in topologyObj['deviceGroups']:
                #srcMac = list  
                srcMac = self.mainObj.restpy.Topology.find(Name=topologyObj['name']) \
                    .DeviceGroup.find(Name=deviceGroupObj['name']) \
                        .Ethernet.find().Mac.Values
                
                # gatewayMac = list      
                gatewayMac = self.mainObj.restpy.Topology.find(Name=topologyObj['name']) \
                    .DeviceGroup.find() \
                        .Ethernet.find() \
                            .Ipv4.find().ResolvedGatewayMac

                ngpfMacAddresses[topologyObj['name']] = {'resolvedGatewayMac': gatewayMac, 'srcMac': srcMac}
        
        self.mainObj.logInfo(f'getNgpfLearnedMacAddresses: {ngpfMacAddresses}')        
        return ngpfMacAddresses
    

                    
