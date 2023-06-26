import os, platform, subprocess
from pathlib import Path

import appUtilities

currentDir = os.path.abspath(os.path.dirname(__file__))

class Ports:
    def __init__(self, mainObj: object) -> None:
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
            # Create vport / chassis+port mapping
            portMap = self.mainObj.session.PortMapAssistant()
            self.vport = dict()
            for index,port in enumerate(self.getPortList()):
                # port: ['10.80.81.12', ' 1', ' 3', 'Host1']
                portName = port[3]
                self.mainObj.logInfo(f'Creating vport: {portName}')
                self.vport[portName] = portMap.Map(IpAddress=port[0], CardId=port[1], PortId=port[2], Name=portName)
            
            self.mainObj.logInfo(f'Configuring port mapping')
            portMap.Connect(ForceOwnership=self.mainObj.configs.get('forceTakePortOwnership', False), IgnoreLinkUp=True)
        
            for port in self.mainObj.configs['ports']:
                portName = port['name']
                if portName in self.vport and port.get('type', None):
                    # novusTenGigLanFcoe
                    self.vport[portName].Type = port['type']
                    
                    # Have to uppercase the port type -> NovusTenGigLan
                    portType = self.vport[portName].Type[0].upper() + self.vport[portName].Type[1:]
                    
                    if 'Fcoe' in portType:
                        # Strip off 'Fcoe' for vport.L1Config.NovasTenGigLan (without Fcoe)
                        portType = portType.split('Fcoe')[0]
                    
                    portObj = getattr(self.vport[portName].L1Config, portType)
                    
                    if port.get('media', None):
                        self.mainObj.logInfo(f'Configuring port meida: {port["name"]} = {port["media"]}')
                        portObj.Media = port['media']
            
                    if 'ieeeL1Defaults' in port:
                        self.mainObj.logInfo(f'Enable port ieeeL1Defaults: {port["name"]} = {port["ieeeL1Defaults"]}')
                        portObj.IeeeL1Defaults = port['ieeeL1Defaults']
                    
                    if 'enableAutoNegotiation' in port:
                        self.mainObj.logInfo(f'Enable Auto-Negotiation: {port["name"]} = {port["enableAutoNegotiation"]}')
                        portObj.EnableAutoNegotiation = port['enableAutoNegotiation']
                                                
            self.mainObj.restpy.Vport.find().ConnectPorts()
                    
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
            appUtilities.enterLinuxCmd(f'mkdir {capturedFilesPath}', shell=True)

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
        currentCaptureFilename = f'_dataPlane_{appUtilities.getTimestamp().replace(":", "-")}'
        remoteCaptureFiles = self.mainObj.restpy.SaveCaptureFiles(remotePath, currentCaptureFilename)
        captureFileNames = []
        
        self.mainObj.logInfo(f'remoteCaptureFiles: {remoteCaptureFiles}')
        
        for remoteFile in remoteCaptureFiles:            
            # IxNetwork API server OS
            if self.mainObj.session.TestPlatform.Platform == 'linux':
                filename = remoteFile.split('/')[-1]
            else:
                filename = remoteFile.split('\\')[-1]

            localFilePath = str(Path(f"{capturedFilesPath}/{filename}"))
            captureFileNames.append(localFilePath)
            
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
                appUtilities.enterLinuxCmd(f'tshark -i - < {localFilePath} > {localFilePath}.txt', shell=True)

        appUtilities.enterLinuxCmd(f'chmod -R 777 {capturedFilesPath}', shell=True)
        
        return captureFileNames
                        
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
