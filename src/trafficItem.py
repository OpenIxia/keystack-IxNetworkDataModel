import time

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
                # pfcQueueObj.ValueType = 'valueList'
                # pfcQueueObj.ValueList = [1, 3, 5, 7]
                pfcQueueObj.ValueType = endpoint["packetHeaders"]['pfcPause']["pfcQueue"]["valueType"]
                pfcQueueObj.ValueList = [1, 3, 5, 7]
                
                # PFC PAUSE: PFC PAUSE (802.1Qbb)
                pauseFrameObj = self.createPacketHeader(rawTrafficItemObj, packetHeaderToAdd='pfcPause', appendToStack='ethernet$')
                pauseFrameField = pauseFrameObj.find(DisplayName='Control opcode')
                pauseFrameField.ValueType  = endpoint["packetHeaders"]['pfcPause']["controlOpcode"]["valueType"]
                pauseFrameField.StartValue = endpoint["packetHeaders"]['pfcPause']["controlOpcode"]["startValue"]
                
                pauseFrameQueue0 = pauseFrameObj.find(DisplayName='PFC Queue 0')
                # pauseFrameQueue0.ValueType = 'singleValue'
                # pauseFrameQueue0.SingleValue = 'abcd'
                pauseFrameQueue0.ValueType = endpoint["packetHeaders"]['pfcPause']["pfcQueue0"]["valueType"]
                pauseFrameQueue0.StartValue = endpoint["packetHeaders"]['pfcPause']["pfcQueue0"]["startValue"]

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
                
