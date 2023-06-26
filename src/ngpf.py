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
    
