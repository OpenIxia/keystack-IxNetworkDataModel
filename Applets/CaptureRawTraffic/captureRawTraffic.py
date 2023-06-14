import sys, traceback

from ixNetworkDataModelConfig import ConfigIxNetworkRestPy
from keystackEnv import keystackObj

dataModelYamlFile = keystackObj.configParamsFileFullPath

try:
    mainObj = ConfigIxNetworkRestPy(dataModelFile=dataModelYamlFile,
                                    sessionName=None, sessionId=None, apiKey=None, clearConfig=True,
                                    logLevel='info', logFilename=None, keystackObj=keystackObj)
                                            
    mainObj.ports.assignPorts()
    mainObj.portCapture.configure()
    mainObj.closeAllTabs()
    mainObj.ngpf.configure()
    mainObj.ngpf.startAllProtocols()
    mainObj.ngpf.verifyProtocolsUp()
    ngpfMacAddresses = mainObj.ngpf.getNgpfLearnedMacAddresses()        
    mainObj.trafficItem.configRawTrafficItems(ngpfMacAddresses=ngpfMacAddresses)
    mainObj.trafficItem.generateAll()
    mainObj.trafficItem.apply()
    mainObj.portCapture.start()
    mainObj.trafficItem.start()
    mainObj.trafficItem.waitForTrafficCompletion(maxCounter=10)
    mainObj.portCapture.stop()
    mainObj.portCapture.getDataPlaneCaptureFile(writeCaptureToFile=False,
                                                amountOfPacketsToWrite=5,
                                                captureFileDestPath=keystackObj.moduleProperties['artifactsRepo'])


    if mainObj.configs['releasePorts']:
        mainObj.ports.releasePorts()
    
    if mainObj.configs['deleteSession']:
        mainObj.deleteSession()

except Exception as errMsg:
    if 'mainObj' in locals():
        mainObj.logFailed(traceback.format_exc(None, errMsg))

    
        
