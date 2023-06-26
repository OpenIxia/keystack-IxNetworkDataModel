import sys, traceback

from ixNetworkDataModel import ConfigIxNetworkRestPy
from keystackEnv import keystackObj

dataModelYamlFile = keystackObj.configParamsFileFullPath

try:
    mainObj = ConfigIxNetworkRestPy(dataModelFile=dataModelYamlFile, dataModelObj=None,
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
    captureFilenames = mainObj.portCapture.getDataPlaneCaptureFile(
        writeCaptureToFile=False,
        amountOfPacketsToWrite=5,
        captureFileDestPath=keystackObj.moduleProperties['artifactsRepo'])

    print(f'\ncaptureFilenames: {captureFilenames}')
    
    if mainObj.configs.get('releasePorts', False):
        mainObj.ports.releasePorts()
    
    if mainObj.configs.get('deleteSession', True):
        mainObj.deleteSession()
    
except Exception as errMsg:
    print(f'\nError: {traceback.format_exc(None, errMsg)}')
    if 'mainObj' in locals():
        mainObj.logFailed(traceback.format_exc(None, errMsg))

    
        
