import datetime, yaml, subprocess

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
