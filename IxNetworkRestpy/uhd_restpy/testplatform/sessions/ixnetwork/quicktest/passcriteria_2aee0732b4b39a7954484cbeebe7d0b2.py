# MIT LICENSE
#
# Copyright 1997 - 2020 by IXIA Keysight
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE. 
import sys
from uhd_restpy.base import Base
from uhd_restpy.files import Files
if sys.version_info >= (3, 5):
    from typing import List, Any, Union


class PassCriteria(Base):
    """This applies the Pass Criteria to each trial in the test and determines whether the trial passed or failed.
    The PassCriteria class encapsulates a required passCriteria resource which will be retrieved from the server every time the property is accessed.
    """

    __slots__ = ()
    _SDM_NAME = 'passCriteria'
    _SDM_ATT_MAP = {
        'EnableJoinFailuresPassFail': 'enableJoinFailuresPassFail',
        'EnableJoinLatencyPassFail': 'enableJoinLatencyPassFail',
        'EnableLeaveFailuresPassFail': 'enableLeaveFailuresPassFail',
        'EnableLeaveLatencyPassFail': 'enableLeaveLatencyPassFail',
        'PassFailJoinLatencyAgg': 'passFailJoinLatencyAgg',
        'PassFailLeaveLatencyAgg': 'passFailLeaveLatencyAgg',
    }
    _SDM_ENUM_MAP = {
        'passFailJoinLatencyAgg': ['average', 'maximum', 'minimum'],
        'passFailLeaveLatencyAgg': ['average', 'maximum', 'minimum'],
    }

    def __init__(self, parent, list_op=False):
        super(PassCriteria, self).__init__(parent, list_op)

    @property
    def EnableJoinFailuresPassFail(self):
        # type: () -> bool
        """
        Returns
        -------
        - bool: If true, allows to show how many Join actions were marked as Failed or Passed.
        """
        return self._get_attribute(self._SDM_ATT_MAP['EnableJoinFailuresPassFail'])
    @EnableJoinFailuresPassFail.setter
    def EnableJoinFailuresPassFail(self, value):
        # type: (bool) -> None
        self._set_attribute(self._SDM_ATT_MAP['EnableJoinFailuresPassFail'], value)

    @property
    def EnableJoinLatencyPassFail(self):
        # type: () -> bool
        """
        Returns
        -------
        - bool: If true, allows to show the amount of time, in milliseconds, elapsed between the time the client sent an IGMP JOIN (broadcast channel) and the time it received the first byte of data.
        """
        return self._get_attribute(self._SDM_ATT_MAP['EnableJoinLatencyPassFail'])
    @EnableJoinLatencyPassFail.setter
    def EnableJoinLatencyPassFail(self, value):
        # type: (bool) -> None
        self._set_attribute(self._SDM_ATT_MAP['EnableJoinLatencyPassFail'], value)

    @property
    def EnableLeaveFailuresPassFail(self):
        # type: () -> bool
        """
        Returns
        -------
        - bool: If true, allows to show how many Leave actions were marked as Failed or Passed.
        """
        return self._get_attribute(self._SDM_ATT_MAP['EnableLeaveFailuresPassFail'])
    @EnableLeaveFailuresPassFail.setter
    def EnableLeaveFailuresPassFail(self, value):
        # type: (bool) -> None
        self._set_attribute(self._SDM_ATT_MAP['EnableLeaveFailuresPassFail'], value)

    @property
    def EnableLeaveLatencyPassFail(self):
        # type: () -> bool
        """
        Returns
        -------
        - bool: If true, allows to The amount of time, in milliseconds, elapsed between the time the client sent an IGMP LEAVE (broadcast channel) and the time it received the last byte of data.
        """
        return self._get_attribute(self._SDM_ATT_MAP['EnableLeaveLatencyPassFail'])
    @EnableLeaveLatencyPassFail.setter
    def EnableLeaveLatencyPassFail(self, value):
        # type: (bool) -> None
        self._set_attribute(self._SDM_ATT_MAP['EnableLeaveLatencyPassFail'], value)

    @property
    def PassFailJoinLatencyAgg(self):
        # type: () -> str
        """
        Returns
        -------
        - str(average | maximum | minimum): If true, allows to join pass and failure latency aggregate results.
        """
        return self._get_attribute(self._SDM_ATT_MAP['PassFailJoinLatencyAgg'])
    @PassFailJoinLatencyAgg.setter
    def PassFailJoinLatencyAgg(self, value):
        # type: (str) -> None
        self._set_attribute(self._SDM_ATT_MAP['PassFailJoinLatencyAgg'], value)

    @property
    def PassFailLeaveLatencyAgg(self):
        # type: () -> str
        """
        Returns
        -------
        - str(average | maximum | minimum): The pass fail leave latency aggregate.
        """
        return self._get_attribute(self._SDM_ATT_MAP['PassFailLeaveLatencyAgg'])
    @PassFailLeaveLatencyAgg.setter
    def PassFailLeaveLatencyAgg(self, value):
        # type: (str) -> None
        self._set_attribute(self._SDM_ATT_MAP['PassFailLeaveLatencyAgg'], value)

    def update(self, EnableJoinFailuresPassFail=None, EnableJoinLatencyPassFail=None, EnableLeaveFailuresPassFail=None, EnableLeaveLatencyPassFail=None, PassFailJoinLatencyAgg=None, PassFailLeaveLatencyAgg=None):
        # type: (bool, bool, bool, bool, str, str) -> PassCriteria
        """Updates passCriteria resource on the server.

        Args
        ----
        - EnableJoinFailuresPassFail (bool): If true, allows to show how many Join actions were marked as Failed or Passed.
        - EnableJoinLatencyPassFail (bool): If true, allows to show the amount of time, in milliseconds, elapsed between the time the client sent an IGMP JOIN (broadcast channel) and the time it received the first byte of data.
        - EnableLeaveFailuresPassFail (bool): If true, allows to show how many Leave actions were marked as Failed or Passed.
        - EnableLeaveLatencyPassFail (bool): If true, allows to The amount of time, in milliseconds, elapsed between the time the client sent an IGMP LEAVE (broadcast channel) and the time it received the last byte of data.
        - PassFailJoinLatencyAgg (str(average | maximum | minimum)): If true, allows to join pass and failure latency aggregate results.
        - PassFailLeaveLatencyAgg (str(average | maximum | minimum)): The pass fail leave latency aggregate.

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._update(self._map_locals(self._SDM_ATT_MAP, locals()))

    def find(self, EnableJoinFailuresPassFail=None, EnableJoinLatencyPassFail=None, EnableLeaveFailuresPassFail=None, EnableLeaveLatencyPassFail=None, PassFailJoinLatencyAgg=None, PassFailLeaveLatencyAgg=None):
        # type: (bool, bool, bool, bool, str, str) -> PassCriteria
        """Finds and retrieves passCriteria resources from the server.

        All named parameters are evaluated on the server using regex. The named parameters can be used to selectively retrieve passCriteria resources from the server.
        To retrieve an exact match ensure the parameter value starts with ^ and ends with $
        By default the find method takes no parameters and will retrieve all passCriteria resources from the server.

        Args
        ----
        - EnableJoinFailuresPassFail (bool): If true, allows to show how many Join actions were marked as Failed or Passed.
        - EnableJoinLatencyPassFail (bool): If true, allows to show the amount of time, in milliseconds, elapsed between the time the client sent an IGMP JOIN (broadcast channel) and the time it received the first byte of data.
        - EnableLeaveFailuresPassFail (bool): If true, allows to show how many Leave actions were marked as Failed or Passed.
        - EnableLeaveLatencyPassFail (bool): If true, allows to The amount of time, in milliseconds, elapsed between the time the client sent an IGMP LEAVE (broadcast channel) and the time it received the last byte of data.
        - PassFailJoinLatencyAgg (str(average | maximum | minimum)): If true, allows to join pass and failure latency aggregate results.
        - PassFailLeaveLatencyAgg (str(average | maximum | minimum)): The pass fail leave latency aggregate.

        Returns
        -------
        - self: This instance with matching passCriteria resources retrieved from the server available through an iterator or index

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._select(self._map_locals(self._SDM_ATT_MAP, locals()))

    def read(self, href):
        """Retrieves a single instance of passCriteria data from the server.

        Args
        ----
        - href (str): An href to the instance to be retrieved

        Returns
        -------
        - self: This instance with the passCriteria resources from the server available through an iterator or index

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._read(href)

    def Apply(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        """Executes the apply operation on the server.

        Applies the specified Quick Test.

        apply(async_operation=bool)
        ---------------------------
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        payload = { "Arg1": self.href }
        for i in range(len(args)): payload['Arg%s' % (i + 2)] = args[i]
        for item in kwargs.items(): payload[item[0]] = item[1]
        return self._execute('apply', payload=payload, response_object=None)

    def ApplyAsync(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        """Executes the applyAsync operation on the server.

        applyAsync(async_operation=bool)
        --------------------------------
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        payload = { "Arg1": self.href }
        for i in range(len(args)): payload['Arg%s' % (i + 2)] = args[i]
        for item in kwargs.items(): payload[item[0]] = item[1]
        return self._execute('applyAsync', payload=payload, response_object=None)

    def ApplyAsyncResult(self, *args, **kwargs):
        # type: (*Any, **Any) -> Union[bool, None]
        """Executes the applyAsyncResult operation on the server.

        applyAsyncResult(async_operation=bool)bool
        ------------------------------------------
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.
        - Returns bool: 

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        payload = { "Arg1": self.href }
        for i in range(len(args)): payload['Arg%s' % (i + 2)] = args[i]
        for item in kwargs.items(): payload[item[0]] = item[1]
        return self._execute('applyAsyncResult', payload=payload, response_object=None)

    def ApplyITWizardConfiguration(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        """Executes the applyITWizardConfiguration operation on the server.

        Applies the specified Quick Test.

        applyITWizardConfiguration(async_operation=bool)
        ------------------------------------------------
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        payload = { "Arg1": self.href }
        for i in range(len(args)): payload['Arg%s' % (i + 2)] = args[i]
        for item in kwargs.items(): payload[item[0]] = item[1]
        return self._execute('applyITWizardConfiguration', payload=payload, response_object=None)

    def GenerateReport(self, *args, **kwargs):
        # type: (*Any, **Any) -> Union[str, None]
        """Executes the generateReport operation on the server.

        Generate a PDF report for the last succesfull test run.

        generateReport(async_operation=bool)string
        ------------------------------------------
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.
        - Returns str: This method is asynchronous and has no return value.

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        payload = { "Arg1": self.href }
        for i in range(len(args)): payload['Arg%s' % (i + 2)] = args[i]
        for item in kwargs.items(): payload[item[0]] = item[1]
        return self._execute('generateReport', payload=payload, response_object=None)

    def Run(self, *args, **kwargs):
        # type: (*Any, **Any) -> Union[List[str], None]
        """Executes the run operation on the server.

        Starts the specified Quick Test and waits for its execution to finish.

        The IxNetwork model allows for multiple method Signatures with the same name while python does not.

        run(async_operation=bool)list
        -----------------------------
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.
        - Returns list(str): This method is synchronous and returns the result of the test.

        run(InputParameters=string, async_operation=bool)list
        -----------------------------------------------------
        - InputParameters (str): The input arguments of the test.
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.
        - Returns list(str): This method is synchronous and returns the result of the test.

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        payload = { "Arg1": self.href }
        for i in range(len(args)): payload['Arg%s' % (i + 2)] = args[i]
        for item in kwargs.items(): payload[item[0]] = item[1]
        return self._execute('run', payload=payload, response_object=None)

    def Start(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        """Executes the start operation on the server.

        Starts the specified Quick Test.

        The IxNetwork model allows for multiple method Signatures with the same name while python does not.

        start(async_operation=bool)
        ---------------------------
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.

        start(InputParameters=string, async_operation=bool)
        ---------------------------------------------------
        - InputParameters (str): The input arguments of the test.
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        payload = { "Arg1": self.href }
        for i in range(len(args)): payload['Arg%s' % (i + 2)] = args[i]
        for item in kwargs.items(): payload[item[0]] = item[1]
        return self._execute('start', payload=payload, response_object=None)

    def Stop(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        """Executes the stop operation on the server.

        Stops the currently running Quick Test.

        stop(async_operation=bool)
        --------------------------
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        payload = { "Arg1": self.href }
        for i in range(len(args)): payload['Arg%s' % (i + 2)] = args[i]
        for item in kwargs.items(): payload[item[0]] = item[1]
        return self._execute('stop', payload=payload, response_object=None)

    def WaitForTest(self, *args, **kwargs):
        # type: (*Any, **Any) -> Union[List[str], None]
        """Executes the waitForTest operation on the server.

        Waits for the execution of the specified Quick Test to be completed.

        waitForTest(async_operation=bool)list
        -------------------------------------
        - async_operation (bool=False): True to execute the operation asynchronously. Any subsequent rest api calls made through the Connection class will block until the operation is complete.
        - Returns list(str): This method is synchronous and returns the result of the test.

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        payload = { "Arg1": self.href }
        for i in range(len(args)): payload['Arg%s' % (i + 2)] = args[i]
        for item in kwargs.items(): payload[item[0]] = item[1]
        return self._execute('waitForTest', payload=payload, response_object=None)
