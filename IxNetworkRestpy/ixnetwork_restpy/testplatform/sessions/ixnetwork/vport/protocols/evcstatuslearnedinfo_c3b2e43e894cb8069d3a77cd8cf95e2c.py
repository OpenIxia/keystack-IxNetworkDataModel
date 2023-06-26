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
from ixnetwork_restpy.base import Base
from ixnetwork_restpy.files import Files

if sys.version_info >= (3, 5):
    from typing import List, Any, Union


class EvcStatusLearnedInfo(Base):
    """It signifies the status learned info for EVC.
    The EvcStatusLearnedInfo class encapsulates a list of evcStatusLearnedInfo resources that are managed by the system.
    A list of resources can be retrieved from the server using the EvcStatusLearnedInfo.find() method.
    """

    __slots__ = ()
    _SDM_NAME = "evcStatusLearnedInfo"
    _SDM_ATT_MAP = {
        "CbsMagnitude": "cbsMagnitude",
        "CbsMultiplier": "cbsMultiplier",
        "Cf": "cf",
        "CirMagnitude": "cirMagnitude",
        "CirMultiplier": "cirMultiplier",
        "Cm": "cm",
        "DefaultEvc": "defaultEvc",
        "EbsMagnitude": "ebsMagnitude",
        "EbsMultiplier": "ebsMultiplier",
        "EirMagnitude": "eirMagnitude",
        "EirMultiplier": "eirMultiplier",
        "EvcId": "evcId",
        "EvcIdLength": "evcIdLength",
        "EvcType": "evcType",
        "PerCos": "perCos",
        "ReferenceId": "referenceId",
        "StatusType": "statusType",
        "UntaggedPriorityTag": "untaggedPriorityTag",
        "UserPriorityBits000": "userPriorityBits000",
        "UserPriorityBits001": "userPriorityBits001",
        "UserPriorityBits010": "userPriorityBits010",
        "UserPriorityBits011": "userPriorityBits011",
        "UserPriorityBits100": "userPriorityBits100",
        "UserPriorityBits101": "userPriorityBits101",
        "UserPriorityBits110": "userPriorityBits110",
        "UserPriorityBits111": "userPriorityBits111",
        "VlanId": "vlanId",
    }
    _SDM_ENUM_MAP = {}

    def __init__(self, parent, list_op=False):
        super(EvcStatusLearnedInfo, self).__init__(parent, list_op)

    @property
    def CbsMagnitude(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies one octet field.
        """
        return self._get_attribute(self._SDM_ATT_MAP["CbsMagnitude"])

    @property
    def CbsMultiplier(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies one octet field. Default is 1.
        """
        return self._get_attribute(self._SDM_ATT_MAP["CbsMultiplier"])

    @property
    def Cf(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Coupling Flag is 1. Default is false.
        """
        return self._get_attribute(self._SDM_ATT_MAP["Cf"])

    @property
    def CirMagnitude(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies one octet field. Default is 1.
        """
        return self._get_attribute(self._SDM_ATT_MAP["CirMagnitude"])

    @property
    def CirMultiplier(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies two octet field. Default is 1.
        """
        return self._get_attribute(self._SDM_ATT_MAP["CirMultiplier"])

    @property
    def Cm(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Colored Mode Flag is 1. Default is false.
        """
        return self._get_attribute(self._SDM_ATT_MAP["Cm"])

    @property
    def DefaultEvc(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies the default EVC.
        """
        return self._get_attribute(self._SDM_ATT_MAP["DefaultEvc"])

    @property
    def EbsMagnitude(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies one octet field. Default is 1.
        """
        return self._get_attribute(self._SDM_ATT_MAP["EbsMagnitude"])

    @property
    def EbsMultiplier(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies one octet field. Default is 1.
        """
        return self._get_attribute(self._SDM_ATT_MAP["EbsMultiplier"])

    @property
    def EirMagnitude(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies one octet field. Default is 1.
        """
        return self._get_attribute(self._SDM_ATT_MAP["EirMagnitude"])

    @property
    def EirMultiplier(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies two octet field. Default is 1.
        """
        return self._get_attribute(self._SDM_ATT_MAP["EirMultiplier"])

    @property
    def EvcId(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies the ID of the Ethernet Virtual Connection.
        """
        return self._get_attribute(self._SDM_ATT_MAP["EvcId"])

    @property
    def EvcIdLength(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies the length of the EVC ID.
        """
        return self._get_attribute(self._SDM_ATT_MAP["EvcIdLength"])

    @property
    def EvcType(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies the type of EVC.
        """
        return self._get_attribute(self._SDM_ATT_MAP["EvcType"])

    @property
    def PerCos(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Per CoS Flag shows user_priority bit values as significant and the value is set to 1. If the value is set to 0, the user_priority bit values as ignored and not processed. Default is 0
        """
        return self._get_attribute(self._SDM_ATT_MAP["PerCos"])

    @property
    def ReferenceId(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies the EVC reference Id.
        """
        return self._get_attribute(self._SDM_ATT_MAP["ReferenceId"])

    @property
    def StatusType(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies the EVC status.
        """
        return self._get_attribute(self._SDM_ATT_MAP["StatusType"])

    @property
    def UntaggedPriorityTag(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies the priority tag of the untagged value.
        """
        return self._get_attribute(self._SDM_ATT_MAP["UntaggedPriorityTag"])

    @property
    def UserPriorityBits000(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Bandwidth Profile applies to frames with user_priority as 000 and the value is set to 1. Default is 0.
        """
        return self._get_attribute(self._SDM_ATT_MAP["UserPriorityBits000"])

    @property
    def UserPriorityBits001(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Bandwidth Profile applies to frames with user_priority as 001 and the value is set to 1. Default is 0.
        """
        return self._get_attribute(self._SDM_ATT_MAP["UserPriorityBits001"])

    @property
    def UserPriorityBits010(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Bandwidth Profile applies to frames with user_priority as 010 and the value is set to 1. Default is 0.
        """
        return self._get_attribute(self._SDM_ATT_MAP["UserPriorityBits010"])

    @property
    def UserPriorityBits011(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Bandwidth Profile applies to frames with user_priority as 011 and the value is set to 1. Default is 0.
        """
        return self._get_attribute(self._SDM_ATT_MAP["UserPriorityBits011"])

    @property
    def UserPriorityBits100(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Bandwidth Profile applies to frames with user_priority as 100 and the value is set to 1. Default is 0.
        """
        return self._get_attribute(self._SDM_ATT_MAP["UserPriorityBits100"])

    @property
    def UserPriorityBits101(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Bandwidth Profile applies to frames with user_priority as 101 and the value is set to 1. Default is 0.
        """
        return self._get_attribute(self._SDM_ATT_MAP["UserPriorityBits101"])

    @property
    def UserPriorityBits110(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Bandwidth Profile applies to frames with user_priority as 110 and the value is set to 1. Default is 0.
        """
        return self._get_attribute(self._SDM_ATT_MAP["UserPriorityBits110"])

    @property
    def UserPriorityBits111(self):
        # type: () -> str
        """
        Returns
        -------
        - str: If enabled, Bandwidth Profile applies to frames with user_priority as 111 and the value is set to 1. Default is 0.
        """
        return self._get_attribute(self._SDM_ATT_MAP["UserPriorityBits111"])

    @property
    def VlanId(self):
        # type: () -> str
        """
        Returns
        -------
        - str: It signifies the ID of the virtual local area network.
        """
        return self._get_attribute(self._SDM_ATT_MAP["VlanId"])

    def add(self):
        """Adds a new evcStatusLearnedInfo resource on the json, only valid with batch add utility

        Returns
        -------
        - self: This instance with all currently retrieved evcStatusLearnedInfo resources using find and the newly added evcStatusLearnedInfo resources available through an iterator or index

        Raises
        ------
        - Exception: if this function is not being used with config assistance
        """
        return self._add_xpath(self._map_locals(self._SDM_ATT_MAP, locals()))

    def find(
        self,
        CbsMagnitude=None,
        CbsMultiplier=None,
        Cf=None,
        CirMagnitude=None,
        CirMultiplier=None,
        Cm=None,
        DefaultEvc=None,
        EbsMagnitude=None,
        EbsMultiplier=None,
        EirMagnitude=None,
        EirMultiplier=None,
        EvcId=None,
        EvcIdLength=None,
        EvcType=None,
        PerCos=None,
        ReferenceId=None,
        StatusType=None,
        UntaggedPriorityTag=None,
        UserPriorityBits000=None,
        UserPriorityBits001=None,
        UserPriorityBits010=None,
        UserPriorityBits011=None,
        UserPriorityBits100=None,
        UserPriorityBits101=None,
        UserPriorityBits110=None,
        UserPriorityBits111=None,
        VlanId=None,
    ):
        # type: (str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str, str) -> EvcStatusLearnedInfo
        """Finds and retrieves evcStatusLearnedInfo resources from the server.

        All named parameters are evaluated on the server using regex. The named parameters can be used to selectively retrieve evcStatusLearnedInfo resources from the server.
        To retrieve an exact match ensure the parameter value starts with ^ and ends with $
        By default the find method takes no parameters and will retrieve all evcStatusLearnedInfo resources from the server.

        Args
        ----
        - CbsMagnitude (str): It signifies one octet field.
        - CbsMultiplier (str): It signifies one octet field. Default is 1.
        - Cf (str): If enabled, Coupling Flag is 1. Default is false.
        - CirMagnitude (str): It signifies one octet field. Default is 1.
        - CirMultiplier (str): It signifies two octet field. Default is 1.
        - Cm (str): If enabled, Colored Mode Flag is 1. Default is false.
        - DefaultEvc (str): It signifies the default EVC.
        - EbsMagnitude (str): It signifies one octet field. Default is 1.
        - EbsMultiplier (str): It signifies one octet field. Default is 1.
        - EirMagnitude (str): It signifies one octet field. Default is 1.
        - EirMultiplier (str): It signifies two octet field. Default is 1.
        - EvcId (str): It signifies the ID of the Ethernet Virtual Connection.
        - EvcIdLength (str): It signifies the length of the EVC ID.
        - EvcType (str): It signifies the type of EVC.
        - PerCos (str): If enabled, Per CoS Flag shows user_priority bit values as significant and the value is set to 1. If the value is set to 0, the user_priority bit values as ignored and not processed. Default is 0
        - ReferenceId (str): It signifies the EVC reference Id.
        - StatusType (str): It signifies the EVC status.
        - UntaggedPriorityTag (str): It signifies the priority tag of the untagged value.
        - UserPriorityBits000 (str): If enabled, Bandwidth Profile applies to frames with user_priority as 000 and the value is set to 1. Default is 0.
        - UserPriorityBits001 (str): If enabled, Bandwidth Profile applies to frames with user_priority as 001 and the value is set to 1. Default is 0.
        - UserPriorityBits010 (str): If enabled, Bandwidth Profile applies to frames with user_priority as 010 and the value is set to 1. Default is 0.
        - UserPriorityBits011 (str): If enabled, Bandwidth Profile applies to frames with user_priority as 011 and the value is set to 1. Default is 0.
        - UserPriorityBits100 (str): If enabled, Bandwidth Profile applies to frames with user_priority as 100 and the value is set to 1. Default is 0.
        - UserPriorityBits101 (str): If enabled, Bandwidth Profile applies to frames with user_priority as 101 and the value is set to 1. Default is 0.
        - UserPriorityBits110 (str): If enabled, Bandwidth Profile applies to frames with user_priority as 110 and the value is set to 1. Default is 0.
        - UserPriorityBits111 (str): If enabled, Bandwidth Profile applies to frames with user_priority as 111 and the value is set to 1. Default is 0.
        - VlanId (str): It signifies the ID of the virtual local area network.

        Returns
        -------
        - self: This instance with matching evcStatusLearnedInfo resources retrieved from the server available through an iterator or index

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._select(self._map_locals(self._SDM_ATT_MAP, locals()))

    def read(self, href):
        """Retrieves a single instance of evcStatusLearnedInfo data from the server.

        Args
        ----
        - href (str): An href to the instance to be retrieved

        Returns
        -------
        - self: This instance with the evcStatusLearnedInfo resources from the server available through an iterator or index

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._read(href)