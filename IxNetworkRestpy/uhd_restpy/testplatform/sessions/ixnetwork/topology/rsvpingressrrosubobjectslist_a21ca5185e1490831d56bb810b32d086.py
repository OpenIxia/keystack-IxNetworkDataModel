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


class RsvpIngressRroSubObjectsList(Base):
    """Rsvp Ingress RRO Sub-Objects
    The RsvpIngressRroSubObjectsList class encapsulates a list of rsvpIngressRroSubObjectsList resources that are managed by the system.
    A list of resources can be retrieved from the server using the RsvpIngressRroSubObjectsList.find() method.
    """

    __slots__ = ()
    _SDM_NAME = 'rsvpIngressRroSubObjectsList'
    _SDM_ATT_MAP = {
        'BandwidthProtection': 'bandwidthProtection',
        'CType': 'cType',
        'Count': 'count',
        'DescriptiveName': 'descriptiveName',
        'GlobalLabel': 'globalLabel',
        'Ip': 'ip',
        'Label': 'label',
        'LocalIp': 'localIp',
        'Name': 'name',
        'NodeProtection': 'nodeProtection',
        'P2mpIdAsIp': 'p2mpIdAsIp',
        'P2mpIdAsNum': 'p2mpIdAsNum',
        'ProtectionAvailable': 'protectionAvailable',
        'ProtectionInUse': 'protectionInUse',
        'Type': 'type',
    }
    _SDM_ENUM_MAP = {
    }

    def __init__(self, parent, list_op=False):
        super(RsvpIngressRroSubObjectsList, self).__init__(parent, list_op)

    @property
    def BandwidthProtection(self):
        # type: () -> 'Multivalue'
        """
        Returns
        -------
        - obj(uhd_restpy.multivalue.Multivalue): Bandwidth Protection
        """
        from uhd_restpy.multivalue import Multivalue
        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP['BandwidthProtection']))

    @property
    def CType(self):
        # type: () -> 'Multivalue'
        """
        Returns
        -------
        - obj(uhd_restpy.multivalue.Multivalue): C-Type
        """
        from uhd_restpy.multivalue import Multivalue
        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP['CType']))

    @property
    def Count(self):
        # type: () -> int
        """
        Returns
        -------
        - number: Number of elements inside associated multiplier-scaled container object, e.g. number of devices inside a Device Group.
        """
        return self._get_attribute(self._SDM_ATT_MAP['Count'])

    @property
    def DescriptiveName(self):
        # type: () -> str
        """
        Returns
        -------
        - str: Longer, more descriptive name for element. It's not guaranteed to be unique like -name-, but may offer more context.
        """
        return self._get_attribute(self._SDM_ATT_MAP['DescriptiveName'])

    @property
    def GlobalLabel(self):
        # type: () -> 'Multivalue'
        """
        Returns
        -------
        - obj(uhd_restpy.multivalue.Multivalue): Global Label
        """
        from uhd_restpy.multivalue import Multivalue
        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP['GlobalLabel']))

    @property
    def Ip(self):
        # type: () -> 'Multivalue'
        """
        Returns
        -------
        - obj(uhd_restpy.multivalue.Multivalue): IP
        """
        from uhd_restpy.multivalue import Multivalue
        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP['Ip']))

    @property
    def Label(self):
        # type: () -> 'Multivalue'
        """
        Returns
        -------
        - obj(uhd_restpy.multivalue.Multivalue): Label
        """
        from uhd_restpy.multivalue import Multivalue
        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP['Label']))

    @property
    def LocalIp(self):
        # type: () -> List[str]
        """
        Returns
        -------
        - list(str): Local IP
        """
        return self._get_attribute(self._SDM_ATT_MAP['LocalIp'])

    @property
    def Name(self):
        # type: () -> str
        """
        Returns
        -------
        - str: Name of NGPF element, guaranteed to be unique in Scenario
        """
        return self._get_attribute(self._SDM_ATT_MAP['Name'])
    @Name.setter
    def Name(self, value):
        # type: (str) -> None
        self._set_attribute(self._SDM_ATT_MAP['Name'], value)

    @property
    def NodeProtection(self):
        # type: () -> 'Multivalue'
        """
        Returns
        -------
        - obj(uhd_restpy.multivalue.Multivalue): Node Protection
        """
        from uhd_restpy.multivalue import Multivalue
        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP['NodeProtection']))

    @property
    def P2mpIdAsIp(self):
        # type: () -> List[str]
        """
        Returns
        -------
        - list(str): P2MP ID As IP
        """
        return self._get_attribute(self._SDM_ATT_MAP['P2mpIdAsIp'])

    @property
    def P2mpIdAsNum(self):
        # type: () -> List[str]
        """
        Returns
        -------
        - list(str): P2MP ID displayed in Integer format
        """
        return self._get_attribute(self._SDM_ATT_MAP['P2mpIdAsNum'])

    @property
    def ProtectionAvailable(self):
        # type: () -> 'Multivalue'
        """
        Returns
        -------
        - obj(uhd_restpy.multivalue.Multivalue): Protection Available
        """
        from uhd_restpy.multivalue import Multivalue
        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP['ProtectionAvailable']))

    @property
    def ProtectionInUse(self):
        # type: () -> 'Multivalue'
        """
        Returns
        -------
        - obj(uhd_restpy.multivalue.Multivalue): Protection In Use
        """
        from uhd_restpy.multivalue import Multivalue
        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP['ProtectionInUse']))

    @property
    def Type(self):
        # type: () -> 'Multivalue'
        """
        Returns
        -------
        - obj(uhd_restpy.multivalue.Multivalue): Type: IP or Label
        """
        from uhd_restpy.multivalue import Multivalue
        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP['Type']))

    def update(self, Name=None):
        # type: (str) -> RsvpIngressRroSubObjectsList
        """Updates rsvpIngressRroSubObjectsList resource on the server.

        This method has some named parameters with a type: obj (Multivalue).
        The Multivalue class has documentation that details the possible values for those named parameters.

        Args
        ----
        - Name (str): Name of NGPF element, guaranteed to be unique in Scenario

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._update(self._map_locals(self._SDM_ATT_MAP, locals()))

    def add(self, Name=None):
        # type: (str) -> RsvpIngressRroSubObjectsList
        """Adds a new rsvpIngressRroSubObjectsList resource on the json, only valid with batch add utility

        Args
        ----
        - Name (str): Name of NGPF element, guaranteed to be unique in Scenario

        Returns
        -------
        - self: This instance with all currently retrieved rsvpIngressRroSubObjectsList resources using find and the newly added rsvpIngressRroSubObjectsList resources available through an iterator or index

        Raises
        ------
        - Exception: if this function is not being used with config assistance
        """
        return self._add_xpath(self._map_locals(self._SDM_ATT_MAP, locals()))

    def find(self, Count=None, DescriptiveName=None, LocalIp=None, Name=None, P2mpIdAsIp=None, P2mpIdAsNum=None):
        # type: (int, str, List[str], str, List[str], List[str]) -> RsvpIngressRroSubObjectsList
        """Finds and retrieves rsvpIngressRroSubObjectsList resources from the server.

        All named parameters are evaluated on the server using regex. The named parameters can be used to selectively retrieve rsvpIngressRroSubObjectsList resources from the server.
        To retrieve an exact match ensure the parameter value starts with ^ and ends with $
        By default the find method takes no parameters and will retrieve all rsvpIngressRroSubObjectsList resources from the server.

        Args
        ----
        - Count (number): Number of elements inside associated multiplier-scaled container object, e.g. number of devices inside a Device Group.
        - DescriptiveName (str): Longer, more descriptive name for element. It's not guaranteed to be unique like -name-, but may offer more context.
        - LocalIp (list(str)): Local IP
        - Name (str): Name of NGPF element, guaranteed to be unique in Scenario
        - P2mpIdAsIp (list(str)): P2MP ID As IP
        - P2mpIdAsNum (list(str)): P2MP ID displayed in Integer format

        Returns
        -------
        - self: This instance with matching rsvpIngressRroSubObjectsList resources retrieved from the server available through an iterator or index

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._select(self._map_locals(self._SDM_ATT_MAP, locals()))

    def read(self, href):
        """Retrieves a single instance of rsvpIngressRroSubObjectsList data from the server.

        Args
        ----
        - href (str): An href to the instance to be retrieved

        Returns
        -------
        - self: This instance with the rsvpIngressRroSubObjectsList resources from the server available through an iterator or index

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._read(href)

    def get_device_ids(self, PortNames=None, BandwidthProtection=None, CType=None, GlobalLabel=None, Ip=None, Label=None, NodeProtection=None, ProtectionAvailable=None, ProtectionInUse=None, Type=None):
        """Base class infrastructure that gets a list of rsvpIngressRroSubObjectsList device ids encapsulated by this object.

        Use the optional regex parameters in the method to refine the list of device ids encapsulated by this object.

        Args
        ----
        - PortNames (str): optional regex of port names
        - BandwidthProtection (str): optional regex of bandwidthProtection
        - CType (str): optional regex of cType
        - GlobalLabel (str): optional regex of globalLabel
        - Ip (str): optional regex of ip
        - Label (str): optional regex of label
        - NodeProtection (str): optional regex of nodeProtection
        - ProtectionAvailable (str): optional regex of protectionAvailable
        - ProtectionInUse (str): optional regex of protectionInUse
        - Type (str): optional regex of type

        Returns
        -------
        - list(int): A list of device ids that meets the regex criteria provided in the method parameters

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._get_ngpf_device_ids(locals())
