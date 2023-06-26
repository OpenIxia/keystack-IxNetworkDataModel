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


class NacSettings(Base):
    """Nac Options
    The NacSettings class encapsulates a required nacSettings resource which will be retrieved from the server every time the property is accessed.
    """

    __slots__ = ()
    _SDM_NAME = "nacSettings"
    _SDM_ATT_MAP = {
        "ObjectId": "objectId",
    }
    _SDM_ENUM_MAP = {}

    def __init__(self, parent, list_op=False):
        super(NacSettings, self).__init__(parent, list_op)

    @property
    def NacPosture(self):
        """
        Returns
        -------
        - obj(ixnetwork_restpy.testplatform.sessions.ixnetwork.globals.protocolstack.eapoudpglobals.nacsettings.nacposture.nacposture.NacPosture): An instance of the NacPosture class

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        from ixnetwork_restpy.testplatform.sessions.ixnetwork.globals.protocolstack.eapoudpglobals.nacsettings.nacposture.nacposture import (
            NacPosture,
        )

        if len(self._object_properties) > 0:
            if self._properties.get("NacPosture", None) is not None:
                return self._properties.get("NacPosture")
        return NacPosture(self)

    @property
    def NacSequence(self):
        """
        Returns
        -------
        - obj(ixnetwork_restpy.testplatform.sessions.ixnetwork.globals.protocolstack.eapoudpglobals.nacsettings.nacsequence.nacsequence.NacSequence): An instance of the NacSequence class

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        from ixnetwork_restpy.testplatform.sessions.ixnetwork.globals.protocolstack.eapoudpglobals.nacsettings.nacsequence.nacsequence import (
            NacSequence,
        )

        if len(self._object_properties) > 0:
            if self._properties.get("NacSequence", None) is not None:
                return self._properties.get("NacSequence")
        return NacSequence(self)

    @property
    def NacTlv(self):
        """
        Returns
        -------
        - obj(ixnetwork_restpy.testplatform.sessions.ixnetwork.globals.protocolstack.eapoudpglobals.nacsettings.nactlv.nactlv.NacTlv): An instance of the NacTlv class

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        from ixnetwork_restpy.testplatform.sessions.ixnetwork.globals.protocolstack.eapoudpglobals.nacsettings.nactlv.nactlv import (
            NacTlv,
        )

        if len(self._object_properties) > 0:
            if self._properties.get("NacTlv", None) is not None:
                return self._properties.get("NacTlv")
        return NacTlv(self)

    @property
    def NacVendors(self):
        """
        Returns
        -------
        - obj(ixnetwork_restpy.testplatform.sessions.ixnetwork.globals.protocolstack.eapoudpglobals.nacsettings.nacvendors.nacvendors.NacVendors): An instance of the NacVendors class

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        from ixnetwork_restpy.testplatform.sessions.ixnetwork.globals.protocolstack.eapoudpglobals.nacsettings.nacvendors.nacvendors import (
            NacVendors,
        )

        if len(self._object_properties) > 0:
            if self._properties.get("NacVendors", None) is not None:
                return self._properties.get("NacVendors")
        return NacVendors(self)

    @property
    def ObjectId(self):
        # type: () -> str
        """
        Returns
        -------
        - str: Unique identifier for this object
        """
        return self._get_attribute(self._SDM_ATT_MAP["ObjectId"])

    def find(self, ObjectId=None):
        # type: (str) -> NacSettings
        """Finds and retrieves nacSettings resources from the server.

        All named parameters are evaluated on the server using regex. The named parameters can be used to selectively retrieve nacSettings resources from the server.
        To retrieve an exact match ensure the parameter value starts with ^ and ends with $
        By default the find method takes no parameters and will retrieve all nacSettings resources from the server.

        Args
        ----
        - ObjectId (str): Unique identifier for this object

        Returns
        -------
        - self: This instance with matching nacSettings resources retrieved from the server available through an iterator or index

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._select(self._map_locals(self._SDM_ATT_MAP, locals()))

    def read(self, href):
        """Retrieves a single instance of nacSettings data from the server.

        Args
        ----
        - href (str): An href to the instance to be retrieved

        Returns
        -------
        - self: This instance with the nacSettings resources from the server available through an iterator or index

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._read(href)
