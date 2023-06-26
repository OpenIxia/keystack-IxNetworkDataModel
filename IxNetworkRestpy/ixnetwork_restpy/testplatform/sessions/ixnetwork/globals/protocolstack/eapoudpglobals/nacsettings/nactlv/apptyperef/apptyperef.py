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


class AppTypeRef(Base):
    """TLV Application Type
    The AppTypeRef class encapsulates a required appTypeRef resource which will be retrieved from the server every time the property is accessed.
    """

    __slots__ = ()
    _SDM_NAME = "appTypeRef"
    _SDM_ATT_MAP = {
        "Name": "name",
        "ObjectId": "objectId",
        "Value": "value",
    }
    _SDM_ENUM_MAP = {}

    def __init__(self, parent, list_op=False):
        super(AppTypeRef, self).__init__(parent, list_op)

    @property
    def NacApps(self):
        """
        Returns
        -------
        - obj(ixnetwork_restpy.testplatform.sessions.ixnetwork.globals.protocolstack.eapoudpglobals.nacsettings.nactlv.apptyperef.nacapps.nacapps.NacApps): An instance of the NacApps class

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        from ixnetwork_restpy.testplatform.sessions.ixnetwork.globals.protocolstack.eapoudpglobals.nacsettings.nactlv.apptyperef.nacapps.nacapps import (
            NacApps,
        )

        if len(self._object_properties) > 0:
            if self._properties.get("NacApps", None) is not None:
                return self._properties.get("NacApps")
        return NacApps(self)

    @property
    def Name(self):
        # type: () -> str
        """
        Returns
        -------
        - str: AppType Name.
        """
        return self._get_attribute(self._SDM_ATT_MAP["Name"])

    @Name.setter
    def Name(self, value):
        # type: (str) -> None
        self._set_attribute(self._SDM_ATT_MAP["Name"], value)

    @property
    def ObjectId(self):
        # type: () -> str
        """
        Returns
        -------
        - str: Unique identifier for this object
        """
        return self._get_attribute(self._SDM_ATT_MAP["ObjectId"])

    @property
    def Value(self):
        # type: () -> int
        """
        Returns
        -------
        - number: AppType ID.
        """
        return self._get_attribute(self._SDM_ATT_MAP["Value"])

    @Value.setter
    def Value(self, value):
        # type: (int) -> None
        self._set_attribute(self._SDM_ATT_MAP["Value"], value)

    def update(self, Name=None, Value=None):
        # type: (str, int) -> AppTypeRef
        """Updates appTypeRef resource on the server.

        Args
        ----
        - Name (str): AppType Name.
        - Value (number): AppType ID.

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._update(self._map_locals(self._SDM_ATT_MAP, locals()))

    def find(self, Name=None, ObjectId=None, Value=None):
        # type: (str, str, int) -> AppTypeRef
        """Finds and retrieves appTypeRef resources from the server.

        All named parameters are evaluated on the server using regex. The named parameters can be used to selectively retrieve appTypeRef resources from the server.
        To retrieve an exact match ensure the parameter value starts with ^ and ends with $
        By default the find method takes no parameters and will retrieve all appTypeRef resources from the server.

        Args
        ----
        - Name (str): AppType Name.
        - ObjectId (str): Unique identifier for this object
        - Value (number): AppType ID.

        Returns
        -------
        - self: This instance with matching appTypeRef resources retrieved from the server available through an iterator or index

        Raises
        ------
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._select(self._map_locals(self._SDM_ATT_MAP, locals()))

    def read(self, href):
        """Retrieves a single instance of appTypeRef data from the server.

        Args
        ----
        - href (str): An href to the instance to be retrieved

        Returns
        -------
        - self: This instance with the appTypeRef resources from the server available through an iterator or index

        Raises
        ------
        - NotFoundError: The requested resource does not exist on the server
        - ServerError: The server has encountered an uncategorized error condition
        """
        return self._read(href)