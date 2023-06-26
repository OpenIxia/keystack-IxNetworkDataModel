from ixnetwork_restpy.base import Base
from ixnetwork_restpy.files import Files


class PimAssertMessage(Base):
    __slots__ = ()
    _SDM_NAME = "pimAssertMessage"
    _SDM_ATT_MAP = {
        "HeaderVersion": "pimAssertMessage.header.version-1",
        "HeaderType": "pimAssertMessage.header.type-2",
        "HeaderReserved": "pimAssertMessage.header.reserved-3",
        "HeaderChecksum": "pimAssertMessage.header.checksum-4",
        "GroupAddressAddrFamily": "pimAssertMessage.header.groupAddress.addrFamily-5",
        "GroupAddressEncodingType": "pimAssertMessage.header.groupAddress.encodingType-6",
        "GroupAddressB": "pimAssertMessage.header.groupAddress.b-7",
        "GroupAddressReserved": "pimAssertMessage.header.groupAddress.reserved-8",
        "GroupAddressZ": "pimAssertMessage.header.groupAddress.z-9",
        "GroupAddressMaskLength": "pimAssertMessage.header.groupAddress.maskLength-10",
        "GroupMulticastAddrGrpMcastAddrIPv4": "pimAssertMessage.header.groupAddress.groupMulticastAddr.grpMcastAddrIPv4-11",
        "GroupMulticastAddrGrpMcastAddrIPv6": "pimAssertMessage.header.groupAddress.groupMulticastAddr.grpMcastAddrIPv6-12",
        "SourceAddressAddrFamily": "pimAssertMessage.header.sourceAddress.addrFamily-13",
        "SourceAddressEncodingType": "pimAssertMessage.header.sourceAddress.encodingType-14",
        "EncodedUcastSrcAddrSrcAddrIP4": "pimAssertMessage.header.sourceAddress.encodedUcastSrcAddr.srcAddrIP4-15",
        "EncodedUcastSrcAddrSrcAddrIP6": "pimAssertMessage.header.sourceAddress.encodedUcastSrcAddr.srcAddrIP6-16",
        "HeaderR": "pimAssertMessage.header.r-17",
        "HeaderMetricPreference": "pimAssertMessage.header.metricPreference-18",
        "HeaderMetric": "pimAssertMessage.header.metric-19",
    }

    def __init__(self, parent, list_op=False):
        super(PimAssertMessage, self).__init__(parent, list_op)

    @property
    def HeaderVersion(self):
        """
        Display Name: Version
        Default Value: 2
        Value Format: decimal
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP["HeaderVersion"]))

    @property
    def HeaderType(self):
        """
        Display Name: Type
        Default Value: 5
        Value Format: decimal
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP["HeaderType"]))

    @property
    def HeaderReserved(self):
        """
        Display Name: Reserved
        Default Value: 0
        Value Format: decimal
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["HeaderReserved"])
        )

    @property
    def HeaderChecksum(self):
        """
        Display Name: Checksum
        Default Value: 0
        Value Format: hex
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["HeaderChecksum"])
        )

    @property
    def GroupAddressAddrFamily(self):
        """
        Display Name: Addr Family
        Default Value: 1
        Value Format: decimal
        Available enum values: IP, 1, IPv6, 2
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["GroupAddressAddrFamily"])
        )

    @property
    def GroupAddressEncodingType(self):
        """
        Display Name: Encoding Type
        Default Value: 0
        Value Format: decimal
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["GroupAddressEncodingType"])
        )

    @property
    def GroupAddressB(self):
        """
        Display Name: B
        Default Value: 0
        Value Format: hex
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP["GroupAddressB"]))

    @property
    def GroupAddressReserved(self):
        """
        Display Name: Reserved
        Default Value: 0
        Value Format: hex
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["GroupAddressReserved"])
        )

    @property
    def GroupAddressZ(self):
        """
        Display Name: Z
        Default Value: 0
        Value Format: hex
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP["GroupAddressZ"]))

    @property
    def GroupAddressMaskLength(self):
        """
        Display Name: Mask Length
        Default Value: 32
        Value Format: decimal
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["GroupAddressMaskLength"])
        )

    @property
    def GroupMulticastAddrGrpMcastAddrIPv4(self):
        """
        Display Name: Grp Mcast Addr IPv4
        Default Value: 0.0.0.0
        Value Format: iPv4
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self,
            self._get_attribute(
                self._SDM_ATT_MAP["GroupMulticastAddrGrpMcastAddrIPv4"]
            ),
        )

    @property
    def GroupMulticastAddrGrpMcastAddrIPv6(self):
        """
        Display Name: Grp Mcast Addr IPv6
        Default Value: 0::0
        Value Format: iPv6
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self,
            self._get_attribute(
                self._SDM_ATT_MAP["GroupMulticastAddrGrpMcastAddrIPv6"]
            ),
        )

    @property
    def SourceAddressAddrFamily(self):
        """
        Display Name: Addr Family
        Default Value: 1
        Value Format: decimal
        Available enum values: IP, 1, IPv6, 2
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["SourceAddressAddrFamily"])
        )

    @property
    def SourceAddressEncodingType(self):
        """
        Display Name: Encoding Type
        Default Value: 0
        Value Format: decimal
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["SourceAddressEncodingType"])
        )

    @property
    def EncodedUcastSrcAddrSrcAddrIP4(self):
        """
        Display Name: Src Addr IP4
        Default Value: 0.0.0.0
        Value Format: iPv4
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self,
            self._get_attribute(self._SDM_ATT_MAP["EncodedUcastSrcAddrSrcAddrIP4"]),
        )

    @property
    def EncodedUcastSrcAddrSrcAddrIP6(self):
        """
        Display Name: Src Addr IP6
        Default Value: 0::0
        Value Format: iPv6
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self,
            self._get_attribute(self._SDM_ATT_MAP["EncodedUcastSrcAddrSrcAddrIP6"]),
        )

    @property
    def HeaderR(self):
        """
        Display Name: R
        Default Value: 1
        Value Format: hex
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP["HeaderR"]))

    @property
    def HeaderMetricPreference(self):
        """
        Display Name: Metric Preference
        Default Value: 0
        Value Format: hex
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["HeaderMetricPreference"])
        )

    @property
    def HeaderMetric(self):
        """
        Display Name: Metric
        Default Value: 0x0
        Value Format: hex
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP["HeaderMetric"]))

    def add(self):
        return self._create(self._map_locals(self._SDM_ATT_MAP, locals()))
