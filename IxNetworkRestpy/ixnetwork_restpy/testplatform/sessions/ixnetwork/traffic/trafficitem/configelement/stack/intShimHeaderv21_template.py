from ixnetwork_restpy.base import Base
from ixnetwork_restpy.files import Files


class IntShimHeaderv21(Base):
    __slots__ = ()
    _SDM_NAME = "intShimHeaderv21"
    _SDM_ATT_MAP = {
        "ShimHeaderType": "intShimHeaderv21.shimHeader.type-1",
        "ShimHeaderNpt": "intShimHeaderv21.shimHeader.npt-2",
        "ShimHeaderReserved": "intShimHeaderv21.shimHeader.reserved-3",
        "ShimHeaderLength": "intShimHeaderv21.shimHeader.length-4",
        "ShimHeaderDscp": "intShimHeaderv21.shimHeader.dscp-5",
    }

    def __init__(self, parent, list_op=False):
        super(IntShimHeaderv21, self).__init__(parent, list_op)

    @property
    def ShimHeaderType(self):
        """
        Display Name: Type
        Default Value: 1
        Value Format: decimal
        Available enum values: INT-MD, 1, INT-Destination, 2, INT-MX, 3
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["ShimHeaderType"])
        )

    @property
    def ShimHeaderNpt(self):
        """
        Display Name: NPT (Next Protocol Type)
        Default Value: 0
        Value Format: decimal
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(self, self._get_attribute(self._SDM_ATT_MAP["ShimHeaderNpt"]))

    @property
    def ShimHeaderReserved(self):
        """
        Display Name: Reserved
        Default Value: 0x00
        Value Format: hex
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["ShimHeaderReserved"])
        )

    @property
    def ShimHeaderLength(self):
        """
        Display Name: Length
        Default Value: 2
        Value Format: decimal
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["ShimHeaderLength"])
        )

    @property
    def ShimHeaderDscp(self):
        """
        Display Name: UDP port, IP proto, or DSCP
        Default Value: 0x00
        Value Format: hex
        """
        from ixnetwork_restpy.multivalue import Multivalue

        return Multivalue(
            self, self._get_attribute(self._SDM_ATT_MAP["ShimHeaderDscp"])
        )

    def add(self):
        return self._create(self._map_locals(self._SDM_ATT_MAP, locals()))
