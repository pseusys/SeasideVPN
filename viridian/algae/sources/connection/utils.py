from enum import IntEnum


class TyphoonFlag(IntEnum):
    INIT = 1
    HDSK = 2
    DATA = 3
    TERM = 4


class MessageType(IntEnum):
    HANDSHAKE = 1
    HANDSHAKE_DATA = 2
    DATA = 3
    TERMINATION = 4


class CalculatingRTT:
    """
    Calculate RTT using Exponential Weighted Moving Average (EWMA).
    """

    _TYPHOON_ALPHA = 0.125
    _TYPHOON_BETA = 0.25

    def __init__(self, timeout: float):
        self.timeout = timeout
        self.srtt = None
        self.rttvar = None

    def _update_timeout(self, rtt: float):
        if self.srtt is None or self.rttvar is None:
            self.srtt = rtt
            self.rttvar = rtt / 2
        else:
            self.rttvar = (1 - self._TYPHOON_BETA) * self.rttvar + self._TYPHOON_BETA * abs(self.srtt - rtt)
            self.srtt = (1 - self._TYPHOON_ALPHA) * self.srtt + self._TYPHOON_ALPHA * rtt
        self.timeout = self.srtt + 4 * self.rttvar
