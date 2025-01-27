from enum import IntEnum


class TyphoonFlag(IntEnum):
    INIT = 128
    HDSK = 64
    DATA = 32
    TERM = 16


class MessageType(IntEnum):
    HANDSHAKE = TyphoonFlag.HDSK
    HANDSHAKE_DATA = TyphoonFlag.HDSK | TyphoonFlag.DATA
    DATA = TyphoonFlag.DATA
    TERMINATION = TyphoonFlag.TERM


class CalculatingRTT:
    """
    Calculate RTT using Exponential Weighted Moving Average (EWMA).
    """

    _TYPHOON_ALPHA = 0.125
    _TYPHOON_BETA = 0.25
    _TYPHOON_MIN_RTT = 1.0
    _TYPHOON_MAX_RTT = 8.0
    _TYPHOON_MIN_TIMEOUT = 1.0
    _TYPHOON_MAX_TIMEOUT = 32.0

    @property
    def rtt(self) -> float:
        return min(max(self.srtt, self._TYPHOON_MIN_RTT), self._TYPHOON_MAX_RTT)

    @property
    def timeout(self) -> float:
        timeout = self.srtt + 4 * self.rttvar
        return min(max(timeout, self._TYPHOON_MIN_TIMEOUT), self._TYPHOON_MAX_TIMEOUT)

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
