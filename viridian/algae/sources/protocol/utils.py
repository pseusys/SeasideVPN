from enum import IntEnum, unique


@unique
class TyphoonFlag(IntEnum):
    INIT = 128
    HDSK = 64
    DATA = 32
    TERM = 16


@unique
class MessageType(IntEnum):
    HANDSHAKE = TyphoonFlag.HDSK
    HANDSHAKE_DATA = TyphoonFlag.HDSK | TyphoonFlag.DATA
    DATA = TyphoonFlag.DATA
    TERMINATION = TyphoonFlag.TERM


@unique
class TyphoonReturnCode(IntEnum):
    SUCCESS = 0


# ERRORS:


class TyphoonBaseError(RuntimeError):
    pass


class TyphoonInitializationError(TyphoonBaseError):
    pass


class TyphoonParseError(TyphoonBaseError):
    pass


class TyphoonTerminationError(TyphoonBaseError):
    pass

