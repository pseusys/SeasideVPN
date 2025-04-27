from asyncio import CancelledError, Future, create_task, get_running_loop
from enum import IntEnum, unique
from typing import Any, Awaitable, TypeVar


@unique
class ProtocolFlag(IntEnum):
    INIT = 128
    HDSK = 64
    DATA = 32
    TERM = 16


@unique
class ProtocolMessageType(IntEnum):
    HANDSHAKE = ProtocolFlag.HDSK
    HANDSHAKE_DATA = ProtocolFlag.HDSK | ProtocolFlag.DATA
    DATA = ProtocolFlag.DATA
    TERMINATION = ProtocolFlag.TERM


@unique
class ProtocolReturnCode(IntEnum):
    SUCCESS = 0


# ERRORS:


class ProtocolBaseError(RuntimeError):
    pass


class ProtocolInitializationError(ProtocolBaseError):
    pass


class ProtocolParseError(ProtocolBaseError):
    pass


class ProtocolTerminationError(ProtocolBaseError):
    pass


class TyphoonShutdown(Exception):
    pass


class TyphoonInterrupted(Exception):
    def __init__(self, result: Any, *args):
        super().__init__(*args)
        self._result = result


# UTILS:

_T = TypeVar("_T")


async def future_wrapper(future: Future[_T]) -> _T:
    return await future


def monitor_task(awaitable: Awaitable, task_name: str = "asynchronous task") -> None:
    async def guard_task(awaitable: Awaitable) -> None:
        task = create_task(awaitable)
        try:
            await task
        except (CancelledError, TimeoutError, TyphoonShutdown, TyphoonInterrupted, ProtocolTerminationError) as e:
            raise e
        except Exception as e:
            get_running_loop().call_exception_handler(dict(message=f"Unhandled exception in task '{task_name}'!", exception=e, task=task))
            raise e
    return create_task(guard_task(awaitable), name=task_name)
