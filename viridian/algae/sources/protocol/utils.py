from asyncio import FIRST_COMPLETED, FIRST_EXCEPTION, CancelledError, Event, Future, Lock, Task, create_task, current_task, timeout, wait
from contextlib import asynccontextmanager
from enum import IntEnum, unique
from typing import Any, Coroutine, Optional, TypeVar, Union

from ..utils.misc import create_logger


# TYPES:

@unique
class ProtocolTypes(IntEnum):
    ALGAE = 65
    REEF = 82


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


class ProtocolBaseError(Exception):
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


async def _future_wrapper(future: Future[_T]) -> _T:
    return await future


# BASES:


class _ProtocolBase:
    def __init__(self) -> None:
        self._sleeper = Event()
        self._background = list()
        self._logger = create_logger(type(self).__name__)

    async def _sleep(self, action: Union[Coroutine[Any, Any, _T], Future[_T], None] = None, delay: Optional[int] = None) -> Optional[_T]:
        events = list()
        try:
            wait_task = create_task(self._sleeper.wait())
            events += [wait_task]
            if action is not None:
                action_task = create_task(action if isinstance(action, Coroutine) else _future_wrapper(action))
                events = [wait_task, action_task]
            async with timeout(delay / 1000 if delay is not None else None):
                done, pending = await wait(events, return_when=FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                for task in done:
                    if action is not None and task == action_task:
                        raise TyphoonInterrupted(task.result())
                    elif task == wait_task:
                        raise TyphoonShutdown(f"Connection to peer {self._peer_address}:{self._peer_port} was shut down")
        except TimeoutError:
            for event in events:
                event.cancel()
            return None
        except CancelledError:
            for event in events:
                event.cancel()
            raise

    async def _monitor_task(self, main_task: Task, background_task: Task) -> None:
        try:
            await background_task
        except Exception as e:
            self._logger.error(f"Background task failed: {e}")
            await main_task.cancel(e)

    async def close(self, _: bool = True) -> None:
        self._sleeper.set()
        while len(self._background) > 0:
            background = self._background.pop()
            background.cancel()

    async def wrap_backgrounds(self, *backgrounds: Task):
        if len(backgrounds) > 1:
            done, pending = await wait(backgrounds, return_when=FIRST_EXCEPTION)
            for task in pending:
                task.cancel()
            for task in done:
                exception = task.exception()
                if exception is not None:
                    raise exception
            raise RuntimeError("Unknown task failed!")
        else:
            await backgrounds[0]

    @asynccontextmanager
    async def ctx(self, graceful: bool = True):
        background_task = create_task(self.wrap_backgrounds(*self._background))
        monitor_task = create_task(self._monitor_task(current_task(), background_task))

        try:
            yield self
        except CancelledError:
            pass
        finally:
            self._logger.info("Cleaning up context...")
            background_task.cancel()
            monitor_task.cancel()
            await self.close(graceful)
