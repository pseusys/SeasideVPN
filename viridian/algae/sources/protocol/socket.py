from abc import ABC, abstractmethod
from asyncio import Future
from typing import Callable, Optional

from .utils import TyphoonReturnCode

ReceiveCallback = Callable[[bytes], Future[None]]
ServeCallback = Callable[[int, bytes], Future[None]]
ConnectionCallback = Callable[[str, "SeasidePeer", bytes], Future[None]]


class SeasidePeer(ABC):
    @abstractmethod
    async def read(self) -> bytes:
        raise NotImplementedError

    @abstractmethod
    async def write(self, data: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    async def close(self):
        raise NotImplementedError


class SeasideClient(SeasidePeer, ABC):
    @abstractmethod
    async def connect(self, callback: Optional[ReceiveCallback] = None):
        raise NotImplementedError


class SeasideListener(ABC):
    @abstractmethod
    async def listen(self, connection_callback: Optional[ConnectionCallback] = TyphoonReturnCode, data_callback: Optional[ServeCallback] = None):
        raise NotImplementedError
