from pathlib import Path
from sys import path

path.append(str(Path(__file__).parent))

from .whirlpool_viridian_grpc import WhirlpoolViridianStub
