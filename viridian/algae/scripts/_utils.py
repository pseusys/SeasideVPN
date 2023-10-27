from os import getcwd
from pathlib import Path


_CWD = getcwd()
if _CWD.endswith("algae"):
    ALGAE_ROOT = Path(_CWD)
else:
    ALGAE_ROOT = Path(_CWD) / "viridian" / "algae"
