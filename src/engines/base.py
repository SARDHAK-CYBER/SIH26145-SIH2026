from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional
from src.alert_schema import Alert

class Detector(ABC):
    """Common interface every detection engine implements."""
    name: str

    @abstractmethod
    async def score(self, flow: dict) -> Optional[Alert]:
        """Return an Alert if this flow crosses the engine's threshold, else None."""
        raise NotImplementedError