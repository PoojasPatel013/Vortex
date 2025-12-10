from abc import ABC, abstractmethod
from typing import Any, Dict

class BaseScanner(ABC):
    @abstractmethod
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform the scan on the target.
        Returns a dictionary of results.
        """
        pass
