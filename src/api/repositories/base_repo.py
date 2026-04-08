from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseRepository(ABC):
    @abstractmethod
    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_anomalies(self, limit: int = 100) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        pass
