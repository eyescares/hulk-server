from pydantic import BaseModel, Field
from typing import Optional, Dict, List
from enum import Enum
import time


class AttackMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"
    MIX = "MIX"


class PortStatus(str, Enum):
    ALIVE = "alive"
    DOWN = "down"
    PROTECTED = "protected"
    SKIPPED = "skipped"


class AttackStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    STOPPING = "stopping"
    FINISHED = "finished"
    ALL_DOWN = "all_down"
    ERROR = "error"


class PortStats(BaseModel):
    port: int = 0
    status: PortStatus = PortStatus.ALIVE
    total_requests: int = 0
    successful: int = 0
    failed: int = 0
    consecutive_fails: int = 0
    status_codes: Dict[int, int] = {}
    last_response_time: float = 0.0


class AttackRequest(BaseModel):
    target: str
    ports: List[int] = Field(default=[443, 2222, 8443])
    method: AttackMethod = AttackMethod.MIX
    threads: int = Field(default=500, ge=1, le=2000)
    duration: int = Field(default=0, ge=0)
    use_proxies: bool = False


class AttackStats(BaseModel):
    target: str = ""
    method: str = ""
    status: AttackStatus = AttackStatus.IDLE
    ports: Dict[int, PortStats] = {}
    total_requests: int = 0
    successful: int = 0
    failed: int = 0
    requests_per_second: float = 0.0
    elapsed: float = 0.0
    started_at: float = 0.0
    threads: int = 0
    proxies_loaded: int = 0

    def snapshot(self) -> "AttackStats":
        if self.started_at > 0:
            self.elapsed = round(time.time() - self.started_at, 1)
            if self.elapsed > 0:
                self.requests_per_second = round(self.total_requests / self.elapsed, 1)
        return self.model_copy(deep=True)

    @property
    def alive_ports(self) -> List[int]:
        return [p for p, s in self.ports.items() if s.status == PortStatus.ALIVE]

    @property
    def down_ports(self) -> List[int]:
        return [p for p, s in self.ports.items() if s.status == PortStatus.DOWN]
