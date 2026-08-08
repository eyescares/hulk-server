from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List, Optional


class Settings(BaseSettings):
    host: str = Field(default="0.0.0.0", description="API bind address")
    api_port: int = Field(default=7777, description="API port")
    default_threads: int = Field(default=2000, description="Concurrent coroutines per attack")
    max_threads: int = Field(default=10000, description="Hard cap on coroutines")
    request_timeout: int = Field(default=5, description="Per-request timeout in seconds")
    proxy_timeout: int = Field(default=2, description="Proxy connection timeout in seconds")
    proxy_file: Optional[str] = Field(default=None, description="Path to proxy list file (one per line, protocol://host:port)")
    proxy_rotate: bool = Field(default=True, description="Rotate proxies between requests")

    model_config = {"env_prefix": "HULK_"}


settings = Settings()
