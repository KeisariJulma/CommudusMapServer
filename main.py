from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List
import uvicorn
import time
import asyncio
from pathlib import Path

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UserLocation(BaseModel):
    user_id: str
    username: str
    lat: float
    lon: float
    last_seen: float = 0.0


user_store: Dict[str, UserLocation] = {}


@app.on_event("startup")
async def startup_event():
    async def cleanup_inactive_users():
        while True:
            await asyncio.sleep(10)
            now = time.time()
            to_remove = [uid for uid, loc in user_store.items() if now - loc.last_seen > 30]
            for uid in to_remove:
                del user_store[uid]
    
    asyncio.create_task(cleanup_inactive_users())


@app.post("/update-location")
async def update_location(location: UserLocation):
    location.last_seen = time.time()
    user_store[location.user_id] = location
    print(f"📍 Location update: {location.username} ({location.user_id}) -> {location.lat}, {location.lon}")
    return {"status": "ok"}


@app.get("/users", response_model=List[UserLocation])
async def get_users():
    return list(user_store.values())


@app.get("/", response_class=HTMLResponse)
async def read_root():
    return Path("src/map.html").read_text()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)