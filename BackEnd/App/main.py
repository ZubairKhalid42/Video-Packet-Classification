# Fast Api application 
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from App.api import router

app = FastAPI(
    title="Packet Classification API",
    description="API for classifying network packets as video or non-video traffic",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(router, prefix="/api/v1")

@app.get("/")
async def root():
    return {
        "message": "Packet Classification API",
        "docs": "/docs",
        "health": "/api/v1/health"
    }