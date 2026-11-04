"""Public, passive search API. No accounts, login, or administrative routes."""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / '.env')

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from app.api.schemas import UnifiedEnrichmentRequest
from app.services import unified
from app.services.registry import provider_status

app=FastAPI(title="Unified Threat Intelligence API",docs_url="/api/docs",redoc_url=None)
app.add_middleware(TrustedHostMiddleware,allowed_hosts=[v.strip() for v in os.getenv('ALLOWED_HOSTS','localhost,127.0.0.1').split(',') if v.strip()])
app.add_middleware(CORSMiddleware,allow_origins=[v.strip() for v in os.getenv('CORS_ALLOWED_ORIGINS','http://localhost:3005').split(',') if v.strip()],allow_methods=['GET','POST'],allow_headers=['Content-Type'])

@app.middleware('http')
async def headers(request,call_next):
    response=await call_next(request)
    response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store'})
    return response

@app.get('/api/health')
def health():
    return {'status':'ok','service':'Unified Threat Intelligence API'}

@app.get('/api/providers/status')
def providers():
    return provider_status()

@app.post('/api/enrichment/unified')
async def search(data:UnifiedEnrichmentRequest):
    return await unified.enrich_indicator_all(data.indicator)
