"""
Distributed Authentication and Authorization System
Features: JWT, OAuth2, RBAC, MFA, SSO, Session Management, Rate Limiting
"""

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import asyncio
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import redis.asyncio as redis

from app.core.config import settings
from app.core.database import get_db
from app.core.redis_client import get_redis
from app.core.rate_limiter import RateLimiter
from app.core.session_manager import SessionManager
from app.services.auth_service import AuthService
from app.services.oauth_service import OAuthService
from app.services.rbac_service import RBACService
from app.services.mfa_service import MFAService
from app.services.audit_service import AuditService
from app.api.v1.api import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    app.state.redis = await get_redis()
    app.state.rate_limiter = RateLimiter()
    app.state.session_manager = SessionManager()
    app.state.auth_service = AuthService()
    app.state.oauth_service = OAuthService()
    app.state.rbac_service = RBACService()
    app.state.mfa_service = MFAService()
    app.state.audit_service = AuditService()
    
    # Initialize services
    await app.state.auth_service.initialize()
    await app.state.oauth_service.initialize()
    await app.state.rbac_service.initialize()
    await app.state.mfa_service.initialize()
    await app.state.audit_service.initialize()
    
    # Start background tasks
    asyncio.create_task(app.state.session_manager.cleanup_expired_sessions())
    asyncio.create_task(app.state.audit_service.process_audit_logs())
    
    yield
    
    # Shutdown
    await app.state.redis.close()


app = FastAPI(
    title="Distributed Authentication and Authorization System",
    description="A comprehensive authentication and authorization system with JWT, OAuth2, RBAC, MFA, and SSO capabilities",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware"""
    rate_limiter = app.state.rate_limiter
    
    # Get client IP
    client_ip = request.client.host
    
    # Check rate limit
    if not await rate_limiter.is_allowed(client_ip, request.url.path):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    
    response = await call_next(request)
    return response

# Audit logging middleware
@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """Audit logging middleware"""
    audit_service = app.state.audit_service
    
    # Log request
    await audit_service.log_request(request)
    
    response = await call_next(request)
    
    # Log response
    await audit_service.log_response(request, response)
    
    return response

# Include API router
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
async def root():
    return {
        "message": "Distributed Authentication and Authorization System",
        "version": "1.0.0",
        "features": [
            "JWT Authentication",
            "OAuth2 Authorization",
            "Role-Based Access Control (RBAC)",
            "Multi-Factor Authentication (MFA)",
            "Single Sign-On (SSO)",
            "Session Management",
            "Rate Limiting",
            "Audit Logging"
        ]
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "redis": "connected",
            "auth_service": "ready",
            "oauth_service": "ready",
            "rbac_service": "ready",
            "mfa_service": "ready",
            "audit_service": "ready"
        }
    }


@app.get("/metrics")
async def get_metrics():
    """Get system metrics"""
    metrics = {
        "active_sessions": await app.state.session_manager.get_active_session_count(),
        "rate_limit_stats": await app.state.rate_limiter.get_stats(),
        "auth_stats": await app.state.auth_service.get_stats(),
        "audit_stats": await app.state.audit_service.get_stats()
    }
    return metrics


@app.post("/auth/validate-token")
async def validate_token(token: str = Depends(HTTPBearer())):
    """Validate JWT token"""
    try:
        auth_service = app.state.auth_service
        user = await auth_service.validate_token(token.credentials)
        return {
            "valid": True,
            "user": user,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )


@app.get("/auth/user-permissions/{user_id}")
async def get_user_permissions(user_id: str):
    """Get user permissions"""
    try:
        rbac_service = app.state.rbac_service
        permissions = await rbac_service.get_user_permissions(user_id)
        return {
            "user_id": user_id,
            "permissions": permissions,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {str(e)}"
        )


@app.get("/auth/session-info/{session_id}")
async def get_session_info(session_id: str):
    """Get session information"""
    try:
        session_manager = app.state.session_manager
        session_info = await session_manager.get_session(session_id)
        if not session_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        return session_info
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session not found: {str(e)}"
        )


@app.post("/auth/revoke-session/{session_id}")
async def revoke_session(session_id: str):
    """Revoke a session"""
    try:
        session_manager = app.state.session_manager
        success = await session_manager.revoke_session(session_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        return {"message": "Session revoked successfully", "session_id": session_id}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error revoking session: {str(e)}"
        )


@app.get("/oauth/providers")
async def get_oauth_providers():
    """Get available OAuth providers"""
    oauth_service = app.state.oauth_service
    providers = await oauth_service.get_available_providers()
    return {
        "providers": providers,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/audit/logs")
async def get_audit_logs(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100
):
    """Get audit logs"""
    try:
        audit_service = app.state.audit_service
        logs = await audit_service.get_logs(
            user_id=user_id,
            action=action,
            start_date=start_date,
            end_date=end_date,
            limit=limit
        )
        return {
            "logs": logs,
            "count": len(logs),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving audit logs: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )

