"""
Advanced Authentication Service
"""

import asyncio
import hashlib
import secrets
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
import redis.asyncio as redis
import logging

from app.core.config import settings
from app.models.user import User, UserSession, LoginAttempt
from app.models.role import Role, Permission, UserRole
from app.schemas.auth import UserCreate, UserLogin, TokenResponse, UserResponse
from app.core.security import create_access_token, create_refresh_token, verify_password, get_password_hash

logger = logging.getLogger(__name__)


class AuthService:
    """Advanced authentication service with multiple security features"""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.redis_client = None
        self.login_attempts = {}
        self.max_login_attempts = 5
        self.lockout_duration = 300  # 5 minutes
        self.session_timeout = 3600  # 1 hour
        self.refresh_token_timeout = 86400 * 7  # 7 days
    
    async def initialize(self):
        """Initialize authentication service"""
        try:
            self.redis_client = redis.from_url(settings.REDIS_URL)
            logger.info("Authentication service initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing authentication service: {e}")
    
    async def register_user(self, user_data: UserCreate, db: AsyncSession) -> UserResponse:
        """Register a new user"""
        try:
            # Check if user already exists
            result = await db.execute(select(User).where(User.email == user_data.email))
            if result.scalar_one_or_none():
                raise ValueError("Email already registered")
            
            result = await db.execute(select(User).where(User.username == user_data.username))
            if result.scalar_one_or_none():
                raise ValueError("Username already taken")
            
            # Hash password
            hashed_password = get_password_hash(user_data.password)
            
            # Generate MFA secret
            mfa_secret = pyotp.random_base32()
            
            # Create user
            db_user = User(
                email=user_data.email,
                username=user_data.username,
                hashed_password=hashed_password,
                full_name=user_data.full_name,
                is_active=True,
                mfa_secret=mfa_secret,
                mfa_enabled=False,
                created_at=datetime.utcnow()
            )
            
            db.add(db_user)
            await db.commit()
            await db.refresh(db_user)
            
            # Assign default role
            await self._assign_default_role(db_user.id, db)
            
            # Log registration
            await self._log_auth_event("user_registration", db_user.id, {
                "email": user_data.email,
                "username": user_data.username
            })
            
            return UserResponse.from_orm(db_user)
        
        except Exception as e:
            await db.rollback()
            logger.error(f"Error registering user: {e}")
            raise
    
    async def authenticate_user(self, login_data: UserLogin, db: AsyncSession, request_info: Dict[str, Any]) -> TokenResponse:
        """Authenticate user with login credentials"""
        try:
            # Check rate limiting
            client_ip = request_info.get("client_ip", "unknown")
            if not await self._check_rate_limit(client_ip):
                raise ValueError("Too many login attempts. Please try again later.")
            
            # Find user
            result = await db.execute(select(User).where(User.email == login_data.email))
            user = result.scalar_one_or_none()
            
            if not user:
                await self._record_failed_login(client_ip, login_data.email)
                raise ValueError("Invalid credentials")
            
            # Check if user is active
            if not user.is_active:
                raise ValueError("Account is deactivated")
            
            # Check if account is locked
            if await self._is_account_locked(user.id):
                raise ValueError("Account is temporarily locked due to multiple failed attempts")
            
            # Verify password
            if not verify_password(login_data.password, user.hashed_password):
                await self._record_failed_login(client_ip, login_data.email, user.id)
                raise ValueError("Invalid credentials")
            
            # Check MFA if enabled
            if user.mfa_enabled:
                if not login_data.mfa_code:
                    raise ValueError("MFA code required")
                
                if not await self._verify_mfa_code(user.mfa_secret, login_data.mfa_code):
                    await self._record_failed_login(client_ip, login_data.email, user.id)
                    raise ValueError("Invalid MFA code")
            
            # Generate tokens
            access_token = create_access_token(data={"sub": user.username})
            refresh_token = create_refresh_token(data={"sub": user.username})
            
            # Create session
            session_id = await self._create_session(user.id, request_info, db)
            
            # Update last login
            await db.execute(
                update(User)
                .where(User.id == user.id)
                .values(last_login=datetime.utcnow())
            )
            await db.commit()
            
            # Log successful login
            await self._log_auth_event("user_login", user.id, {
                "email": user.email,
                "session_id": session_id,
                "client_ip": client_ip
            })
            
            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                user=UserResponse.from_orm(user)
            )
        
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
            raise
    
    async def refresh_token(self, refresh_token: str, db: AsyncSession) -> TokenResponse:
        """Refresh access token using refresh token"""
        try:
            # Verify refresh token
            payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username = payload.get("sub")
            
            if not username:
                raise ValueError("Invalid refresh token")
            
            # Find user
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            
            if not user or not user.is_active:
                raise ValueError("User not found or inactive")
            
            # Generate new access token
            access_token = create_access_token(data={"sub": user.username})
            
            # Log token refresh
            await self._log_auth_event("token_refresh", user.id, {
                "username": username
            })
            
            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                user=UserResponse.from_orm(user)
            )
        
        except jwt.ExpiredSignatureError:
            raise ValueError("Refresh token expired")
        except jwt.JWTError:
            raise ValueError("Invalid refresh token")
        except Exception as e:
            logger.error(f"Error refreshing token: {e}")
            raise
    
    async def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate JWT token and return user info"""
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username = payload.get("sub")
            
            if not username:
                raise ValueError("Invalid token")
            
            # Check if token is blacklisted
            if await self._is_token_blacklisted(token):
                raise ValueError("Token is blacklisted")
            
            # Get user info from cache or database
            user_info = await self._get_user_info(username)
            
            return user_info
        
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expired")
        except jwt.JWTError:
            raise ValueError("Invalid token")
        except Exception as e:
            logger.error(f"Error validating token: {e}")
            raise
    
    async def logout(self, token: str, db: AsyncSession) -> bool:
        """Logout user and invalidate tokens"""
        try:
            # Decode token to get user info
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username = payload.get("sub")
            
            if not username:
                return False
            
            # Find user
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            
            if not user:
                return False
            
            # Blacklist token
            await self._blacklist_token(token)
            
            # Revoke all user sessions
            await self._revoke_user_sessions(user.id, db)
            
            # Log logout
            await self._log_auth_event("user_logout", user.id, {
                "username": username
            })
            
            return True
        
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return False
    
    async def change_password(self, user_id: str, old_password: str, new_password: str, db: AsyncSession) -> bool:
        """Change user password"""
        try:
            # Find user
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            
            if not user:
                raise ValueError("User not found")
            
            # Verify old password
            if not verify_password(old_password, user.hashed_password):
                raise ValueError("Invalid old password")
            
            # Hash new password
            hashed_password = get_password_hash(new_password)
            
            # Update password
            await db.execute(
                update(User)
                .where(User.id == user_id)
                .values(
                    hashed_password=hashed_password,
                    password_changed_at=datetime.utcnow()
                )
            )
            await db.commit()
            
            # Log password change
            await self._log_auth_event("password_change", user_id, {
                "user_id": user_id
            })
            
            return True
        
        except Exception as e:
            await db.rollback()
            logger.error(f"Error changing password: {e}")
            raise
    
    async def reset_password(self, email: str, db: AsyncSession) -> bool:
        """Initiate password reset process"""
        try:
            # Find user
            result = await db.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()
            
            if not user:
                # Don't reveal if email exists
                return True
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            reset_token_expires = datetime.utcnow() + timedelta(hours=1)
            
            # Store reset token in Redis
            if self.redis_client:
                await self.redis_client.setex(
                    f"password_reset:{reset_token}",
                    3600,  # 1 hour
                    json.dumps({
                        "user_id": user.id,
                        "email": email,
                        "expires_at": reset_token_expires.isoformat()
                    })
                )
            
            # TODO: Send reset email
            # await self._send_password_reset_email(email, reset_token)
            
            # Log password reset request
            await self._log_auth_event("password_reset_request", user.id, {
                "email": email
            })
            
            return True
        
        except Exception as e:
            logger.error(f"Error initiating password reset: {e}")
            raise
    
    async def confirm_password_reset(self, reset_token: str, new_password: str, db: AsyncSession) -> bool:
        """Confirm password reset with token"""
        try:
            # Get reset token from Redis
            if not self.redis_client:
                raise ValueError("Redis not available")
            
            token_data = await self.redis_client.get(f"password_reset:{reset_token}")
            if not token_data:
                raise ValueError("Invalid or expired reset token")
            
            token_info = json.loads(token_data)
            user_id = token_info["user_id"]
            
            # Hash new password
            hashed_password = get_password_hash(new_password)
            
            # Update password
            await db.execute(
                update(User)
                .where(User.id == user_id)
                .values(
                    hashed_password=hashed_password,
                    password_changed_at=datetime.utcnow()
                )
            )
            await db.commit()
            
            # Remove reset token
            await self.redis_client.delete(f"password_reset:{reset_token}")
            
            # Log password reset
            await self._log_auth_event("password_reset", user_id, {
                "user_id": user_id
            })
            
            return True
        
        except Exception as e:
            await db.rollback()
            logger.error(f"Error confirming password reset: {e}")
            raise
    
    async def _check_rate_limit(self, client_ip: str) -> bool:
        """Check if client is rate limited"""
        try:
            if not self.redis_client:
                return True
            
            key = f"rate_limit:{client_ip}"
            current_attempts = await self.redis_client.get(key)
            
            if current_attempts and int(current_attempts) >= self.max_login_attempts:
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return True
    
    async def _record_failed_login(self, client_ip: str, email: str, user_id: Optional[str] = None):
        """Record failed login attempt"""
        try:
            if not self.redis_client:
                return
            
            # Increment rate limit counter
            key = f"rate_limit:{client_ip}"
            await self.redis_client.incr(key)
            await self.redis_client.expire(key, self.lockout_duration)
            
            # Record failed attempt
            attempt_key = f"failed_login:{client_ip}:{email}"
            await self.redis_client.incr(attempt_key)
            await self.redis_client.expire(attempt_key, self.lockout_duration)
            
            # If user_id provided, record user-specific failed attempt
            if user_id:
                user_attempt_key = f"failed_login_user:{user_id}"
                await self.redis_client.incr(user_attempt_key)
                await self.redis_client.expire(user_attempt_key, self.lockout_duration)
        
        except Exception as e:
            logger.error(f"Error recording failed login: {e}")
    
    async def _is_account_locked(self, user_id: str) -> bool:
        """Check if user account is locked"""
        try:
            if not self.redis_client:
                return False
            
            key = f"failed_login_user:{user_id}"
            attempts = await self.redis_client.get(key)
            
            return attempts and int(attempts) >= self.max_login_attempts
        
        except Exception as e:
            logger.error(f"Error checking account lock: {e}")
            return False
    
    async def _create_session(self, user_id: str, request_info: Dict[str, Any], db: AsyncSession) -> str:
        """Create user session"""
        try:
            session_id = secrets.token_urlsafe(32)
            
            # Create session in database
            session = UserSession(
                id=session_id,
                user_id=user_id,
                client_ip=request_info.get("client_ip", "unknown"),
                user_agent=request_info.get("user_agent", "unknown"),
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(seconds=self.session_timeout)
            )
            
            db.add(session)
            await db.commit()
            
            # Store session in Redis for fast access
            if self.redis_client:
                session_data = {
                    "user_id": user_id,
                    "client_ip": request_info.get("client_ip", "unknown"),
                    "user_agent": request_info.get("user_agent", "unknown"),
                    "created_at": session.created_at.isoformat(),
                    "expires_at": session.expires_at.isoformat()
                }
                await self.redis_client.setex(
                    f"session:{session_id}",
                    self.session_timeout,
                    json.dumps(session_data)
                )
            
            return session_id
        
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            raise
    
    async def _blacklist_token(self, token: str):
        """Add token to blacklist"""
        try:
            if not self.redis_client:
                return
            
            # Decode token to get expiration
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            exp = payload.get("exp")
            
            if exp:
                # Calculate TTL
                ttl = exp - datetime.utcnow().timestamp()
                if ttl > 0:
                    await self.redis_client.setex(f"blacklist:{token}", int(ttl), "1")
        
        except Exception as e:
            logger.error(f"Error blacklisting token: {e}")
    
    async def _is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        try:
            if not self.redis_client:
                return False
            
            result = await self.redis_client.get(f"blacklist:{token}")
            return result is not None
        
        except Exception as e:
            logger.error(f"Error checking token blacklist: {e}")
            return False
    
    async def _get_user_info(self, username: str) -> Dict[str, Any]:
        """Get user info from cache or database"""
        try:
            # Try to get from cache first
            if self.redis_client:
                cached_user = await self.redis_client.get(f"user_info:{username}")
                if cached_user:
                    return json.loads(cached_user)
            
            # Get from database
            # This would require a database session, but for now return basic info
            return {
                "username": username,
                "cached": False
            }
        
        except Exception as e:
            logger.error(f"Error getting user info: {e}")
            return {"username": username, "cached": False}
    
    async def _revoke_user_sessions(self, user_id: str, db: AsyncSession):
        """Revoke all user sessions"""
        try:
            # Update sessions in database
            await db.execute(
                update(UserSession)
                .where(UserSession.user_id == user_id)
                .values(revoked=True, revoked_at=datetime.utcnow())
            )
            await db.commit()
            
            # Remove from Redis
            if self.redis_client:
                # Get all session keys for user
                pattern = f"session:*"
                keys = await self.redis_client.keys(pattern)
                
                for key in keys:
                    session_data = await self.redis_client.get(key)
                    if session_data:
                        data = json.loads(session_data)
                        if data.get("user_id") == user_id:
                            await self.redis_client.delete(key)
        
        except Exception as e:
            logger.error(f"Error revoking user sessions: {e}")
    
    async def _assign_default_role(self, user_id: str, db: AsyncSession):
        """Assign default role to new user"""
        try:
            # Get default role
            result = await db.execute(select(Role).where(Role.name == "user"))
            default_role = result.scalar_one_or_none()
            
            if default_role:
                user_role = UserRole(user_id=user_id, role_id=default_role.id)
                db.add(user_role)
                await db.commit()
        
        except Exception as e:
            logger.error(f"Error assigning default role: {e}")
    
    async def _verify_mfa_code(self, mfa_secret: str, mfa_code: str) -> bool:
        """Verify MFA code"""
        try:
            totp = pyotp.TOTP(mfa_secret)
            return totp.verify(mfa_code, valid_window=1)
        except Exception as e:
            logger.error(f"Error verifying MFA code: {e}")
            return False
    
    async def _log_auth_event(self, event_type: str, user_id: str, details: Dict[str, Any]):
        """Log authentication event"""
        try:
            # This would integrate with the audit service
            logger.info(f"Auth event: {event_type} for user {user_id}: {details}")
        except Exception as e:
            logger.error(f"Error logging auth event: {e}")
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get authentication service statistics"""
        try:
            stats = {
                "active_sessions": 0,
                "failed_attempts": 0,
                "locked_accounts": 0
            }
            
            if self.redis_client:
                # Count active sessions
                session_keys = await self.redis_client.keys("session:*")
                stats["active_sessions"] = len(session_keys)
                
                # Count failed attempts
                failed_keys = await self.redis_client.keys("failed_login:*")
                stats["failed_attempts"] = len(failed_keys)
                
                # Count locked accounts
                locked_keys = await self.redis_client.keys("failed_login_user:*")
                stats["locked_accounts"] = len(locked_keys)
            
            return stats
        
        except Exception as e:
            logger.error(f"Error getting auth stats: {e}")
            return {}

