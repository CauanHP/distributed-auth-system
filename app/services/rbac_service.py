"""
Role-Based Access Control (RBAC) Service
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload
import redis.asyncio as redis
import logging

from app.core.config import settings
from app.models.role import Role, Permission, UserRole, RolePermission
from app.models.user import User
from app.schemas.rbac import RoleCreate, PermissionCreate, UserRoleAssign

logger = logging.getLogger(__name__)


class RBACService:
    """Advanced Role-Based Access Control service"""
    
    def __init__(self):
        self.redis_client = None
        self.permission_cache = {}
        self.role_cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    async def initialize(self):
        """Initialize RBAC service"""
        try:
            self.redis_client = redis.from_url(settings.REDIS_URL)
            await self._load_permissions_cache()
            await self._load_roles_cache()
            logger.info("RBAC service initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing RBAC service: {e}")
    
    async def create_role(self, role_data: RoleCreate, db: AsyncSession) -> Role:
        """Create a new role"""
        try:
            # Check if role already exists
            result = await db.execute(select(Role).where(Role.name == role_data.name))
            if result.scalar_one_or_none():
                raise ValueError("Role already exists")
            
            # Create role
            role = Role(
                name=role_data.name,
                description=role_data.description,
                is_active=True,
                created_at=datetime.utcnow()
            )
            
            db.add(role)
            await db.commit()
            await db.refresh(role)
            
            # Update cache
            await self._update_role_cache(role)
            
            # Log role creation
            await self._log_rbac_event("role_created", role.id, {
                "role_name": role.name,
                "description": role.description
            })
            
            return role
        
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creating role: {e}")
            raise
    
    async def create_permission(self, permission_data: PermissionCreate, db: AsyncSession) -> Permission:
        """Create a new permission"""
        try:
            # Check if permission already exists
            result = await db.execute(
                select(Permission).where(
                    and_(
                        Permission.resource == permission_data.resource,
                        Permission.action == permission_data.action
                    )
                )
            )
            if result.scalar_one_or_none():
                raise ValueError("Permission already exists")
            
            # Create permission
            permission = Permission(
                name=permission_data.name,
                resource=permission_data.resource,
                action=permission_data.action,
                description=permission_data.description,
                is_active=True,
                created_at=datetime.utcnow()
            )
            
            db.add(permission)
            await db.commit()
            await db.refresh(permission)
            
            # Update cache
            await self._update_permission_cache(permission)
            
            # Log permission creation
            await self._log_rbac_event("permission_created", permission.id, {
                "permission_name": permission.name,
                "resource": permission.resource,
                "action": permission.action
            })
            
            return permission
        
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creating permission: {e}")
            raise
    
    async def assign_role_to_user(self, user_role_data: UserRoleAssign, db: AsyncSession) -> bool:
        """Assign role to user"""
        try:
            # Check if assignment already exists
            result = await db.execute(
                select(UserRole).where(
                    and_(
                        UserRole.user_id == user_role_data.user_id,
                        UserRole.role_id == user_role_data.role_id
                    )
                )
            )
            if result.scalar_one_or_none():
                raise ValueError("Role already assigned to user")
            
            # Create user role assignment
            user_role = UserRole(
                user_id=user_role_data.user_id,
                role_id=user_role_data.role_id,
                assigned_by=user_role_data.assigned_by,
                assigned_at=datetime.utcnow(),
                expires_at=user_role_data.expires_at
            )
            
            db.add(user_role)
            await db.commit()
            
            # Invalidate user permissions cache
            await self._invalidate_user_permissions_cache(user_role_data.user_id)
            
            # Log role assignment
            await self._log_rbac_event("role_assigned", user_role_data.user_id, {
                "role_id": user_role_data.role_id,
                "assigned_by": user_role_data.assigned_by
            })
            
            return True
        
        except Exception as e:
            await db.rollback()
            logger.error(f"Error assigning role to user: {e}")
            raise
    
    async def remove_role_from_user(self, user_id: str, role_id: str, db: AsyncSession) -> bool:
        """Remove role from user"""
        try:
            # Find user role assignment
            result = await db.execute(
                select(UserRole).where(
                    and_(
                        UserRole.user_id == user_id,
                        UserRole.role_id == role_id
                    )
                )
            )
            user_role = result.scalar_one_or_none()
            
            if not user_role:
                raise ValueError("Role not assigned to user")
            
            # Remove assignment
            await db.delete(user_role)
            await db.commit()
            
            # Invalidate user permissions cache
            await self._invalidate_user_permissions_cache(user_id)
            
            # Log role removal
            await self._log_rbac_event("role_removed", user_id, {
                "role_id": role_id
            })
            
            return True
        
        except Exception as e:
            await db.rollback()
            logger.error(f"Error removing role from user: {e}")
            raise
    
    async def assign_permission_to_role(self, role_id: str, permission_id: str, db: AsyncSession) -> bool:
        """Assign permission to role"""
        try:
            # Check if assignment already exists
            result = await db.execute(
                select(RolePermission).where(
                    and_(
                        RolePermission.role_id == role_id,
                        RolePermission.permission_id == permission_id
                    )
                )
            )
            if result.scalar_one_or_none():
                raise ValueError("Permission already assigned to role")
            
            # Create role permission assignment
            role_permission = RolePermission(
                role_id=role_id,
                permission_id=permission_id,
                assigned_at=datetime.utcnow()
            )
            
            db.add(role_permission)
            await db.commit()
            
            # Invalidate role permissions cache
            await self._invalidate_role_permissions_cache(role_id)
            
            # Log permission assignment
            await self._log_rbac_event("permission_assigned", role_id, {
                "permission_id": permission_id
            })
            
            return True
        
        except Exception as e:
            await db.rollback()
            logger.error(f"Error assigning permission to role: {e}")
            raise
    
    async def remove_permission_from_role(self, role_id: str, permission_id: str, db: AsyncSession) -> bool:
        """Remove permission from role"""
        try:
            # Find role permission assignment
            result = await db.execute(
                select(RolePermission).where(
                    and_(
                        RolePermission.role_id == role_id,
                        RolePermission.permission_id == permission_id
                    )
                )
            )
            role_permission = result.scalar_one_or_none()
            
            if not role_permission:
                raise ValueError("Permission not assigned to role")
            
            # Remove assignment
            await db.delete(role_permission)
            await db.commit()
            
            # Invalidate role permissions cache
            await self._invalidate_role_permissions_cache(role_id)
            
            # Log permission removal
            await self._log_rbac_event("permission_removed", role_id, {
                "permission_id": permission_id
            })
            
            return True
        
        except Exception as e:
            await db.rollback()
            logger.error(f"Error removing permission from role: {e}")
            raise
    
    async def get_user_permissions(self, user_id: str, db: AsyncSession) -> List[Dict[str, Any]]:
        """Get all permissions for a user"""
        try:
            # Try to get from cache first
            cached_permissions = await self._get_user_permissions_from_cache(user_id)
            if cached_permissions:
                return cached_permissions
            
            # Get user roles
            user_roles_result = await db.execute(
                select(UserRole, Role)
                .join(Role, UserRole.role_id == Role.id)
                .where(
                    and_(
                        UserRole.user_id == user_id,
                        Role.is_active == True,
                        or_(
                            UserRole.expires_at.is_(None),
                            UserRole.expires_at > datetime.utcnow()
                        )
                    )
                )
            )
            user_roles = user_roles_result.all()
            
            if not user_roles:
                return []
            
            role_ids = [user_role.Role.id for user_role in user_roles]
            
            # Get permissions for roles
            permissions_result = await db.execute(
                select(Permission, RolePermission)
                .join(RolePermission, Permission.id == RolePermission.permission_id)
                .where(
                    and_(
                        RolePermission.role_id.in_(role_ids),
                        Permission.is_active == True
                    )
                )
            )
            permissions = permissions_result.all()
            
            # Format permissions
            user_permissions = []
            for permission, _ in permissions:
                user_permissions.append({
                    "id": permission.id,
                    "name": permission.name,
                    "resource": permission.resource,
                    "action": permission.action,
                    "description": permission.description
                })
            
            # Cache permissions
            await self._cache_user_permissions(user_id, user_permissions)
            
            return user_permissions
        
        except Exception as e:
            logger.error(f"Error getting user permissions: {e}")
            return []
    
    async def check_permission(self, user_id: str, resource: str, action: str, db: AsyncSession) -> bool:
        """Check if user has specific permission"""
        try:
            # Get user permissions
            permissions = await self.get_user_permissions(user_id, db)
            
            # Check if permission exists
            for permission in permissions:
                if permission["resource"] == resource and permission["action"] == action:
                    return True
            
            return False
        
        except Exception as e:
            logger.error(f"Error checking permission: {e}")
            return False
    
    async def get_user_roles(self, user_id: str, db: AsyncSession) -> List[Dict[str, Any]]:
        """Get all roles for a user"""
        try:
            # Get user roles
            result = await db.execute(
                select(UserRole, Role)
                .join(Role, UserRole.role_id == Role.id)
                .where(
                    and_(
                        UserRole.user_id == user_id,
                        Role.is_active == True,
                        or_(
                            UserRole.expires_at.is_(None),
                            UserRole.expires_at > datetime.utcnow()
                        )
                    )
                )
            )
            user_roles = result.all()
            
            # Format roles
            roles = []
            for user_role, role in user_roles:
                roles.append({
                    "id": role.id,
                    "name": role.name,
                    "description": role.description,
                    "assigned_at": user_role.assigned_at.isoformat(),
                    "expires_at": user_role.expires_at.isoformat() if user_role.expires_at else None
                })
            
            return roles
        
        except Exception as e:
            logger.error(f"Error getting user roles: {e}")
            return []
    
    async def get_role_permissions(self, role_id: str, db: AsyncSession) -> List[Dict[str, Any]]:
        """Get all permissions for a role"""
        try:
            # Try to get from cache first
            cached_permissions = await self._get_role_permissions_from_cache(role_id)
            if cached_permissions:
                return cached_permissions
            
            # Get role permissions
            result = await db.execute(
                select(Permission, RolePermission)
                .join(RolePermission, Permission.id == RolePermission.permission_id)
                .where(
                    and_(
                        RolePermission.role_id == role_id,
                        Permission.is_active == True
                    )
                )
            )
            role_permissions = result.all()
            
            # Format permissions
            permissions = []
            for permission, _ in role_permissions:
                permissions.append({
                    "id": permission.id,
                    "name": permission.name,
                    "resource": permission.resource,
                    "action": permission.action,
                    "description": permission.description
                })
            
            # Cache permissions
            await self._cache_role_permissions(role_id, permissions)
            
            return permissions
        
        except Exception as e:
            logger.error(f"Error getting role permissions: {e}")
            return []
    
    async def get_all_roles(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Get all active roles"""
        try:
            result = await db.execute(select(Role).where(Role.is_active == True))
            roles = result.scalars().all()
            
            # Format roles
            formatted_roles = []
            for role in roles:
                formatted_roles.append({
                    "id": role.id,
                    "name": role.name,
                    "description": role.description,
                    "is_active": role.is_active,
                    "created_at": role.created_at.isoformat()
                })
            
            return formatted_roles
        
        except Exception as e:
            logger.error(f"Error getting all roles: {e}")
            return []
    
    async def get_all_permissions(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Get all active permissions"""
        try:
            result = await db.execute(select(Permission).where(Permission.is_active == True))
            permissions = result.scalars().all()
            
            # Format permissions
            formatted_permissions = []
            for permission in permissions:
                formatted_permissions.append({
                    "id": permission.id,
                    "name": permission.name,
                    "resource": permission.resource,
                    "action": permission.action,
                    "description": permission.description,
                    "is_active": permission.is_active,
                    "created_at": permission.created_at.isoformat()
                })
            
            return formatted_permissions
        
        except Exception as e:
            logger.error(f"Error getting all permissions: {e}")
            return []
    
    async def _load_permissions_cache(self):
        """Load permissions into cache"""
        try:
            if not self.redis_client:
                return
            
            # This would load all permissions from database
            # For now, we'll use an empty cache
            self.permission_cache = {}
        
        except Exception as e:
            logger.error(f"Error loading permissions cache: {e}")
    
    async def _load_roles_cache(self):
        """Load roles into cache"""
        try:
            if not self.redis_client:
                return
            
            # This would load all roles from database
            # For now, we'll use an empty cache
            self.role_cache = {}
        
        except Exception as e:
            logger.error(f"Error loading roles cache: {e}")
    
    async def _update_permission_cache(self, permission: Permission):
        """Update permission in cache"""
        try:
            if not self.redis_client:
                return
            
            permission_data = {
                "id": permission.id,
                "name": permission.name,
                "resource": permission.resource,
                "action": permission.action,
                "description": permission.description
            }
            
            await self.redis_client.setex(
                f"permission:{permission.id}",
                self.cache_ttl,
                json.dumps(permission_data)
            )
        
        except Exception as e:
            logger.error(f"Error updating permission cache: {e}")
    
    async def _update_role_cache(self, role: Role):
        """Update role in cache"""
        try:
            if not self.redis_client:
                return
            
            role_data = {
                "id": role.id,
                "name": role.name,
                "description": role.description
            }
            
            await self.redis_client.setex(
                f"role:{role.id}",
                self.cache_ttl,
                json.dumps(role_data)
            )
        
        except Exception as e:
            logger.error(f"Error updating role cache: {e}")
    
    async def _get_user_permissions_from_cache(self, user_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get user permissions from cache"""
        try:
            if not self.redis_client:
                return None
            
            cached_data = await self.redis_client.get(f"user_permissions:{user_id}")
            if cached_data:
                return json.loads(cached_data)
            
            return None
        
        except Exception as e:
            logger.error(f"Error getting user permissions from cache: {e}")
            return None
    
    async def _cache_user_permissions(self, user_id: str, permissions: List[Dict[str, Any]]):
        """Cache user permissions"""
        try:
            if not self.redis_client:
                return
            
            await self.redis_client.setex(
                f"user_permissions:{user_id}",
                self.cache_ttl,
                json.dumps(permissions)
            )
        
        except Exception as e:
            logger.error(f"Error caching user permissions: {e}")
    
    async def _invalidate_user_permissions_cache(self, user_id: str):
        """Invalidate user permissions cache"""
        try:
            if not self.redis_client:
                return
            
            await self.redis_client.delete(f"user_permissions:{user_id}")
        
        except Exception as e:
            logger.error(f"Error invalidating user permissions cache: {e}")
    
    async def _get_role_permissions_from_cache(self, role_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get role permissions from cache"""
        try:
            if not self.redis_client:
                return None
            
            cached_data = await self.redis_client.get(f"role_permissions:{role_id}")
            if cached_data:
                return json.loads(cached_data)
            
            return None
        
        except Exception as e:
            logger.error(f"Error getting role permissions from cache: {e}")
            return None
    
    async def _cache_role_permissions(self, role_id: str, permissions: List[Dict[str, Any]]):
        """Cache role permissions"""
        try:
            if not self.redis_client:
                return
            
            await self.redis_client.setex(
                f"role_permissions:{role_id}",
                self.cache_ttl,
                json.dumps(permissions)
            )
        
        except Exception as e:
            logger.error(f"Error caching role permissions: {e}")
    
    async def _invalidate_role_permissions_cache(self, role_id: str):
        """Invalidate role permissions cache"""
        try:
            if not self.redis_client:
                return
            
            await self.redis_client.delete(f"role_permissions:{role_id}")
        
        except Exception as e:
            logger.error(f"Error invalidating role permissions cache: {e}")
    
    async def _log_rbac_event(self, event_type: str, entity_id: str, details: Dict[str, Any]):
        """Log RBAC event"""
        try:
            # This would integrate with the audit service
            logger.info(f"RBAC event: {event_type} for entity {entity_id}: {details}")
        except Exception as e:
            logger.error(f"Error logging RBAC event: {e}")

