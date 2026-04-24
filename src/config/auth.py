"""
Identity and Access Management Configuration
Abstract interface for Identity Providers to allow seamless migration from local auth to Keycloak.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
import os

# Configuration for local JWT (should be moved to .env in production)
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-key-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class User:
    """Standardized User model across identity providers."""
    def __init__(self, user_id: str, username: str, roles: list[str]):
        self.user_id = user_id
        self.username = username
        self.roles = roles

    def has_role(self, role: str) -> bool:
        return role in self.roles


class IdentityProvider(ABC):
    """Abstract interface for authentication and authorization."""
    
    @abstractmethod
    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[User]:
        """Authenticate user and return User object if successful."""
        pass
        
    @abstractmethod
    async def authorize(self, user: User, resource: str, action: str) -> bool:
        """Check if user is authorized to perform action on resource."""
        pass
        
    @abstractmethod
    def create_access_token(self, user: User) -> str:
        """Generate an access token for the user."""
        pass


class LocalIdentityProvider(IdentityProvider):
    """Simple JWT-based auth for development, testing, and graduation demo."""
    
    def __init__(self, db_pool):
        self.db = db_pool

    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[User]:
        username = credentials.get("username")
        api_key = credentials.get("api_key")
        
        # In a real local provider, we'd check password hashes.
        # For our dashboard, it uses api_key_hash.
        async with self.db.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, username, role 
                FROM users 
                WHERE username = $1 AND api_key_hash = crypt($2, api_key_hash) AND active = TRUE
                """,
                username, api_key
            )
            
            if row:
                return User(
                    user_id=str(row['id']),
                    username=row['username'],
                    roles=[row['role']]
                )
        return None

    async def authorize(self, user: User, resource: str, action: str) -> bool:
        # Simplified RBAC: Admin can do anything, Analyst can view and submit.
        if user.has_role("admin"):
            return True
        if user.has_role("analyst") and action in ["read", "submit"]:
            return True
        return False

    def create_access_token(self, user: User) -> str:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode = {
            "sub": user.username,
            "id": user.user_id,
            "roles": user.roles,
            "exp": expire
        }
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt


class KeycloakIdentityProvider(IdentityProvider):
    """Production-ready OIDC integration for future deployment."""
    
    def __init__(self, keycloak_url: str, realm: str, client_id: str):
        self.keycloak_url = keycloak_url
        self.realm = realm
        self.client_id = client_id
        # Client secret, certs, etc. would be initialized here

    async def authenticate(self, credentials: Dict[str, Any]) -> Optional[User]:
        raise NotImplementedError("Keycloak integration planned for post-graduation phase.")

    async def authorize(self, user: User, resource: str, action: str) -> bool:
        raise NotImplementedError("Keycloak integration planned for post-graduation phase.")
        
    def create_access_token(self, user: User) -> str:
        raise NotImplementedError("Keycloak issues its own tokens.")

