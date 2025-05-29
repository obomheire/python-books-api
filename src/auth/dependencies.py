from typing import Any, List

from fastapi import Depends, Request, status
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from sqlmodel.ext.asyncio.session import AsyncSession

from src.db.main import get_session
from src.db.models import User
from src.db.redis import token_in_blocklist

from .service import UserService
from .utils import decode_token
from src.errors import (
    InvalidToken,
    RefreshTokenRequired,
    AccessTokenRequired,
    InsufficientPermission,
    AccountNotVerified,
)

# Instantiate the user service for DB interactions
user_service = UserService()


# Base TokenBearer class to handle general token authentication logic
class TokenBearer(HTTPBearer):
    def __init__(self, auto_error=True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials | None:
        # Extract token from the request header
        creds = await super().__call__(request)
        token = creds.credentials

        # Decode token to get token data (payload)
        token_data = decode_token(token)

        # Validate token integrity
        if not self.token_valid(token):
            raise InvalidToken()

        # Check if token is blacklisted (e.g. logged out or revoked)
        if await token_in_blocklist(token_data["jti"]):
            raise InvalidToken()

        # Additional validation (implemented in subclasses)
        self.verify_token_data(token_data)

        # Return decoded token data
        return token_data

    def token_valid(self, token: str) -> bool:
        # Decode token and check if token data exists
        token_data = decode_token(token)
        return token_data is not None

    def verify_token_data(self, token_data):
        # Placeholder for token-type-specific checks (must override in subclasses)
        raise NotImplementedError("Please Override this method in child classes")


# Validates that the token is an access token (not refresh)
class AccessTokenBearer(TokenBearer):
    def verify_token_data(self, token_data: dict) -> None:
        if token_data and token_data["refresh"]:
            raise AccessTokenRequired()


# Validates that the token is a refresh token (not access)
class RefreshTokenBearer(TokenBearer):
    def verify_token_data(self, token_data: dict) -> None:
        if token_data and not token_data["refresh"]:
            raise RefreshTokenRequired()


# Dependency to get the current authenticated user from the token
async def get_current_user(
    token_details: dict = Depends(AccessTokenBearer()),
    session: AsyncSession = Depends(get_session),
):
    # Extract user's email from token payload
    user_email = token_details["user"]["email"]

    # Query the database for the user
    user = await user_service.get_user_by_email(user_email, session)

    return user


# Role-based access control dependency
class RoleChecker:
    def __init__(self, allowed_roles: List[str]) -> None:
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: User = Depends(get_current_user)) -> Any:
        # Ensure the user's email is verified
        if not current_user.is_verified:
            raise AccountNotVerified()

        # Check if the user's role is allowed
        if current_user.role in self.allowed_roles:
            return True

        # Raise an error if role is not permitted
        raise InsufficientPermission()
