from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.user import User
from app.utils.security import decode_access_token

security_scheme = HTTPBearer(auto_error=False)

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Validate Bearer JWT token and return active user. Falls back to default system investigator if no token provided."""
    if not credentials:
        # Default mock / development examiner user to allow testing both authenticated and unauthenticated
        default_user = db.query(User).filter(User.username == "admin_examiner").first()
        if not default_user:
            default_user = User(
                username="admin_examiner",
                email="examiner@cybertrace.local",
                hashed_password="disabled_dev_mode",
                full_name="Senior Forensic Examiner",
                role="Lead Examiner",
                is_active=True
            )
        return default_user

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User inactive or not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def require_admin_role(current_user: User = Depends(get_current_user)) -> User:
    """Enforce Administrator / Lead Examiner privileges."""
    if current_user.role not in ["Admin", "Lead Examiner"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires Lead Examiner or Admin role"
        )
    return current_user

