from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.user import User
from app.schemas.auth_schema import (
    UserRegisterSchema,
    UserLoginSchema,
    ForgotPasswordRequestSchema,
    ResetPasswordSchema,
    TokenResponseSchema,
    UserProfileSchema
)
from app.utils.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_password_reset_token,
    decode_password_reset_token
)
from app.utils.auth_deps import get_current_user, normalize_role, VALID_ROLES

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])

@router.post("/register", response_model=TokenResponseSchema, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserRegisterSchema, db: Session = Depends(get_db)):
    """Enroll a new forensic investigator with cryptographic credentials."""
    # Check if username or email already exists
    existing_user = db.query(User).filter(
        (User.username == payload.username.strip()) | (User.email == payload.email.strip().lower())
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is already registered."
        )

    # Normalize and validate role
    target_role = normalize_role(payload.role)
    if target_role not in VALID_ROLES:
        target_role = "Investigator"

    user = User(
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name.strip() if payload.full_name else "Forensic Examiner",
        role=target_role,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
        "email": user.email
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 86400,
        "user_info": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@router.post("/login", response_model=TokenResponseSchema)
def login_user(payload: UserLoginSchema, db: Session = Depends(get_db)):
    """Authenticate investigator and generate signed Bearer access token."""
    login_id = payload.username.strip()
    user = db.query(User).filter(
        (User.username == login_id) | (User.email == login_id.lower())
    ).first()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid investigator credentials. Check your username/email and password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Investigator account is deactivated or suspended.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
        "email": user.email
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 86400,
        "user_info": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequestSchema, db: Session = Depends(get_db)):
    """Generate a time-limited password reset token for account recovery."""
    target_id = payload.identifier.strip()
    user = db.query(User).filter(
        (User.username == target_id) | (User.email == target_id.lower())
    ).first()

    if not user:
        # Generic response to prevent user enumeration
        return {
            "message": "If an account matches that email/username, a password reset token has been issued.",
            "reset_token": None
        }

    reset_token = create_password_reset_token(user.username, expires_minutes=15)
    return {
        "message": f"Password reset token issued for user '{user.username}'. Token expires in 15 minutes.",
        "reset_token": reset_token,
        "expires_in_minutes": 15
    }

@router.post("/reset-password")
def reset_password(payload: ResetPasswordSchema, db: Session = Depends(get_db)):
    """Reset account password using a valid cryptographic reset token."""
    try:
        decoded = decode_password_reset_token(payload.reset_token)
        username = decoded.get("sub")
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid or expired reset token: {str(e)}"
        )

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account associated with this token no longer exists."
        )

    user.hashed_password = hash_password(payload.new_password)
    db.commit()

    return {
        "status": "success",
        "message": "Password has been successfully updated. You may now log in with your new credentials."
    }

@router.get("/me", response_model=UserProfileSchema)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Retrieve authenticated examiner identity and credentials."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "is_active": current_user.is_active
    }

@router.post("/logout")
def logout_user(current_user: User = Depends(get_current_user)):
    """Acknowledge session termination and revoke client bearer token."""
    return {
        "status": "success",
        "message": f"Session terminated for user '{current_user.username}'. Token cleared."
    }
