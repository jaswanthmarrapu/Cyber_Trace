from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class UserRegisterSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: str = Field(..., max_length=100, description="Examiner email address")
    password: str = Field(..., min_length=6, description="Cryptographic account password")
    full_name: Optional[str] = Field("Forensic Examiner", max_length=100)
    role: Optional[str] = Field("Investigator", description="Role: Admin, Investigator, or Viewer")

class UserLoginSchema(BaseModel):
    username: str = Field(..., description="Username or email address")
    password: str = Field(..., description="Account password")

class ForgotPasswordRequestSchema(BaseModel):
    identifier: str = Field(..., description="Registered email address or username")

class ResetPasswordSchema(BaseModel):
    reset_token: str = Field(..., description="Valid 15-minute password reset token")
    new_password: str = Field(..., min_length=6, description="New strong password")

class TokenResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Dict[str, Any]

class UserProfileSchema(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool


