"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional

class User(BaseModel):
    """Users collection schema (collection name: user)"""
    email: EmailStr = Field(..., description="User email (unique)")
    password_hash: str = Field(..., description="BCrypt hashed password")
    name: Optional[str] = Field(None, description="Full name")
    avatar_url: Optional[str] = Field(None, description="Avatar URL")
    is_active: bool = Field(True, description="Is the account active?")
