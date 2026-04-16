from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class RetrievedDocument(BaseModel):
    score: float = Field(..., ge=0.0, le=1.0)
    text: str = Field(..., min_length=1)
    metadata: Optional[Dict[str, Any]] = Field(default=None)