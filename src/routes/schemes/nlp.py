from pydantic import BaseModel
from typing import Optional

class PushRequest(BaseModel):
    do_reset: Optional[int] = 0
    file_id: str  # Made required for safety

class SearchRequest(BaseModel):
    text: str
    limit: Optional[int] = 20