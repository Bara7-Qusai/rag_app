from pydantic import BaseModel
from typing import Optional

class ProcessRequest(BaseModel):
    file_id: str = None
    chunk_size: Optional[int] = 1000
    overlap_size: Optional[int] = 200
    do_reset: Optional[int] = 0