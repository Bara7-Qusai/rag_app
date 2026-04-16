from .BaseController import BaseController
from .ProjectController import ProjectController
import os
from langchain_community.document_loaders import TextLoader
from langchain_community.document_loaders import PyMuPDFLoader
from langchain_community.document_loaders import JSONLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from models import ProcessingEnum
from collections import defaultdict
import re
from helpers.json_processor import process_json_file
from langchain.schema import Document

class ProcessController(BaseController):

    def __init__(self, project_id: str):
        super().__init__()

        self.project_id = project_id
        self.project_path = ProjectController().get_project_path(project_id=project_id)
 
    def get_file_extension(self, file_id: str):
        return os.path.splitext(file_id)[-1]

 
    def get_file_loader(self, file_id: str):

        file_ext = self.get_file_extension(file_id=file_id)
        file_path = os.path.join(
            self.project_path,
            file_id
        )

        if not os.path.exists(file_path):
            return None

        if file_ext == ProcessingEnum.TXT.value:
            return TextLoader(file_path, encoding="utf-8")

        if file_ext == ProcessingEnum.PDF.value:
            return PyMuPDFLoader(file_path)
        
        if file_ext == ProcessingEnum.JSON.value:
               return  None 
        return None       
        
    

    def get_file_content(self, file_id: str):

        file_ext = self.get_file_extension(file_id=file_id)

        # JSON يحتاج file_path مباشرة — مش loader
        if file_ext == ProcessingEnum.JSON.value:
            file_path = os.path.join(self.project_path, file_id)
            if os.path.exists(file_path):
                return file_path  # نرجع الـ path
            return None

        # TXT و PDF — الطريقة الأصلية
        loader = self.get_file_loader(file_id=file_id)
        if loader:
            try:
                return loader.load()
            except Exception as e:
                print(f"Error loading file {file_id}: {e}")
                return None

        return None
    
    def merge_alerts(self, file_content: list):
        """
        This function is designed to merge the content of alerts that share the same ID.
        """
        merged_alerts = defaultdict(list)

        for rec in file_content:
            alert_id = rec.metadata.get("id")
            if not alert_id:
                
                match = re.search(r'"id"\s*:\s*"([^"]+)"', rec.page_content)
                if match:
                    alert_id = match.group(1)
                else:
                    alert_id = "unknown_alert" #

            merged_alerts[alert_id].append(rec.page_content)

        merged_documents = []
        for alert_id, contents in merged_alerts.items():
            full_content = "\n".join(contents)
            merged_documents.append(
                {
                    "page_content": full_content,
                    "metadata": {"id": alert_id}
                }
            )
        return merged_documents

    def process_file_content(self, file_content: list, file_id: str,
                             chunk_size: int=500, overlap_size: int=100):


        file_ext = self.get_file_extension(file_id=file_id) 
        if file_ext == ProcessingEnum.JSON.value:
            file_path = os.path.join(self.project_path, file_id)
            json_chunks = process_json_file(file_path)

            # حوّل النتيجة لـ LangChain Document عشان تتوافق مع باقي الكود
            return [
                Document(
                    page_content=chunk["text"],
                    metadata=chunk["metadata"]
                )
                for chunk in json_chunks
            ] 

        merged_content = self.merge_alerts(file_content)

        # Event-aware chunking preserves log boundaries and improves retrieval relevance.
        chunks = self._chunk_text_events(merged_content, chunk_size=chunk_size, overlap_size=overlap_size)
        return chunks

    def _chunk_text_events(self, merged_content: list, chunk_size: int, overlap_size: int) -> list:
        """Chunk logs by event boundaries rather than arbitrary character windows."""
        documents = []
        for rec in merged_content:
            lines = [line.strip() for line in rec["page_content"].splitlines() if line.strip()]
            if not lines:
                continue

            current_lines = []
            current_length = 0
            for line in lines:
                if current_lines and current_length + len(line) + 1 > chunk_size:
                    documents.append(
                        Document(page_content="\n".join(current_lines), metadata=rec["metadata"])
                    )
                    # retain the last overlap_size characters as context for the next chunk
                    overlap_lines = []
                    overlap_length = 0
                    for prev_line in reversed(current_lines):
                        if overlap_length + len(prev_line) + 1 > overlap_size:
                            break
                        overlap_lines.insert(0, prev_line)
                        overlap_length += len(prev_line) + 1
                    current_lines = overlap_lines
                    current_length = sum(len(l) + 1 for l in current_lines)

                current_lines.append(line)
                current_length += len(line) + 1

            if current_lines:
                documents.append(
                    Document(page_content="\n".join(current_lines), metadata=rec["metadata"])
                )

        return documents
    
