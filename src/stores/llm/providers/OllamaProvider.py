import requests
import json
from ..LLMInterface import LLMInterface
from typing import Union, List


class OllamaProvider(LLMInterface):

    def __init__(self, api_url="http://127.0.0.1:11434"):
        self.api_url = api_url
        self.generation_model_id = None
        self.embedding_model_id = None
        self.embedding_size = None

    # ========================
    # Setup
    # ========================
    def set_generation_model(self, model_id: str):
        self.generation_model_id = model_id

    def set_embedding_model(self, model_id: str, embedding_size: int):
        self.embedding_model_id = model_id
        self.embedding_size = embedding_size

    # ========================
    # Prompt
    # ========================
    def construct_prompt(self, prompt: str, role: str):
        return prompt

    # ========================
    # Generation
    # ========================
    def generate_text(
        self,
        prompt: str,
        chat_history: list = [],
        max_output_tokens: int = None,
        temperature: float = None,
    ):
        if not self.generation_model_id:
            raise Exception("Generation model not set")

        # build full prompt
        full_prompt = ""
        for msg in chat_history:
            if isinstance(msg, dict):
                full_prompt += msg.get("content", "") + "\n"
            else:
                full_prompt += str(msg) + "\n"

        full_prompt += prompt

        response = requests.post(
            f"{self.api_url}/api/generate",
            json={
                "model": self.generation_model_id,
                "prompt": full_prompt,
                "num_ctx": 1024,
                "num_predict": 600,
                "stream": True,
            },
            timeout=300,
            stream=True,
        )

        if response.status_code != 200:
            raise Exception(f"Ollama generation error: {response.text}")

        full_response = ""
        for line in response.iter_lines():
            if line:
                try:
                    data = json.loads(line.decode('utf-8'))
                    if 'response' in data:
                        full_response += data['response']
                    if data.get('done', False):
                        break
                except json.JSONDecodeError:
                    continue

        return full_response

    # ========================
    # Single Embedding
    # ========================
    def embed_text(self, text: str, document_type: str = None):
        if not self.embedding_model_id:
            raise Exception("Embedding model not set")

        response = requests.post(
            f"{self.api_url}/api/embeddings",
            json={
                "model": self.embedding_model_id,
                "prompt": text,
            },
            timeout=60,
        )

        if response.status_code != 200:
            raise Exception(f"Ollama embedding error: {response.text}")

        data = response.json()

        if "embedding" not in data:
            raise Exception(f"Invalid embedding response: {data}")

        embedding = data["embedding"]

        # validate size
        if self.embedding_size and len(embedding) != self.embedding_size:
            raise Exception(
                f"Embedding size mismatch: expected {self.embedding_size}, got {len(embedding)}"
            )

        return embedding

    # ========================
    # Batch Embeddings
    # ========================
   
    def embed_texts(self, texts: List[str], document_type: str = None):
        embeddings = []

        for text in texts:
            emb = self.embed_text(text)

            if not emb:
                raise Exception("Embedding failed for one of the texts")

            embeddings.append(emb)

        # check consistency
        sizes = [len(e) for e in embeddings]
        if len(set(sizes)) != 1:
            raise Exception(f"Inconsistent embedding sizes: {set(sizes)}")

        return embeddings