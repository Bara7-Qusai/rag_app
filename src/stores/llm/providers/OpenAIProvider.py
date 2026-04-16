from ..LLMInterface import LLMInterface
from ..LLMEnums import OpenAIEnums
from openai import OpenAI
from fastapi import HTTPException
import logging
import time
from typing import Union, List

class OpenAIProvider(LLMInterface):

    def __init__(self, api_key: str, api_url: str=None,
                       default_input_max_characters: int=1000,
                       default_generation_max_output_tokens: int=1000,
                       default_generation_temperature: float=0.1):
        
        self.api_key = api_key
        self.api_url = api_url

        self.default_input_max_characters = default_input_max_characters
        self.default_generation_max_output_tokens = default_generation_max_output_tokens
        self.default_generation_temperature = default_generation_temperature

        self.generation_model_id = None

        self.embedding_model_id = None
        self.embedding_size = None

        self.client = OpenAI(
            api_key = self.api_key,
            base_url = self.api_url if self.api_url and len(self.api_url) else None,
            timeout=60.0,  # Reduced timeout
            max_retries=0,
        )

        self.enums = OpenAIEnums
        self.logger = logging.getLogger(__name__)

    def set_generation_model(self, model_id: str):
        self.generation_model_id = model_id

    def set_embedding_model(self, model_id: str, embedding_size: int):
        self.embedding_model_id = model_id
        self.embedding_size = embedding_size

    def process_text(self, text: str):
        return text[:self.default_input_max_characters].strip()

    def construct_prompt(self, prompt: str, role: str):
        return {"role": role, "content": prompt}

    def generate_text(self, prompt: str, chat_history: list=[], max_output_tokens: int=None,
                            temperature: float = None):
        
        if not self.client:
            self.logger.error("OpenAI client was not set")
            return None

        if not self.generation_model_id:
            self.logger.error("Generation model for OpenAI was not set")
            return None
        
        max_output_tokens = max_output_tokens if max_output_tokens else self.default_generation_max_output_tokens
        temperature = temperature if temperature else self.default_generation_temperature

        chat_history.append(
            self.construct_prompt(prompt=prompt, role=OpenAIEnums.USER.value)
        )

        # Retry with exponential backoff
        max_retries = 3
        base_delay = 1.0
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model = self.generation_model_id,
                    messages = chat_history,
                    max_tokens = max_output_tokens,
                    temperature = temperature
                )

                if not response or not response.choices or len(response.choices) == 0 or not response.choices[0].message:
                    self.logger.error("Error while generating text with OpenAI")
                    return None

                return response.choices[0].message.content

            except Exception as e:
                self.logger.warning(f"OpenAI request failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    self.logger.info(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    self.logger.error(f"OpenAI request failed after {max_retries} attempts")
                    return None


    def embed_text(self, text: Union[str, List[str]], document_type: str = None):
        
        if not self.client:
            self.logger.error("OpenAI client was not set")
            return None

        if not self.embedding_model_id:
            self.logger.error("Embedding model for OpenAI was not set")
            return None
        
        response = self.client.embeddings.create(
            model = self.embedding_model_id,
            input = text,
        )

        if not response or not response.data or len(response.data) == 0 or not response.data[0].embedding:
            self.logger.error("Error while embedding text with OpenAI")
            return None

        return response.data[0].embedding

    def embed_texts(self, texts: list, document_type: str = None):
        
        if not self.client:
            self.logger.error("OpenAI client was not set")
            return None

        if not self.embedding_model_id:
            self.logger.error("Embedding model for OpenAI was not set")
            return None

        # Fallback URLs in case primary fails
        urls_to_try = [
            self.api_url,
            "http://127.0.0.1:11434/v1/",
        ]

        max_retries = 3
        backoff = 1.0
        last_error = None

        for url in urls_to_try:
            if not url:
                continue
            
            # Create client with this URL
            temp_client = OpenAI(
                api_key=self.api_key,
                base_url=url if url else None,
                timeout=300.0,
                max_retries=0,
            )

            for attempt in range(1, max_retries + 1):
                try:
                    response = temp_client.embeddings.create(
                        model=self.embedding_model_id,
                        input=texts,
                    )

                    if (not response or not response.data or
                        len(response.data) != len(texts)):
                        raise ValueError("Invalid embedding response")

                    embeddings = [data.embedding for data in response.data]
                    
                    # Check for consistent embedding lengths
                    embedding_lengths = [len(emb) for emb in embeddings]
                    if len(set(embedding_lengths)) != 1:
                        self.logger.error(f"Inconsistent embedding lengths: {set(embedding_lengths)}")
                        raise ValueError(f"Inconsistent embedding lengths: {set(embedding_lengths)}")
                    
                    return embeddings

                except Exception as e:
                    last_error = e
                    msg = str(e).lower()

                    # Retry on transient networking errors
                    if any(x in msg for x in ("connection", "timeout", "temporary failure", "rate limit")):
                        self.logger.warning(f"Embedding retry {attempt}/{max_retries} on {url} after error: {e}")
                        time.sleep(backoff)
                        backoff *= 2
                        continue

                    # If not transient, try next URL
                    break

        self.logger.error(f"Failed to embed texts after trying all URLs: {last_error}")

    