from qdrant_client import models, QdrantClient
from ..VectorDBInterface import VectorDBInterface
from ..VectorDBEnums import DistanceMethodEnums
import logging
from typing import List
from models.db_schemes import RetrievedDocument
import time
import math

class QdrantDBProvider(VectorDBInterface):

    def __init__(self, db_path: str, distance_method: str, default_vector_size: int = None, index_threshold: int = None):
        self.client = None
        self.db_path = db_path
        self.distance_method = None
        self.default_vector_size = default_vector_size
        self.index_threshold = index_threshold

        if distance_method == DistanceMethodEnums.COSINE.value:
            self.distance_method = models.Distance.COSINE
        elif distance_method == DistanceMethodEnums.DOT.value:
            self.distance_method = models.Distance.DOT

        self.logger = logging.getLogger(__name__)

    def connect(self):
        self.client = QdrantClient(path=self.db_path)

    def disconnect(self):
        self.client = None

    def is_collection_existed(self, collection_name: str) -> bool:
        return self.client.collection_exists(collection_name=collection_name)

    def list_all_collections(self) -> List:
        return self.client.get_collections()

    def get_collection_info(self, collection_name: str) -> dict:
        return self.client.get_collection(collection_name=collection_name)

    def delete_collection(self, collection_name: str):
        if self.is_collection_existed(collection_name):
            return self.client.delete_collection(collection_name=collection_name)

    def create_collection(self, collection_name: str,
                                embedding_size: int,
                                do_reset: bool = False):
        if do_reset:
            _ = self.delete_collection(collection_name=collection_name)

        if not self.is_collection_existed(collection_name):
            _ = self.client.create_collection(
                collection_name=collection_name,
                vectors_config=models.VectorParams(
                    size=embedding_size,
                    distance=self.distance_method
                )
            )
            return True
        else:
            # Check if existing collection has the correct vector size
            try:
                collection_info = self.get_collection_info(collection_name)
                current_size = collection_info.config.params.vectors.size
                if current_size != embedding_size:
                    self.logger.info(f"Collection {collection_name} has vector size {current_size}, but expected {embedding_size}. Recreating...")
                    _ = self.delete_collection(collection_name=collection_name)
                    _ = self.client.create_collection(
                        collection_name=collection_name,
                        vectors_config=models.VectorParams(
                            size=embedding_size,
                            distance=self.distance_method
                        )
                    )
                    return True
            except AttributeError as e:
                self.logger.warning(f"Could not check vector size for collection {collection_name}: {e}. Assuming mismatch and recreating.")
                _ = self.delete_collection(collection_name=collection_name)
                _ = self.client.create_collection(
                    collection_name=collection_name,
                    vectors_config=models.VectorParams(
                        size=embedding_size,
                        distance=self.distance_method
                    )
                )
                return True

        return False

    def insert_one(self, collection_name: str, text: str, vector: list,
                         metadata: dict = None,
                         record_id: str = None):

        if not self.is_collection_existed(collection_name):
            self.logger.error(f"Can not insert new record to non-existed collection: {collection_name}")
            return False

        try:
            point = models.PointStruct(
                id=record_id,
                vector=vector,
                payload={"text": text, "metadata": metadata}
            )
            self.client.upsert(
                collection_name=collection_name,
                points=[point],
            )
        except Exception as e:
            self.logger.error(f"Error while inserting record: {e}")
            return False

        return True

    def insert_many(self, collection_name: str, texts: list,
                          vectors: list, metadata: list = None,
                          record_ids: list = None, batch_size: int = 10):

        if metadata is None:
            metadata = [None] * len(texts)

        if record_ids is None:
            record_ids = list(range(0, len(texts)))

        for i in range(0, len(texts), batch_size):
            batch_end = i + batch_size

            batch_texts    = texts[i:batch_end]
            batch_vectors  = vectors[i:batch_end]
            batch_metadata = metadata[i:batch_end]
            batch_ids      = record_ids[i:batch_end]

            points = [
                models.PointStruct(
                    id=batch_ids[x],
                    vector=batch_vectors[x],
                    payload={
                        "text": batch_texts[x],
                        "metadata": batch_metadata[x]
                    }
                )
                for x in range(len(batch_texts))
            ]

            try:
                self.client.upsert(
                    collection_name=collection_name,
                    points=points,
                )
            except Exception as e:
                error_msg = str(e).lower()
                if "disk i/o error" in error_msg or "cannot commit" in error_msg:
                    self.logger.warning(f"Transient error while inserting batch, retrying: {e}")
                    time.sleep(1)  # Brief pause
                    try:
                        self.client.upsert(
                            collection_name=collection_name,
                            points=points,
                        )
                    except Exception as retry_e:
                        self.logger.error(f"Error while inserting batch after retry: {retry_e}")
                        return False
                else:
                    self.logger.error(f"Error while inserting batch: {e}")
                    return False

        return True

    def search_by_vector(self, collection_name: str, vector: list, limit: int = 5, metadata_filter: list = None):

        results = self.client.search(
            collection_name=collection_name,
            query_vector=vector,
            limit=limit
        )

        if not results or len(results) == 0:
            return None

        documents = [
            RetrievedDocument(**{
                "score": result.score,
                "text": result.payload["text"],
                "metadata": result.payload.get("metadata"),
            })
            for result in results
        ]

        if metadata_filter:
            documents = [doc for doc in documents if self._matches_metadata_filter(doc.metadata, metadata_filter)]

        return documents

    def _matches_metadata_filter(self, metadata, metadata_filter: list) -> bool:
        if not metadata or not isinstance(metadata, dict):
            return False

        for condition in metadata_filter:
            key = condition.get("key")
            operator = condition.get("operator", "equals")
            value = condition.get("value")
            if not key or value is None:
                continue

            if key == "location" and operator == "equals":
                if metadata.get("location") == value:
                    return True
            elif key == "rule.groups" and operator == "contains":
                rule = metadata.get("rule")
                if isinstance(rule, dict):
                    group_value = rule.get("groups")
                    if isinstance(group_value, list) and value in group_value:
                        return True
            elif key == "rule.mitre.id" and operator == "equals":
                rule = metadata.get("rule")
                if isinstance(rule, dict):
                    mitre = rule.get("mitre")
                    if isinstance(mitre, dict) and mitre.get("id") == value:
                        return True
            elif key == "rule.level" and operator == "greater_than":
                rule = metadata.get("rule")
                if isinstance(rule, dict):
                    level = rule.get("level")
                    if isinstance(level, (int, str)) and int(level) > value:
                        return True
            elif operator == "equals":
                current = metadata
                for part in key.split('.'):
                    if not isinstance(current, dict) or part not in current:
                        current = None
                        break
                    current = current.get(part)
                if current == value:
                    return True

        return False