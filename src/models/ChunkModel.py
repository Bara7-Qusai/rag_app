from .BaseDataModel import BaseDataModel
from .db_schemes import DataChunk
from .enums.DataBaseEnum import DataBaseEnum
from bson.objectid import ObjectId
from pymongo import InsertOne
from sqlalchemy.future import select
from sqlalchemy import delete

class ChunkModel(BaseDataModel):

    def __init__(self, db_client: object):
        super().__init__(db_client=db_client)
        self.collection = db_client
        
    @classmethod
    async def create_instance(cls, db_client: object):
        instance = cls(db_client)
        await instance.init_collection()
        return instance
    
    
    async def create_chunk(self, chunk: DataChunk):
        async with self.db_client() as session:
            async with session.begin():
                session.add(chunk)
            await session.commit()
            await session.refresh(chunk)
            return chunk

    async def get_chunk(self, chunk_id: str):
        async with self.db_client() as session:
            result = await session.execute(
                select(DataChunk).where(DataChunk.chunk_id == int(chunk_id))
            )
            chunk = result.scalars().first()
            return chunk

    async def insert_many_chunks(self, chunks: list, batch_size: int=100):
        async with self.db_client() as session:
            async with session.begin():
                session.add_all(chunks)
            await session.commit()
            for chunk in chunks:
                await session.refresh(chunk)
        return len(chunks)

    async def delete_chunks_by_project_id(self, project_id: int):
        async with self.db_client() as session:
            result = await session.execute(
                delete(DataChunk).where(DataChunk.chunk_project_id == project_id)
            )
            await session.commit()
            return result.rowcount
    
    async def get_project_chunks(self, project_id: int, page_no: int=1, page_size: int=200, asset_id: int = None):
        async with self.db_client() as session:
            query = select(DataChunk).where(DataChunk.chunk_project_id == project_id)
            if asset_id is not None:
                query = query.where(DataChunk.chunk_asset_id == asset_id)

            result = await session.execute(
                query.offset((page_no-1) * page_size)
                .limit(page_size)
            )
            records = result.scalars().all()
            return records
        
        
        async def get_total_chunks_count(self, project_id: ObjectId):
             total_count = 0
             async with self.db_client() as session:
                   count_sql = select(func.count(DataChunk.chunk_id)).where(DataChunk.chunk_project_id == project_id)
                   records_count = await session.execute(count_sql)
                   total_count = records_count.scalar()
        
                   return total_count
    

    