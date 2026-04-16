from .BaseDataModel import BaseDataModel
from .db_schemes import Asset
from .enums.DataBaseEnum import DataBaseEnum
from bson import ObjectId
from sqlalchemy.future import select

class AssetModel(BaseDataModel):

    def __init__(self, db_client: object):
        super().__init__(db_client=db_client)
        self.collection =  db_client

    @classmethod
    async def create_instance(cls, db_client: object):
        instance = cls(db_client)
        await instance.init_collection()
        return instance

    
    async def create_asset(self, asset: Asset):

        async with self.db_client() as session:
            async with session.begin():
                session.add(asset)
            await session.commit()
            await session.refresh(asset)
            
            return asset

    async def get_all_project_assets(self, asset_project_id: str, asset_type: str):

        async with self.db_client() as session:
            result = await session.execute(
                select(Asset).where(Asset.asset_project_id == int(asset_project_id), Asset.asset_type == asset_type)
            )
            records = result.scalars().all()
            return records

    async def get_asset_record(self, asset_project_id: str, asset_name: str):

        async with self.db_client() as session:
            result = await session.execute(
                select(Asset).where(Asset.asset_project_id == int(asset_project_id), Asset.asset_name == asset_name)
            )
            record = result.scalars().first()
            return record

    async def get_asset_record_by_id(self, asset_project_id: str, asset_id: int):

        async with self.db_client() as session:
            result = await session.execute(
                select(Asset).where(Asset.asset_project_id == int(asset_project_id), Asset.asset_id == int(asset_id))
            )
            record = result.scalars().first()
            return record


    