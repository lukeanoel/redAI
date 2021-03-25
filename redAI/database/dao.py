from .data_helper import DataHelper
import logging


class Dao:

    def __init__(self, database):
        self.logger = logging.getLogger('DataService')
        self.db = DataHelper(database)

    def build(self, schema):
        self.db.build(schema)

    async def get(self, table, criteria=None):
        return await self.db.get(table, criteria)

    def update(self, table, key, value, data):
        self.db.update(table, key, value, data)

    def insert(self, table, data):
        return self.db.insert(table, data)

    async def delete(self, table, data):
        await self.db.delete(table, data)

    async def raw_query(self, query, one=False):
        return await self.db.raw_query(query, one)

    async def raw_select(self, query):
        return await self.db.raw_select(query)