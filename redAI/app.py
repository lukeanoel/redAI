#!/usr/bin/env python
import os
import logging
from redAI.database.attack_interface import Attack
from stix2 import MemoryStore
from service.data_svc import DataService
from service.collection_svc import CollectionService
from service.cleaning_svc import CleaningService
from service.ml_svc import MachineLearningService
from database.dao import Dao


def main():
    logging.info('Reloading database')
    data_svc.reload_database()
    collection_svc.init_data_csv()
    ml_svc.build_model()


if __name__ == '__main__':
    logging.getLogger().setLevel('DEBUG')
    logging.info('Welcome to RedAI')
    dao = Dao(os.path.join('database', 'redAI.db'))
    src = MemoryStore()
    src.load_from_file('./models/attack_dict.json')
    attack = Attack(src)

    # Start services and initiate main function
    data_svc = DataService(dao=dao)
    collection_svc = CollectionService(attack=attack, data_svc=data_svc)
    cleaning_svc = CleaningService()
    ml_svc = MachineLearningService()
    services = dict(dao=dao, data_svc=data_svc, collection_svc=collection_svc)
    main()
