import pandas as pd
from pymongo import MongoClient

def insert_into_mongo():

    csv_path = './assets/parsed_logs.csv'
    df = pd.read_csv(csv_path)

    client = MongoClient('mongodb://localhost:27017/')

    db = client['ssh_logs_db']
    collection = db['logs']

    data_dict = df.to_dict("records")
    collection.insert_many(data_dict)

    print("Inserción en MongoDB completada.")

if __name__ == "__main__":
    insert_into_mongo()