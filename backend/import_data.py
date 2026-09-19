import pandas as pd
from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017"
DATABASE_NAME = "flyyy_privacy_platform"
COLLECTION_NAME = "source_customers"

CSV_FILE = "data/customers.csv"

client = MongoClient(MONGO_URI)

db = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]

df = pd.read_csv(CSV_FILE)

records = df.to_dict(orient="records")

if records:
    collection.delete_many({})
    result = collection.insert_many(records)

    print("=" * 50)
    print("DATA IMPORT SUCCESSFUL")
    print("=" * 50)
    print(f"Records imported : {len(result.inserted_ids)}")
    print(f"Database         : {DATABASE_NAME}")
    print(f"Collection       : {COLLECTION_NAME}")
else:
    print("CSV contains no records.")

client.close()
