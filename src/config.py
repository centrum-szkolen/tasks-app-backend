from pymongo import MongoClient
from dotenv import load_dotenv
import os 
load_dotenv()

DB_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

client = MongoClient(DB_URI)
db = client[DB_NAME]

users_collection = db['users']
tasks_collection = db['tasks']