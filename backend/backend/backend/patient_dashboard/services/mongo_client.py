from pymongo import MongoClient
import os

# Returns a pymongo Database instance
def get_db():
    uri = os.getenv('MONGODB_URI')
    if not uri:
        raise RuntimeError("MONGODB_URI not set in env")
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    # optional: test selection on first call
    client.admin.command('ping')
    # use the DB name encoded in the URI or override here
    # if you want an explicit DB name: client['myDatabase']
    return client.get_default_database()