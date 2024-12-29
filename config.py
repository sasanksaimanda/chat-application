from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/')
db = client.clientchat_application
users_collection = db.users
chats_collection = db.chats
media_collection = db.media
