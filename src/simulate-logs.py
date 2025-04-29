import random
from datetime import datetime, timedelta
from pymongo import MongoClient
import uuid

levels = ["INFO", "WARNING", "ERROR", "CRITICAL"]
services = ["auth", "database", "payment", "api", "storage"]
users = ["user" + str(i) for i in range(1, 11)]
ips = ["192.168.1." + str(i) for i in range(1, 50)]

def generate_log():
    now = datetime.now()
    level = random.choices(levels, weights=[70, 15, 10, 5])[0]
    service = random.choice(services)
    user = random.choice(users)
    ip = random.choice(ips)
    log_id = str(uuid.uuid4())
    message = f"{service.upper()} operation by {user}"
    timestamp = now.isoformat()
    return {
        "id": log_id,
        "timestamp": timestamp,
        "level": level,
        "service": service,
        "user": user,
        "ip": ip,
        "message": message
    }

client = MongoClient("mongodb://localhost:27017/")
db = client["logdb"]
collection = db["logs"]

for _ in range(3000):
    collection.insert_one(generate_log())
