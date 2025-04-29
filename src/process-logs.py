from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest
import pandas as pd
from visualitation import generate_graphic

# Carga los datos desde MongoDB
from pymongo import MongoClient
client = MongoClient("mongodb://localhost:27017/")
logs = pd.DataFrame(list(client.logdb.logs.find()))

# Preprocesado
logs["timestamp"] = pd.to_datetime(logs["timestamp"])
logs["hour"] = logs["timestamp"].dt.hour
logs["ip_last"] = logs["ip"].apply(lambda x: int(x.split('.')[-1]))

# Codificación de texto
for col in ["level", "service", "user"]:
    logs[col] = LabelEncoder().fit_transform(logs[col])

features = ["level", "service", "user", "ip_last", "hour"]
model = IsolationForest(contamination=0.05, random_state=42)
logs["anomaly"] = model.fit_predict(logs[features])

generate_graphic(logs)