import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from pymongo import MongoClient
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest

st.title("Análisis de Anomalías en Logs del Sistema")

@st.cache_data
def load_data():
    client = MongoClient("mongodb://localhost:27017/")
    logs = pd.DataFrame(list(client.logdb.logs.find()))
    
    # Convertir ObjectId a string para evitar problemas con Arrow
    logs["_id"] = logs["_id"].astype(str)
    
    logs["timestamp"] = pd.to_datetime(logs["timestamp"])
    logs["hour"] = logs["timestamp"].dt.hour
    logs["ip_last"] = logs["ip"].apply(lambda x: int(x.split('.')[-1]))

    for col in ["level", "service", "user"]:
        logs[col] = LabelEncoder().fit_transform(logs[col])

    features = ["level", "service", "user", "ip_last", "hour"]
    model = IsolationForest(contamination=0.05, random_state=42)
    logs["anomaly"] = model.fit_predict(logs[features])
    
    return logs

logs = load_data()
st.write(f"Total de registros: {len(logs)}")

# Filtros
hour_range = st.slider("Filtrar por hora", 0, 23, (0, 23))
filtered = logs[(logs["hour"] >= hour_range[0]) & (logs["hour"] <= hour_range[1])]

st.write("Muestra de los datos:")
st.dataframe(filtered.head(20))

fig, ax = plt.subplots(figsize=(10, 6))
colors = filtered["anomaly"].map({1: "blue", -1: "red"})
ax.scatter(filtered["timestamp"], filtered["ip_last"], c=colors)
ax.set_title("Anomalías Detectadas")
ax.set_xlabel("Timestamp")
ax.set_ylabel("Último octeto de IP")
plt.xticks(rotation=45)
st.pyplot(fig)
