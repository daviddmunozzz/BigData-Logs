import matplotlib.pyplot as plt
from pymongo import MongoClient
import pandas as pd

#client = MongoClient("mongodb://localhost:27017/")
#logs = pd.DataFrame(list(client.logdb.logs.find()))

def generate_graphic(logs):

    fig, ax = plt.subplots(figsize=(10, 6))
    colors = logs["anomaly"].map({1: "blue", -1: "red"})
    ax.scatter(logs["timestamp"], logs["ip_last"], c=colors)
    ax.set_title("Detección de Anomalías en Logs por IP")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Último octeto de IP")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("anomalies_detailed.png")
