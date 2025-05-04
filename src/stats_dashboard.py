import streamlit as st
import pandas as pd
from pymongo import MongoClient

# Configuración de la página
st.set_page_config(page_title="SSH Log Dashboard", layout="wide")
st.title("SSH Log Dashboard")

# Conexión a MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['ssh_logs_db']
collection = db['logs']

# Función para cargar datos desde MongoDB
def load_data():
    data = list(collection.find({}, {"_id": 0}))  # Excluye el campo _id
    df = pd.DataFrame(data)
    return df

# Cargar datos
df = load_data()

if df.empty:
    st.warning("No se han encontrado datos en la base de datos.")
else:
    st.write(f"Última actualización manual: {pd.Timestamp.now().strftime('%H:%M:%S')}")

    # Métricas
    st.metric("Total registros", len(df))
    st.metric("Usuarios únicos", df['user'].nunique())
    st.metric("IPs únicas", df['ip'].nunique())

    # Visualizaciones
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Eventos por tipo")
        st.bar_chart(df['event'].value_counts())

    with col2:
        st.subheader("Usuarios más frecuentes")
        st.bar_chart(df['user'].value_counts().head(10))

    # Mostrar las primeras filas para depuración
    st.subheader("Primeras filas del DataFrame")
    st.write(df.head(10))

    # ========================
    # Análisis temporal nuevo
    # ========================
    st.header("📈 Evolución de accesos fallidos")

    # Convertir a datetime real
    try:
        df['datetime'] = pd.to_datetime(df['month'] + ' ' + df['day'].astype(str) + ' ' + df['time'],
                                        format='%b %d %H:%M:%S', errors='coerce')
        df = df.dropna(subset=['datetime'])
    except Exception as e:
        st.error(f"Error al convertir a datetime: {e}")

    # Filtros
    event_filter = st.selectbox("Selecciona tipo de evento",
                                options=sorted(df['event'].dropna().unique()),
                                index=0)

    agg_filter = st.radio("Agrupar por", options=["Hora", "Día"], horizontal=True)

    filtered_df = df[df['event'] == event_filter]

    # Agrupación y gráfico
    if agg_filter == "Hora":
        grouped = filtered_df.groupby(filtered_df['datetime'].dt.hour).size()
        grouped.index.name = "Hora del día"
    else:
        grouped = filtered_df.groupby(filtered_df['datetime'].dt.date).size()
        grouped.index.name = "Día"

    st.line_chart(grouped)
