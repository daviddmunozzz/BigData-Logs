import streamlit as st
import pandas as pd
from pymongo import MongoClient
import plotly.express as px

st.set_page_config(page_title="SSH Log Dashboard", layout="wide")
st.title("SSH Log Dashboard")

client = MongoClient('mongodb://localhost:27017/')
db = client['ssh_logs_db']
collection = db['logs']

def load_data():
    data = list(collection.find({}, {"_id": 0}))
    df = pd.DataFrame(data)
    return df

df = load_data()

if df.empty:
    st.warning("No data found in the database.")
else:
    df['user'] = df['user'].fillna('')
    try:
        df['datetime'] = pd.to_datetime(
            '2024 ' + df['month'] + ' ' + df['day'].astype(str) + ' ' + df['time'],
            format='%Y %b %d %H:%M:%S', errors='coerce'
        )
        df = df.dropna(subset=['datetime'])
    except Exception as e:
        st.error(f"Datetime conversion error: {e}")

    st.write(f"Last update: {pd.Timestamp.now().strftime('%H:%M:%S')}")
    
    st.metric("Total records", len(df))
    st.metric("Unique users", df['user'].nunique())
    st.metric("Unique IPs", df['ip'].nunique())
    st.metric("Distinct Events", df['event'].nunique())

    failed_events = df['event'].isin(['failed_password', 'invalid_user', 'auth_failure']).sum()
    failed_rate = (failed_events / len(df)) * 100 if len(df) > 0 else 0
    st.metric("Failed Login Rate", f"{failed_rate:.2f}%")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Event types")
        st.bar_chart(df['event'].value_counts())
    with col2:
        st.subheader("Top users")
        st.bar_chart(df['user'].value_counts().head(10))

    st.subheader("Sample records")
    st.write(df.head(10))

    st.header("Access evolution")
    event_filter = st.selectbox("Select event type", options=sorted(df['event'].dropna().unique()), index=0)
    agg_filter = st.radio("Group by", options=["Hour", "Day"], horizontal=True)
    filtered_df = df[df['event'] == event_filter]

    if agg_filter == "Hour":
        filtered_df['hour'] = filtered_df['datetime'].dt.hour
        grouped = filtered_df.groupby('hour').size().sort_index()
        grouped.index = grouped.index.astype(str).str.zfill(2)
        grouped.index.name = "Hour"
    else:
        grouped = filtered_df.groupby(filtered_df['datetime'].dt.date).size().sort_index()
        grouped.index = pd.to_datetime(grouped.index)
        grouped.index = grouped.index.strftime('%b %d')
        grouped.index.name = "Date"

    st.line_chart(grouped)

    st.subheader("System-wide Event Evolution")

    # A. Eventos totales a lo largo del tiempo
    events_per_day = df.groupby(df['datetime'].dt.date).size().reset_index(name="Total Events")
    events_per_day.rename(columns={'datetime': 'date'}, inplace=True)
    fig_total_events = px.line(events_per_day, x='date', y='Total Events', title="Total Events Over Time")
    st.plotly_chart(fig_total_events, use_container_width=True)

    # B. Eventos sospechosos vs normales por día
    suspicious_events = ['failed_password', 'invalid_user', 'auth_failure']
    df['event_type'] = df['event'].apply(lambda x: 'Suspicious' if x in suspicious_events else 'Normal')
    evolution_df = df.groupby([df['datetime'].dt.date, 'event_type']).size().reset_index(name="Count")
    evolution_df.rename(columns={'datetime': 'date'}, inplace=True)
    evolution_pivot = evolution_df.pivot(index='date', columns='event_type', values='Count').fillna(0)
    fig_evolution = px.line(evolution_pivot, x=evolution_pivot.index, y=['Suspicious', 'Normal'],
                            title="Suspicious vs Normal Events Over Time")
    st.plotly_chart(fig_evolution, use_container_width=True)

    # C. Evolución por tipo de evento
    events_by_type = df.groupby([df['datetime'].dt.date, 'event']).size().reset_index(name='Count')
    events_by_type.rename(columns={'datetime': 'date'}, inplace=True)
    fig_all_events_by_type = px.line(
        events_by_type,
        x='date',
        y='Count',
        color='event',
        title='Event Types Over Time'
    )
    st.plotly_chart(fig_all_events_by_type, use_container_width=True)

    ip_event_summary = df.groupby(['ip', 'event']).size().unstack(fill_value=0)
    ip_event_summary['total_events'] = ip_event_summary.sum(axis=1)
    ip_event_summary['distinct_source_ports'] = df.groupby('ip')['port'].nunique()
    ip_event_summary['source_ports_list'] = df.groupby('ip')['port'].apply(lambda x: sorted(set(x.dropna().astype(int).astype(str))))
    ip_event_summary['first_seen'] = df.groupby('ip')['datetime'].min()
    ip_event_summary['last_seen'] = df.groupby('ip')['datetime'].max()
    ip_event_summary['failed_logins'] = ip_event_summary.get('failed_password', 0) + \
                                        ip_event_summary.get('invalid_user', 0) + \
                                        ip_event_summary.get('auth_failure', 0)
    user_attempts = df[df['event'].isin(suspicious_events)].groupby('ip')['user'].apply(lambda x: sorted(set(x)))
    ip_event_summary['failed_users'] = ip_event_summary.index.map(user_attempts).fillna('').astype(str)
    root_login_attempts = df[df['user'].str.lower().isin(['root', 'admin'])]
    tried_root_admin = root_login_attempts.groupby('ip').size()
    ip_event_summary['tried_root_admin'] = ip_event_summary.index.map(tried_root_admin).fillna(0).astype(int)
    ip_event_summary['event_diversity'] = df.groupby('ip')['event'].nunique()

    ip_event_summary['suspicious_score'] = (
        2 * ip_event_summary['failed_logins'] +
        3 * ip_event_summary['distinct_source_ports'] +
        0.5 * ip_event_summary['total_events'] +
        15 * (ip_event_summary['tried_root_admin'] > 0).astype(int) +
        1 * ip_event_summary['event_diversity']
    ).clip(upper=100)

    def classify_ip_types(row):
        score = row['suspicious_score']
        failed = row['failed_logins']
        ports = row['distinct_source_ports']
        root = row['tried_root_admin']
        diversity = row['event_diversity']
        attacker_score = min(100, 0.6 * score + 5 * root + 2 * failed)
        bot_score = min(100, 1.5 * diversity + 2 * ports)
        legit_score = max(0, 100 - attacker_score - bot_score)
        total = attacker_score + bot_score + legit_score
        return {
            'Attacker': round(attacker_score * 100 / total, 1),
            'Bot': round(bot_score * 100 / total, 1),
            'Authorized': round(legit_score * 100 / total, 1)
        }

    ip_event_summary['ip_type_profile'] = ip_event_summary.apply(classify_ip_types, axis=1)
    ip_event_summary = ip_event_summary.sort_values(by='suspicious_score', ascending=False)

    st.subheader("Global IP Statistics")
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.metric("Total IPs", ip_event_summary.shape[0])
        st.metric("Failed Login IPs", (ip_event_summary['failed_logins'] > 0).sum())
        st.metric("Root/Admin Attempts", (ip_event_summary['tried_root_admin'] > 0).sum())
    with col_b:
        st.metric("IPs > 100 Events", (ip_event_summary['total_events'] > 100).sum())
        st.metric("Max Events/IP", int(ip_event_summary['total_events'].max()))
        st.metric("Avg Events/IP", f"{ip_event_summary['total_events'].mean():.2f}")
    with col_c:
        st.metric("Avg Suspicious Score", f"{ip_event_summary['suspicious_score'].mean():.2f}")
        st.metric("Suspicious > 80", (ip_event_summary['suspicious_score'] > 80).sum())

    st.subheader("Distributions")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.plotly_chart(px.histogram(ip_event_summary, x='suspicious_score', nbins=20, title="Suspicious Score Distribution", width=400, height=400), use_container_width=False)
    with col2:
        top_ips = ip_event_summary.sort_values(by='total_events', ascending=False).head(10)
        st.plotly_chart(px.bar(top_ips, x=top_ips.index, y='total_events', title="Top 10 Most Active IPs", width=400, height=400), use_container_width=False)
    with col3:
        top_suspicious = ip_event_summary.sort_values(by='suspicious_score', ascending=False).head(10)
        st.plotly_chart(px.bar(top_suspicious, x=top_suspicious.index, y='suspicious_score', title="Top 10 Suspicious IPs", width=400, height=400), use_container_width=False)

    st.subheader("Event and Port Usage Diversity")
    col4, col5 = st.columns(2)
    with col4:
        fig4 = px.bar(x=ip_event_summary['event_diversity'].value_counts().sort_index().index,
                      y=ip_event_summary['event_diversity'].value_counts().sort_index().values,
                      title="Event Type Diversity")
        st.plotly_chart(fig4, use_container_width=False)
    with col5:
        fig5 = px.bar(x=ip_event_summary['distinct_source_ports'].value_counts().sort_index().index,
                      y=ip_event_summary['distinct_source_ports'].value_counts().sort_index().values,
                      title="Source Port Diversity")
        st.plotly_chart(fig5, use_container_width=False)

    selected_ip = st.selectbox("Select an IP", ip_event_summary.index.sort_values())
    col_table, col_detail, col_logs = st.columns([1.2, 1.5, 3])
    with col_table:
        st.subheader("IP List")
        st.dataframe(ip_event_summary[['suspicious_score']].reset_index(), height=500, use_container_width=True)

    with col_detail:
        ip_data = ip_event_summary.loc[selected_ip]
        st.markdown(f"### IP Details: {selected_ip}")
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown(f"**Suspicious Score:** {ip_data['suspicious_score']}")
            st.markdown(f"**First Seen:** {ip_data['first_seen']}")
            st.markdown(f"**Last Seen:** {ip_data['last_seen']}")
        with col_b:
            ports_display = ip_data['source_ports_list']
            ports_preview = ', '.join(ports_display[:40])
            st.markdown(f"**Source Ports Used:** {int(ip_data['distinct_source_ports'])} ({ports_preview}...)")
            if len(ports_display) > 40:
                with st.expander("Show all ports"):
                    st.text(', '.join(ports_display))
        st.markdown(f"**Failed Logins:** {ip_data['failed_logins']} ({ip_data['failed_users']})")
        for col in ip_event_summary.columns:
            if col not in ['total_events', 'suspicious_score', 'distinct_source_ports',
                           'source_ports_list', 'first_seen', 'last_seen', 'failed_users', 'ip_type_profile']:
                st.markdown(f"**{col.replace('_', ' ').title()}:** {ip_data[col]}")

    with col_logs:
        st.subheader("Logs for selected IP")
        ip_specific_df = df[df['ip'] == selected_ip].drop(columns=['month', 'day', 'time'], errors='ignore')
        st.dataframe(ip_specific_df.sort_values(by='datetime', ascending=False).reset_index(drop=True), height=500)

    st.subheader("Access Pattern Visualizations")
    def draw_pie(counts, title):
        if len(counts) > 10:
            top_10 = counts.nlargest(10)
            others_sum = counts.drop(top_10.index).sum()
            top_10["Others"] = others_sum
        else:
            top_10 = counts
        return px.pie(top_10.reset_index(), names=top_10.index.name or "index", values=top_10.values, title=title)

    col1, col2, col3 = st.columns(3)
    with col1:
        access_by_hour = ip_specific_df['datetime'].dt.hour.value_counts().sort_index()
        access_by_hour.index = access_by_hour.index.map(lambda h: f"{h:02d}:00")
        st.plotly_chart(draw_pie(access_by_hour, "Access by Hour"), use_container_width=False)
    with col2:
        st.plotly_chart(draw_pie(ip_specific_df['event'].value_counts(), "Event Type Distribution"), use_container_width=False)
    with col3:
        st.plotly_chart(draw_pie(ip_specific_df['user'].value_counts(), "Top Users Attempted"), use_container_width=False)

    st.subheader("IP Classification Estimate")
    ip_type_data = ip_data['ip_type_profile']
    type_df = pd.DataFrame({'Category': list(ip_type_data.keys()), 'Probability': list(ip_type_data.values())})
    fig_type = px.pie(type_df, names='Category', values='Probability', width=400, height=400)
    st.plotly_chart(fig_type, use_container_width=False)
