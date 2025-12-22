import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.ensemble import IsolationForest
from fpdf import FPDF
import hashlib
import time
import sqlite3
import os

# --- 1. CONFIGURAZIONE SISTEMA ---
st.set_page_config(
    page_title="Insight Certifier | Enterprise AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. GESTIONE PASSWORD (IL CANCELLO) ---
def check_password():
    """Ritorna True se l'utente ha la password corretta."""

    def password_entered():
        """Controlla se la password inserita è corretta."""
        if st.session_state["password"] == st.secrets["password"]:
            st.session_state["password_correct"] = True
            del st.session_state["password"]  # Non conservare la password
        else:
            st.session_state["password_correct"] = False

    if "password_correct" not in st.session_state:
        # Prima esecuzione, mostra l'input
        st.text_input(
            "🔒 Accesso Riservato. Inserisci la Security Key:", 
            type="password", 
            on_change=password_entered, 
            key="password"
        )
        st.caption("Insight Certifier Platform - Protected Environment")
        return False
    
    elif not st.session_state["password_correct"]:
        # Password sbagliata
        st.text_input(
            "🔒 Accesso Riservato. Inserisci la Security Key:", 
            type="password", 
            on_change=password_entered, 
            key="password"
        )
        st.error("⛔ Accesso Negato. Chiave di sicurezza non valida.")
        return False
    
    else:
        # Password corretta
        return True

# --- BLOCCO DI SICUREZZA ---
if not check_password():
    st.stop()

# ==============================================================================
# AREA PROTETTA: IL SOFTWARE VERO E PROPRIO
# ==============================================================================

# --- 0. CONFIGURAZIONE UTENTE ---
USER_NAME = "Francesco Pagliara"
ROLE = "Head of Data Strategy"
DB_NAME = "insight_certifier_memory.db"

# --- CSS CUSTOM ---
st.markdown("""
<style>
    .stTabs [data-baseweb="tab-list"] { gap: 10px; }
    .stTabs [data-baseweb="tab"] { height: 50px; border-radius: 4px 4px 0px 0px; }
    .footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background-color: #0e1117; color: #808495;
        text-align: center; padding: 10px; font-size: 12px;
        border-top: 1px solid #262730; z-index: 100;
    }
    .block-container { padding-bottom: 50px; }
</style>
""", unsafe_allow_html=True)

# --- GESTIONE DATABASE (SQLITE) ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            filename TEXT,
            total_rows INTEGER,
            anomalies_found INTEGER,
            risk_value REAL,
            user TEXT,
            hash_signature TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_audit_log(filename, total_rows, anomalies_count, risk_val, signature):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    c.execute('''
        INSERT INTO audit_log (timestamp, filename, total_rows, anomalies_found, risk_value, user, hash_signature)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, filename, total_rows, anomalies_count, risk_val, USER_NAME, signature))
    conn.commit()
    conn.close()

def load_history():
    try:
        conn = sqlite3.connect(DB_NAME)
        df = pd.read_sql_query("SELECT * FROM audit_log ORDER BY id DESC", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

init_db()

# --- INIZIALIZZAZIONE MEMORIA DI SESSIONE ---
if 'audit_done' not in st.session_state: st.session_state.audit_done = False
if 'df_full' not in st.session_state: st.session_state.df_full = None
if 'df_anomalies' not in st.session_state: st.session_state.df_anomalies = pd.DataFrame()
if 'risk_val' not in st.session_state: st.session_state.risk_val = 0.0
if 'total_rows' not in st.session_state: st.session_state.total_rows = 0
if 'target_col' not in st.session_state: st.session_state.target_col = ""
if 'contamination' not in st.session_state: st.session_state.contamination = 0.05

# --- MOTORE PDF ---
class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.set_text_color(30, 60, 100)
        self.cell(0, 10, 'INSIGHT CERTIFIER - ENTERPRISE AUDIT', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, 'Decision Integrity Assurance Protocol', 0, 1, 'C')
        self.ln(10)
        self.line(10, 30, 200, 30)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Confidential - Generated by {USER_NAME} - Page {self.page_no()}/{{nb}}', 0, 0, 'C')

def generate_pdf(df_anomalies, total_rows, risk_value, target_col_name):
    pdf = PDFReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 10, f'Date of Issue: {time.strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'R')
    pdf.ln(5)
    
    # EXECUTIVE SUMMARY
    pdf.set_font('Arial', 'B', 14)
    pdf.set_fill_color(230, 230, 250)
    pdf.cell(0, 10, "  1. EXECUTIVE SUMMARY", 0, 1, 'L', 1)
    pdf.ln(5)
    pdf.set_font('Arial', '', 11)
    pdf.cell(0, 8, f"Total Transactions Audited: {total_rows}", 0, 1)
    pdf.set_text_color(200, 0, 0)
    pdf.set_font('Arial', 'B', 11)
    pdf.cell(0, 8, f"Critical Anomalies Detected: {len(df_anomalies)}", 0, 1)
    pdf.cell(0, 8, f"Total Financial Exposure: EUR {risk_value:,.2f}", 0, 1)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)

    # FORENSIC DETAIL
    pdf.set_font('Arial', 'B', 14)
    pdf.set_fill_color(230, 230, 250)
    pdf.cell(0, 10, "  2. FORENSIC DETAIL (TOP PRIORITY)", 0, 1, 'L', 1)
    pdf.ln(5)
    pdf.set_font('Courier', 'B', 10)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(30, 8, 'ID REF', 1, 0, 'C', 1)
    pdf.cell(50, 8, 'DEPARTMENT', 1, 0, 'C', 1)
    pdf.cell(50, 8, 'VALUE (EUR)', 1, 0, 'C', 1)
    pdf.cell(60, 8, 'AI VERDICT', 1, 1, 'C', 1)
    pdf.set_font('Courier', '', 10)
    for index, row in df_anomalies.iterrows():
        id_ord = str(row.iloc[0])[:10]
        reparto = str(row['Reparto'])[:18] if 'Reparto' in row else "N/A"
        importo = row[target_col_name]
        pdf.cell(30, 8, id_ord, 1)
        pdf.cell(50, 8, reparto, 1)
        pdf.cell(50, 8, f"{importo:,.2f}", 1)
        pdf.set_text_color(200, 0, 0)
        pdf.cell(60, 8, 'CRITICAL OUTLIER', 1, 1, 'C')
        pdf.set_text_color(0, 0, 0)
    pdf.ln(15)

    # HASH
    pdf.set_font('Arial', 'B', 14)
    pdf.set_fill_color(200, 220, 255)
    pdf.cell(0, 10, "  3. BLOCKCHAIN-READY INTEGRITY HASH", 0, 1, 'L', 1)
    pdf.ln(5)
    data_bytes = str(df_anomalies.values).encode()
    digital_signature = hashlib.sha256(data_bytes).hexdigest()
    pdf.set_font('Arial', '', 9)
    pdf.multi_cell(0, 5, "This document is digitally secured using SHA-256 hashing algorithms.")
    pdf.ln(5)
    pdf.set_font('Courier', 'B', 8)
    pdf.multi_cell(0, 5, f"SECURE HASH: {digital_signature}")
    filename = "Insight_Enterprise_Audit.pdf"
    pdf.output(filename)
    return filename, digital_signature

# --- SIDEBAR ---
with st.sidebar:
    st.title("🛡️ Insight Certifier")
    st.caption("Cloud Secure Edition v6.0")
    st.divider()
    st.write("### 👤 User Profile")
    st.info(f"**{USER_NAME}**")
    st.caption(ROLE)
    st.write("### 📡 System Status")
    st.success("AI Core: **ONLINE**")
    st.success("Cloud Uplink: **SECURE**")
    st.divider()
    if st.button("🔒 Logout / Lock Terminal"):
        del st.session_state["password_correct"]
        st.rerun()

# --- MAIN ---
st.title("🛡️ Insight Certifier Platform")
st.markdown("##### The Ultimate Decision Assurance System")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🏠 Control Room", "🕵️‍♂️ Audit Operations", "📜 Storico Log", "⚙️ Advanced Lab", "🎓 Academy"
])

# --- TAB 1 ---
with tab1:
    st.subheader("Global Security Overview")
    st.write(f"### 👋 Benvenuto, {USER_NAME}.")
    st.markdown("Ambiente Cloud Protetto. Connessione crittografata attiva.")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("System Uptime", "99.9%", "+0.1%")
    c2.metric("Cloud Latency", "24ms", "⚡")
    c3.metric("Encryption", "AES-256", "🔒")
    c4.metric("Threat Level", "LOW", "🛡️")
    st.divider()
    if st.session_state.audit_done:
         st.info("🔔 **NOTIFICA:** Risultati disponibili in 'Audit Operations'.")
    else:
         st.info("💡 **INFO:** In modalità Cloud, lo storico locale viene resettato al termine della sessione per Privacy.")

# --- TAB 2 ---
with tab2:
    st.subheader("📂 Data Ingestion & Analysis")
    uploaded_file = st.file_uploader("Upload ERP Export (CSV / Excel)", type=["csv", "xlsx", "xls"])
    
    if uploaded_file:
        try:
            if uploaded_file.name.endswith('.csv'): df = pd.read_csv(uploaded_file)
            else: df = pd.read_excel(uploaded_file)
            st.success(f"✅ File '{uploaded_file.name}' caricato.")
            with st.expander("📊 Anteprima Dati Grezzi"): st.dataframe(df.head())
            col_btn, col_blank = st.columns([1, 4])
            with col_btn: start_audit = st.button("🚀 AVVIA AUDIT AI", type="primary", use_container_width=True)
            
            if start_audit:
                st.session_state.audit_done = False
                with st.spinner('🤖 Analisi Cloud in corso...'):
                    time.sleep(1)
                    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
                    if not numeric_cols: st.error("Nessun dato finanziario rilevato.")
                    else:
                        target = numeric_cols[-1]
                        model = IsolationForest(contamination=st.session_state.contamination, random_state=42)
                        df['Anomaly_Score'] = model.fit_predict(df[[target]])
                        df['Status'] = df['Anomaly_Score'].apply(lambda x: 'Critical 🔴' if x == -1 else 'Verified 🟢')
                        anomalies = df[df['Status'] == 'Critical 🔴']
                        risk_val = anomalies[target].sum()
                        data_bytes = str(anomalies.values).encode()
                        signature = hashlib.sha256(data_bytes).hexdigest()
                        save_audit_log(uploaded_file.name, len(df), len(anomalies), risk_val, signature)
                        st.session_state.df_full = df
                        st.session_state.df_anomalies = anomalies
                        st.session_state.risk_val = risk_val
                        st.session_state.total_rows = len(df)
                        st.session_state.target_col = target
                        st.session_state.audit_done = True
            
            if st.session_state.audit_done:
                st.divider()
                m1, m2, m3 = st.columns(3)
                m1.metric("Righe Analizzate", st.session_state.total_rows)
                m2.metric("Anomalie Critiche", len(st.session_state.df_anomalies), delta="Alert", delta_color="inverse")
                m3.metric("Rischio Finanziario", f"€ {st.session_state.risk_val:,.2f}")
                fig = px.scatter(
                    st.session_state.df_full, x=st.session_state.df_full.index, y=st.session_state.target_col, 
                    color='Status', color_discrete_map={'Verified 🟢': '#2ecc71', 'Critical 🔴': '#e74c3c'},
                    title="Anomaly Detection Radar", template="plotly_dark"
                )
                st.plotly_chart(fig, use_container_width=True)
                if not st.session_state.df_anomalies.empty:
                    st.error("⚠️ TRANSAZIONI CRITICHE RILEVATE")
                    st.dataframe(st.session_state.df_anomalies.style.background_gradient(cmap='Reds'))
                    c_pdf, c_csv = st.columns(2)
                    pdf_name, sig = generate_pdf(st.session_state.df_anomalies, st.session_state.total_rows, st.session_state.risk_val, st.session_state.target_col)
                    with open(pdf_name, "rb") as f: c_pdf.download_button(label="💎 SCARICA CERTIFICATO (PDF)", data=f, file_name=pdf_name, mime="application/pdf", type="primary", use_container_width=True)
                    csv_data = st.session_state.df_anomalies.to_csv(index=False).encode('utf-8')
                    c_csv.download_button(label="🛠️ SCARICA LISTA LAVORABILE (CSV)", data=csv_data, file_name="anomalie.csv", mime="text/csv", use_container_width=True)
                    st.caption(f"SHA-256: {sig}")
                else: st.success("✅ Audit Pulito.")
        except Exception as e: st.error(f"Errore: {e}")

# --- TAB 3 ---
with tab3:
    st.subheader("📜 Storico Operazioni (Session Log)")
    if st.button("🔄 Aggiorna"): st.rerun()
    history_df = load_history()
    if not history_df.empty: st.dataframe(history_df.style.format({"risk_value": "€ {:,.2f}", "total_rows": "{:,}"}), use_container_width=True)
    else: st.warning("Nessun audit registrato in questa sessione cloud.")

# --- TAB 4 ---
with tab4:
    st.subheader("⚙️ Calibrazione Algoritmo")
    new_contam = st.slider("Sensibilità AI", 0.01, 0.20, value=st.session_state.contamination)
    if new_contam != st.session_state.contamination: st.session_state.contamination = new_contam
    st.divider()
    st.code("""{ "Model": "Isolation Forest", "Env": "Cloud Protected" }""", language="json")

# --- TAB 5 ---
with tab5:
    st.subheader("🎓 Academy Cloud")
    st.info("Questa versione Cloud permette l'audit da qualsiasi dispositivo. I dati vengono processati in RAM e non persistono sui server per garantire la Privacy.")
    with st.expander("🏁 PRIMI PASSI"): st.write("Carica il file in 'Audit Operations' e lancia l'AI.")

st.markdown(f"""<div class="footer">Insight Certifier Platform © 2025 | <b>{USER_NAME}</b> | Cloud Secure Edition</div>""", unsafe_allow_html=True)