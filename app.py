import streamlit as st
import pandas as pd
from datetime import date, datetime, time, timedelta
import os
import io
import zipfile
import logging
import urllib.parse
import re
import shutil
import pytz # Biblioteca de Fuso Horário
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors

# --- CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(page_title="Gestão Psicologia", page_icon="🧠", layout="wide")

# ==============================================================================
# 🔒 SISTEMA DE LOGIN
# ==============================================================================
def check_password():
    def password_entered():
        if st.session_state["password"] == st.secrets["password"]:
            st.session_state["password_correct"] = True
            del st.session_state["password"]
        else:
            st.session_state["password_correct"] = False

    if st.session_state.get("password_correct", False):
        return True

    st.title("🔒 Acesso Restrito - Consultório")
    st.text_input("Digite a senha:", type="password", key="password", on_change=password_entered)
    if "password_correct" in st.session_state:
        st.error("Senha incorreta.")
    return False

# Comente a linha abaixo apenas para testes locais
if not check_password():
    st.stop()

# ==============================================================================
# CONFIGURAÇÕES
# ==============================================================================
ARQUIVO_LOG = "system_errors.log"
ARQUIVO_AGENDAMENTOS = "banco_dados_agendamentos.csv"
ARQUIVO_PACIENTES = "banco_dados_pacientes.csv"
CHAVE_PIX = "SEU_CPF_OU_CNPJ"

# Configuração de Fuso Horário (Brasil)
TZ_BR = pytz.timezone('America/Sao_Paulo')

OPCOES_STATUS = ["📅 Agendado", "✅ Realizado", "❌ Cancelado", "⚠️ Falta"]
OPCOES_PAGAMENTO = ["PIX", "CARTÃO", "DINHEIRO", "CONVÊNIO", "PENDENTE"]
TIPOS_SERVICO = [
    "Consulta em Neuropsicologia",
    "Consulta em Psicoterapia",
    "Sessão de Psicoterapia",
    "Avaliação Neuropsicológica",
    "Pacote Mensal" # Nova opção
]

VERSAO = "Psi 1.1 (Timezone BR)"

logging.basicConfig(filename=ARQUIVO_LOG, level=logging.ERROR, format='%(asctime)s | %(levelname)s | %(message)s', force=True)
logger = logging.getLogger("clinica")

# ==============================================================================
# FUNÇÕES AUXILIARES
# ==============================================================================
def get_data_hora_atual():
    """Retorna data e hora atuais no fuso do Brasil."""
    return datetime.now(TZ_BR)

def limpar_telefone(telefone):
    if not telefone: return ""
    return re.sub(r'\D', '', str(telefone))

def validar_telefone(telefone):
    limpo = limpar_telefone(telefone)
    if not limpo: return "", None
    if limpo.startswith("55") and len(limpo) > 11: limpo = limpo[2:]
    if len(limpo) < 10 or len(limpo) > 11: return limpo, "⚠️ Telefone inválido."
    return limpo, None

def limpar_hora_rigoroso(h):
    try:
        if h in [None, "", "nan", "NaT"] or pd.isna(h): return None
        if isinstance(h, time): return h
        hs = str(h).strip()
        for fmt in ("%H:%M", "%H:%M:%S"):
            try: return datetime.strptime(hs, fmt).time()
            except: pass
        t = pd.to_datetime(hs, errors='coerce')
        if not pd.isna(t): return t.time()
        return None
    except: return None

def gerar_id_sequencial(df):
    try:
        if df.empty: return 1
        df = df.copy()
        df['ID_Agendamento'] = pd.to_numeric(df['ID_Agendamento'], errors='coerce').fillna(0).astype(int)
        return int(df['ID_Agendamento'].max()) + 1
    except: return 1

# ==============================================================================
# BANCO DE DADOS
# ==============================================================================
def carregar_pacientes():
    colunas = ["Nome", "Contato", "Observacoes"]
    if not os.path.exists(ARQUIVO_PACIENTES): return pd.DataFrame(columns=colunas)
    try:
        df = pd.read_csv(ARQUIVO_PACIENTES, dtype=str).fillna("")
        for c in colunas:
            if c not in df.columns: df[c] = ""
        return df[colunas]
    except Exception as e:
        logger.error(f"Erro carregar pacientes: {e}")
        return pd.DataFrame(columns=colunas)

def carregar_agendamentos():
    colunas_padrao = ["ID_Agendamento", "Paciente", "Servico", "Valor", "Data", "Hora", "Status", "Pagamento", "Contato", "Desconto", "Observacoes"]
    if not os.path.exists(ARQUIVO_AGENDAMENTOS): return pd.DataFrame(columns=colunas_padrao)
    try:
        df = pd.read_csv(ARQUIVO_AGENDAMENTOS)
        for c in colunas_padrao:
            if c not in df.columns: df[c] = None
        
        df["Data"] = pd.to_datetime(df["Data"], errors="coerce").dt.date
        df["Hora"] = df["Hora"].apply(limpar_hora_rigoroso)
        
        for col in ["Valor", "Desconto"]:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
            
        df['ID_Agendamento'] = pd.to_numeric(df['ID_Agendamento'], errors='coerce').fillna(0).astype(int)
        
        if df['ID_Agendamento'].duplicated().any() or (not df.empty and df['ID_Agendamento'].max() == 0):
             df['ID_Agendamento'] = range(1, len(df) + 1)
        
        for c in ["Paciente", "Servico", "Status", "Pagamento", "Contato", "Observacoes"]:
            df[c] = df[c].fillna("").astype(str)
            
        return df[colunas_padrao]
    except Exception as e:
        logger.error(f"Erro carregar agendamentos: {e}")
        return pd.DataFrame(columns=colunas_padrao)

def salvar_agendamentos(df):
    try:
        if os.path.exists(ARQUIVO_AGENDAMENTOS):
            shutil.copy(ARQUIVO_AGENDAMENTOS, ARQUIVO_AGENDAMENTOS + ".bak")
        
        salvar = df.copy()
        salvar['Data'] = salvar['Data'].apply(lambda x: x.strftime('%Y-%m-%d') if hasattr(x, 'strftime') else x)
        salvar['Hora'] = salvar['Hora'].apply(lambda x: x.strftime('%H:%M') if isinstance(x, time) else str(x))
        salvar.to_csv(ARQUIVO_AGENDAMENTOS, index=False)
        return True
    except Exception as e:
        logger.error(f"Erro salvar agendamentos: {e}")
        return False

def salvar_pacientes(df):
    try:
        if os.path.exists(ARQUIVO_PACIENTES):
            shutil.copy(ARQUIVO_PACIENTES, ARQUIVO_PACIENTES + ".bak")
        df.to_csv(ARQUIVO_PACIENTES, index=False)
        return True
    except Exception as e:
        logger.error(f"Erro salvar pacientes: {e}")
        return False

# ==============================================================================
# PDF (RECIBO CLÍNICO)
# ==============================================================================
def desenhar_cabecalho(p, titulo):
    if os.path.exists("logo.png"):
        try: p.drawImage("logo.png", 30, 750, width=100, height=50, mask='auto', preserveAspectRatio=True)
        except: pass
    p.setFont("Helvetica-Bold", 14)
    p.drawString(150, 775, "CONSULTÓRIO DE PSICOLOGIA")
    p.setFont("Helvetica", 10)
    p.drawString(150, 760, "Neuropsicologia e Psicoterapia")
    p.line(30, 740, 565, 740)

def gerar_recibo_pdf(dados):
    try:
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4)
        
        id_p = dados.get('ID_Agendamento', 'NOVO')
        desenhar_cabecalho(p, f"Recibo #{id_p}")

        y = 700
        p.setFont("Helvetica-Bold", 12)
        p.drawString(30, y, "RECIBO DE PAGAMENTO")
        y -= 30
        
        p.setFont("Helvetica", 12)
        texto_recibo = f"Recebi de {dados.get('Paciente', '')}"
        p.drawString(30, y, texto_recibo)
        y -= 20
        
        valor = float(dados.get('Valor', 0))
        p.drawString(30, y, f"A importância de R$ {valor:,.2f}")
        y -= 20
        
        p.drawString(30, y, f"Referente a: {dados.get('Servico', 'Serviços de Psicologia')}")
        y -= 20
        
        dt = dados.get('Data')
        dt_s = dt.strftime('%d/%m/%Y') if hasattr(dt, 'strftime') else str(dt)
        p.drawString(30, y, f"Data do atendimento: {dt_s}")
        
        # Assinatura
        y_ass = 150
        p.line(150, y_ass, 450, y_ass)
        p.setFont("Helvetica", 10)
        p.drawCentredString(300, y_ass - 15, "Assinatura do Profissional")
        p.setFont("Helvetica-Oblique", 8)
        
        # Data do documento (Hoje no Brasil)
        hoje_br = get_data_hora_atual().strftime('%d/%m/%Y')
        p.drawCentredString(300, y_ass - 30, f"Emitido em: {hoje_br}")
        
        p.showPage()
        p.save()
        buffer.seek(0)
        return buffer
    except: return None

# ==============================================================================
# INICIALIZAÇÃO
# ==============================================================================
if 'agendamentos' not in st.session_state: st.session_state.agendamentos = carregar_agendamentos()
if 'pacientes' not in st.session_state: st.session_state.pacientes = carregar_pacientes()

with st.sidebar:
    if os.path.exists("logo.png"): st.image("logo.png", width=250)
    st.title("Gestão Psi")
    st.divider()
    menu = st.radio("Menu Principal", ["Dashboard", "Novo Agendamento", "Agenda Completa", "Emitir Recibos", "Pacientes", "Configurações"])
    st.divider()
    
    # Resumo do dia (com Fuso Horário correto)
    hj = get_data_hora_atual().date()
    df_hj = st.session_state.agendamentos[st.session_state.agendamentos['Data'] == hj]
    if not df_hj.empty:
        qtd = len(df_hj)
        st.info(f"📅 Hoje ({hj.strftime('%d/%m')}): {qtd} atendimentos")

# ==============================================================================
# PÁGINAS
# ==============================================================================

# --- DASHBOARD ---
if menu == "Dashboard":
    st.title("📊 Painel do Consultório")
    
    df = st.session_state.agendamentos
    if df.empty:
        st.info("Nenhum agendamento registrado.")
    else:
        col1, col2 = st.columns(2)
        with col1:
            dt_filter = st.date_input("Filtrar Data:", get_data_hora_atual().date())
        
        df_dia = df[df['Data'] == dt_filter].copy()
        
        c1, c2, c3 = st.columns(3)
        agendados = len(df_dia[df_dia['Status'] == '📅 Agendado'])
        realizados = len(df_dia[df_dia['Status'] == '✅ Realizado'])
        fat_dia = df_dia['Valor'].sum()
        
        c1.metric("Agendados", agendados)
        c2.metric("Realizados", realizados)
        c3.metric("Faturamento Dia", f"R$ {fat_dia:,.2f}")
        
        st.divider()
        st.subheader(f"Agenda de {dt_filter.strftime('%d/%m/%Y')}")
        
        if not df_dia.empty:
            try:
                df_dia['h_sort'] = df_dia['Hora'].apply(lambda x: x if isinstance(x, time) else time(23,59))
                df_dia = df_dia.sort_values('h_sort')
            except: pass

            edited = st.data_editor(
                df_dia,
                column_order=["Hora", "Paciente", "Servico", "Status", "Valor", "Observacoes"],
                disabled=["Paciente", "Servico", "Valor", "Hora"],
                hide_index=True,
                use_container_width=True,
                key="dash_editor",
                column_config={
                    "Status": st.column_config.SelectboxColumn(options=OPCOES_STATUS, required=True),
                    "Hora": st.column_config.TimeColumn(format="HH:mm"),
                    "Valor": st.column_config.NumberColumn(format="R$ %.2f")
                }
            )
            
            if not edited.equals(df_dia):
                df_glob = st.session_state.agendamentos.copy()
                for i in edited.index:
                    idp = edited.at[i, 'ID_Agendamento']
                    mask = df_glob['ID_Agendamento'] == idp
                    if mask.any():
                        df_glob.loc[mask, ['Status', 'Observacoes']] = edited.loc[i, ['Status', 'Observacoes']].values
                st.session_state.agendamentos = df_glob
                salvar_agendamentos(df_glob)
                st.toast("Agenda atualizada!")
                st.rerun()
        else:
            st.info("Agenda livre.")

# --- NOVO AGENDAMENTO ---
elif menu == "Novo Agendamento":
    st.title("🗓️ Novo Agendamento")
    
    if st.session_state.get('reset_form', False):
        st.session_state.idx_pac = 0
        st.session_state.reset_form = False
    if 'idx_pac' not in st.session_state: st.session_state.idx_pac = 0
    
    try: pacs = sorted(st.session_state.pacientes['Nome'].unique())
    except: pacs = []
    lista_pacs = ["-- Selecione --"] + pacs
    
    c1, c2 = st.columns([3, 1])
    with c1:
        pac_sel = st.selectbox("Paciente", lista_pacs, index=st.session_state.idx_pac, key="sel_pac")
    with c2:
        hora_sel = st.time_input("Horário", value=time(8, 0))
    
    if pac_sel in lista_pacs: st.session_state.idx_pac = lista_pacs.index(pac_sel)
    
    contato_auto = ""
    if pac_sel and pac_sel != "-- Selecione --":
        res = st.session_state.pacientes[st.session_state.pacientes['Nome'] == pac_sel]
        if not res.empty: contato_auto = res.iloc[0]['Contato']

    with st.form("form_agenda", clear_on_submit=False):
        c1, c2 = st.columns(2)
        with c1:
            dt = st.date_input("Data", min_value=get_data_hora_atual().date())
        with c2:
            servico = st.selectbox("Tipo de Serviço", TIPOS_SERVICO, key="f_servico")
        
        # LÓGICA DE VALOR DO PACOTE
        c3, c4 = st.columns(2)
        with c3:
            desc = st.number_input("Desconto (%)", 0, 100, 0, step=5, key="f_desc")
        
        # Se for pacote, libera o campo de valor manual
        # Se não, calcula automático
        valor_manual = 0.0
        usar_valor_manual = False
        
        if servico == "Pacote Mensal":
            usar_valor_manual = True
            with c4:
                valor_manual = st.number_input("Valor do Pacote (R$)", min_value=0.0, step=50.0, value=600.0)
                st.caption("Defina o valor total do pacote.")
        else:
            with c4:
                # Calcula automático para serviços padrão
                if servico == "Avaliação Neuropsicológica": base = 2500.00
                else: base = 150.00
                val_calc = base * (1 - desc/100)
                st.metric("Valor da Sessão", f"R$ {val_calc:.2f}")

        obs = st.text_area("Observações", key="f_obs")
        
        submitted = st.form_submit_button("💾 Agendar Sessão", type="primary", use_container_width=True)
        
        if submitted:
            if not pac_sel or pac_sel == "-- Selecione --":
                st.error("Selecione um paciente.")
            else:
                try:
                    df_a = st.session_state.agendamentos
                    nid = gerar_id_sequencial(df_a)
                    
                    # Define valor final
                    if usar_valor_manual:
                        valor_final = valor_manual * (1 - desc/100) # Aplica desconto no pacote também se quiser
                    else:
                        if servico == "Avaliação Neuropsicológica": base = 2500.00
                        else: base = 150.00
                        valor_final = base * (1 - desc/100)

                    novo = {
                        "ID_Agendamento": nid,
                        "Paciente": pac_sel,
                        "Servico": servico,
                        "Valor": valor_final,
                        "Data": dt,
                        "Hora": hora_sel.strftime("%H:%M"),
                        "Status": "📅 Agendado",
                        "Pagamento": "PENDENTE",
                        "Contato": contato_auto,
                        "Desconto": desc,
                        "Observacoes": obs
                    }
                    
                    df_novo = pd.DataFrame([novo])
                    df_novo['Data'] = pd.to_datetime(df_novo['Data']).dt.date
                    
                    st.session_state.agendamentos = pd.concat([df_a, df_novo], ignore_index=True)
                    salvar_agendamentos(st.session_state.agendamentos)
                    
                    st.success("Agendamento realizado!")
                    st.session_state.reset_form = True
                    st.session_state.f_obs = ""
                    st.rerun()
                except Exception as e:
                    st.error(f"Erro ao salvar: {e}")

# --- AGENDA COMPLETA ---
elif menu == "Agenda Completa":
    st.title("📂 Histórico e Agenda")
    df = st.session_state.agendamentos
    
    if df.empty:
        st.info("Nenhum registro.")
    else:
        with st.expander("🔍 Filtros Avançados", expanded=False):
            c1, c2 = st.columns(2)
            with c1:
                f_status = st.multiselect("Status", OPCOES_STATUS, default=OPCOES_STATUS)
            with c2:
                f_pac = st.multiselect("Paciente", sorted(df['Paciente'].unique()))
                
        df_view = df.copy()
        if f_status: df_view = df_view[df_view['Status'].isin(f_status)]
        if f_pac: df_view = df_view[df_view['Paciente'].isin(f_pac)]
        
        df_view = df_view.sort_values("Data", ascending=False)
        
        edited = st.data_editor(
            df_view,
            num_rows="dynamic",
            use_container_width=True,
            hide_index=True,
            column_config={
                "ID_Agendamento": st.column_config.NumberColumn("#", disabled=True, width="small"),
                "Valor": st.column_config.NumberColumn(format="R$ %.2f"),
                "Data": st.column_config.DateColumn(format="DD/MM/YYYY"),
                "Hora": st.column_config.TimeColumn(format="HH:mm"),
                "Status": st.column_config.SelectboxColumn(options=OPCOES_STATUS, required=True),
                "Pagamento": st.column_config.SelectboxColumn(options=OPCOES_PAGAMENTO, required=True),
                "Servico": st.column_config.SelectboxColumn(options=TIPOS_SERVICO, required=True)
            }
        )
        
        if not edited.equals(df_view):
            try:
                df_master = st.session_state.agendamentos.copy()
                for idx in edited.index:
                    id_ag = edited.at[idx, 'ID_Agendamento']
                    mask = df_master['ID_Agendamento'] == id_ag
                    if mask.any():
                        for col in edited.columns:
                            if col != 'ID_Agendamento':
                                df_master.loc[mask, col] = edited.at[idx, col]
                
                st.session_state.agendamentos = df_master
                salvar_agendamentos(df_master)
                st.toast("Salvo!", icon="💾")
            except:
                st.error("Erro ao salvar edição.")

# --- EMITIR RECIBOS ---
elif menu == "Emitir Recibos":
    st.title("🖨️ Recibos e Documentos")
    df = st.session_state.agendamentos
    
    if df.empty:
        st.warning("Sem atendimentos registrados.")
    else:
        paciente = st.selectbox("Selecione o Paciente:", sorted(df['Paciente'].unique()))
        atendimentos = df[df['Paciente'] == paciente].sort_values("Data", ascending=False)
        
        if not atendimentos.empty:
            opcoes = {
                i: f"{r['Data'].strftime('%d/%m/%Y')} - {r['Servico']} (R$ {r['Valor']:.2f})"
                for i, r in atendimentos.iterrows()
            }
            
            sel_id = st.selectbox("Selecione o atendimento:", options=opcoes.keys(), format_func=lambda x: opcoes[x])
            
            if st.button("📄 Gerar Recibo PDF", type="primary"):
                dados = atendimentos.loc[sel_id]
                pdf = gerar_recibo_pdf(dados.to_dict())
                if pdf:
                    st.download_button(
                        label="⬇️ Baixar Recibo",
                        data=pdf,
                        file_name=f"Recibo_{paciente}.pdf",
                        mime="application/pdf"
                    )
                else:
                    st.error("Erro ao gerar PDF.")

# --- PACIENTES ---
elif menu == "Pacientes":
    st.title("👥 Cadastro de Pacientes")
    t1, t2 = st.tabs(["Novo Paciente", "Base de Dados"])
    
    with t1:
        with st.form("form_paciente", clear_on_submit=True):
            nome = st.text_input("Nome Completo")
            zap = st.text_input("WhatsApp / Contato")
            obs = st.text_area("Histórico / Observações Iniciais")
            
            if st.form_submit_button("Salvar Paciente"):
                if not nome:
                    st.error("Nome é obrigatório.")
                else:
                    if nome in st.session_state.pacientes['Nome'].values:
                        st.warning("Paciente já cadastrado.")
                    else:
                        zap_limpo = limpar_telefone(zap)
                        novo = pd.DataFrame([{"Nome": nome, "Contato": zap_limpo, "Observacoes": obs}])
                        st.session_state.pacientes = pd.concat([st.session_state.pacientes, novo], ignore_index=True)
                        salvar_pacientes(st.session_state.pacientes)
                        st.success("Cadastrado com sucesso!")
                        st.rerun()
    
    with t2:
        if not st.session_state.pacientes.empty:
            edited = st.data_editor(st.session_state.pacientes, num_rows="dynamic", use_container_width=True)
            if not edited.equals(st.session_state.pacientes):
                st.session_state.pacientes = edited
                salvar_pacientes(edited)
                st.toast("Lista de pacientes salva!")

# --- CONFIGURAÇÕES / BACKUP ---
elif menu == "Configurações":
    st.title("⚙️ Sistema e Backup")
    c1, c2 = st.columns(2)
    with c1:
        st.write("### 📦 Backup de Segurança")
        try:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "a", zipfile.ZIP_DEFLATED, False) as z:
                z.writestr("agendamentos.csv", st.session_state.agendamentos.to_csv(index=False))
                z.writestr("pacientes.csv", st.session_state.pacientes.to_csv(index=False))
            st.download_button("📥 Baixar Backup (ZIP)", buf.getvalue(), f"backup_clinica_{date.today()}.zip", "application/zip")
        except:
            st.error("Erro ao gerar backup.")
            
    with c2:
        st.write("### ⚠️ Restauração")
        up = st.file_uploader("Restaurar Agendamentos (CSV)", type="csv")
        if up and st.button("Restaurar"):
            try:
                df = pd.read_csv(up)
                salvar_agendamentos(df)
                st.session_state.agendamentos = carregar_agendamentos()
                st.success("Restaurado!")
                st.rerun()
            except: st.error("Erro ao restaurar.")