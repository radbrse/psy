import streamlit as st
import pandas as pd
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo
import os
import io
import logging
import urllib.parse
import re
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm

# --- CONFIGURAÇÃO DE FUSO HORÁRIO (BRASIL) ---
FUSO_BRASIL = ZoneInfo("America/Sao_Paulo")

def agora_brasil():
    """Retorna datetime atual no fuso horário de Brasília."""
    return datetime.now(FUSO_BRASIL)

def hoje_brasil():
    """Retorna a data de hoje no fuso horário de Brasília."""
    return datetime.now(FUSO_BRASIL).date()

# --- CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(
    page_title="Agenda Psicologia - Dr. Radamés", 
    page_icon="🧠", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configurar localização para pt-BR
import locale
try:
    locale.setlocale(locale.LC_TIME, 'pt_BR.UTF-8')
except:
    try:
        locale.setlocale(locale.LC_TIME, 'Portuguese_Brazil.1252')
    except:
        pass  # Usa padrão do sistema

# CSS Customizado - Tema Profissional Psicologia
st.markdown("""
<style>
    /* Paleta de cores profissional */
    :root {
        --primary-color: #2C5F7C;
        --secondary-color: #5D9BB8;
        --accent-color: #7FB3D5;
        --success-color: #6AA84F;
        --warning-color: #F6B26B;
        --danger-color: #CC4125;
        --light-bg: #F8F9FA;
    }
    
    /* Cabeçalhos mais sóbrios */
    h1, h2, h3 {
        color: var(--primary-color) !important;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    /* Botões primários */
    .stButton>button[kind="primary"] {
        background-color: var(--primary-color) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.5rem 1rem !important;
        font-weight: 500 !important;
    }
    
    .stButton>button[kind="primary"]:hover {
        background-color: var(--secondary-color) !important;
    }
    
    /* Cards de métricas */
    [data-testid="metric-container"] {
        background-color: var(--light-bg);
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid var(--primary-color);
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background-color: var(--light-bg);
        border-radius: 8px 8px 0 0;
        padding: 0.5rem 1rem;
        color: var(--primary-color);
    }
    
    .stTabs [aria-selected="true"] {
        background-color: var(--primary-color) !important;
        color: white !important;
    }
    
    /* Formulários */
    .stTextInput>div>div>input, .stSelectbox>div>div>select {
        border-radius: 6px;
        border: 1px solid #D0D5DD;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: var(--light-bg);
    }
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# 🔒 SISTEMA DE LOGIN
# ==============================================================================
def check_password():
    def password_entered():
        if st.session_state["password"] == st.secrets.get("password", "psi2025"):
            st.session_state["password_correct"] = True
            del st.session_state["password"]
        else:
            st.session_state["password_correct"] = False

    if st.session_state.get("password_correct", False):
        return True

    st.markdown("## 🔒 Acesso Profissional")
    st.info("Sistema de Agendamentos - Psicologia")
    st.text_input("Digite a senha:", type="password", key="password", on_change=password_entered)
    if "password_correct" in st.session_state:
        st.error("❌ Senha incorreta.")
    return False

# Comente a linha abaixo se for rodar localmente sem senha
if not check_password():
    st.stop()

# ==============================================================================
# CONFIGURAÇÕES
# ==============================================================================
ARQUIVO_LOG = "system_errors_psi.log"
ARQUIVO_AGENDAMENTOS = "banco_agendamentos.csv"
ARQUIVO_PACIENTES = "banco_pacientes.csv"
ARQUIVO_PACOTES = "banco_pacotes.csv"
ARQUIVO_HISTORICO = "historico_alteracoes_psi.csv"

# Serviços e Preços
SERVICOS = {
    "Consulta em Neuropsicologia": 150.00,
    "Consulta em Psicoterapia": 150.00,
    "Psicoterapia": 150.00,
    "Avaliação Neuropsicológica": 2500.00
}

OPCOES_STATUS = ["🔵 Agendado", "🟢 Confirmado", "✅ Realizado", "🟡 Remarcado", "🔴 Cancelado", "⚫ Faltou"]
OPCOES_PAGAMENTO = ["PAGO", "NÃO PAGO", "PACOTE", "CORTESIA"]
VERSAO = "1.0"

# Configuração de Logging
logging.basicConfig(
    filename=ARQUIVO_LOG, 
    level=logging.ERROR, 
    format='%(asctime)s | %(levelname)s | %(message)s', 
    force=True
)
logger = logging.getLogger("agenda_psi")

# ==============================================================================
# FUNÇÕES DE VALIDAÇÃO
# ==============================================================================
def limpar_telefone(telefone):
    """Extrai apenas dígitos do telefone."""
    if not telefone:
        return ""
    return re.sub(r'\D', '', str(telefone))

def validar_telefone(telefone):
    """Valida e formata telefone brasileiro."""
    limpo = limpar_telefone(telefone)
    
    if not limpo:
        return "", None
    
    if limpo.startswith("55") and len(limpo) > 11:
        limpo = limpo[2:]
    
    if len(limpo) in [10, 11]:
        return limpo, None
    elif len(limpo) in [8, 9]:
        return limpo, "⚠️ Falta o DDD no telefone"
    elif len(limpo) > 0:
        return limpo, f"⚠️ Telefone com formato incomum ({len(limpo)} dígitos)"
    
    return "", None

def validar_valor(valor, nome_campo, minimo=0, maximo=10000):
    """Valida valores monetários."""
    try:
        if valor is None or valor == "":
            return 0.0, None
        v = float(str(valor).replace(",", "."))
        if v < minimo:
            return minimo, f"⚠️ {nome_campo} não pode ser menor que {minimo}."
        if v > maximo:
            return maximo, f"⚠️ {nome_campo} limitado a {maximo}."
        return round(v, 2), None
    except:
        return 0.0, f"❌ Valor inválido em {nome_campo}."

def validar_desconto(valor):
    """Valida desconto entre 0 e 100."""
    try:
        if valor is None or valor == "":
            return 0.0, None
        v = float(str(valor).replace(",", "."))
        if v < 0:
            return 0.0, "⚠️ Desconto não pode ser negativo."
        if v > 100:
            return 100.0, "⚠️ Desconto limitado a 100%."
        return round(v, 2), None
    except:
        return 0.0, "❌ Desconto inválido."

def validar_data(data, permitir_passado=False):
    """Valida data."""
    try:
        if data is None:
            return hoje_brasil(), "⚠️ Data não informada. Usando hoje."
        
        if isinstance(data, str):
            data = pd.to_datetime(data).date()
        elif isinstance(data, datetime):
            data = data.date()
        
        hoje = hoje_brasil()
        
        if not permitir_passado and data < hoje:
            return data, "⚠️ Data no passado (permitido para edição)."
        
        limite = hoje.replace(year=hoje.year + 1)
        if data > limite:
            return limite, "⚠️ Data muito distante. Ajustada para 1 ano."
        
        return data, None
    except:
        return hoje_brasil(), "❌ Data inválida. Usando hoje."

def validar_hora(hora):
    """Valida e normaliza hora."""
    try:
        if hora is None or hora == "" or str(hora).lower() in ["nan", "nat", "none"]:
            return time(14, 0), None
        
        if isinstance(hora, time):
            return hora, None
        
        hora_str = str(hora).strip()
        
        for fmt in ["%H:%M", "%H:%M:%S", "%I:%M %p"]:
            try:
                return datetime.strptime(hora_str, fmt).time(), None
            except:
                continue
        
        parsed = pd.to_datetime(hora_str, errors='coerce')
        if not pd.isna(parsed):
            return parsed.time(), None
        
        return time(14, 0), f"⚠️ Hora '{hora}' inválida. Usando 14:00."
    except:
        return time(14, 0), "⚠️ Erro na hora: usando 14:00."

def validar_cpf_basico(cpf):
    """Validação básica de CPF (apenas formato)."""
    if not cpf:
        return "", None
    
    limpo = re.sub(r'\D', '', str(cpf))
    
    if len(limpo) == 11:
        return limpo, None
    elif len(limpo) == 0:
        return "", None
    else:
        return limpo, f"⚠️ CPF com formato inválido ({len(limpo)} dígitos)"

def formatar_data_br(data):
    """Formata data para padrão brasileiro dd/mm/aaaa."""
    if data is None:
        return ""
    if isinstance(data, str):
        try:
            data = pd.to_datetime(data).date()
        except:
            return data
    if isinstance(data, datetime):
        data = data.date()
    return data.strftime('%d/%m/%Y')

def parse_data_br(data_str):
    """Parse data do formato brasileiro dd/mm/aaaa."""
    if not data_str:
        return None
    try:
        return datetime.strptime(data_str, '%d/%m/%Y').date()
    except:
        return None

# ==============================================================================
# FUNÇÕES DE CÁLCULO
# ==============================================================================
def gerar_id_sequencial(df):
    """Gera próximo ID sequencial."""
    try:
        if df.empty:
            return 1
        df = df.copy()
        df['ID'] = pd.to_numeric(df['ID'], errors='coerce').fillna(0).astype(int)
        return int(df['ID'].max()) + 1
    except:
        return 1

def calcular_valor_sessao(servico, desconto):
    """Calcula valor da sessão com desconto."""
    try:
        valor_base = SERVICOS.get(servico, 150.00)
        desc, _ = validar_desconto(desconto)
        valor_final = valor_base * (1 - desc / 100)
        return round(valor_final, 2)
    except:
        return 150.00

def calcular_sessoes_restantes(paciente_nome, df_agendamentos, df_pacotes):
    """Calcula sessões restantes do pacote ativo."""
    try:
        # Busca pacote ativo do paciente
        pacotes_paciente = df_pacotes[
            (df_pacotes['Paciente'] == paciente_nome) & 
            (df_pacotes['Status'] == 'ATIVO')
        ]
        
        if pacotes_paciente.empty:
            return None
        
        # Pega o pacote mais recente
        pacote = pacotes_paciente.iloc[-1]
        
        # Verifica validade
        validade = pd.to_datetime(pacote['Validade']).date()
        if validade < hoje_brasil():
            return None
        
        # Conta sessões utilizadas
        sessoes_utilizadas = len(df_agendamentos[
            (df_agendamentos['Paciente'] == paciente_nome) &
            (df_agendamentos['Pagamento'] == 'PACOTE') &
            (df_agendamentos['Data'] >= pd.to_datetime(pacote['DataCompra']).date()) &
            (df_agendamentos['Data'] <= validade)
        ])
        
        total_sessoes = int(pacote['QtdSessoes'])
        restantes = total_sessoes - sessoes_utilizadas
        
        return {
            'restantes': max(0, restantes),
            'total': total_sessoes,
            'validade': validade,
            'valor': float(pacote['Valor'])
        }
    except Exception as e:
        logger.error(f"Erro ao calcular sessões: {e}")
        return None

# ==============================================================================
# FUNÇÕES DE PERSISTÊNCIA
# ==============================================================================
def carregar_pacientes():
    """Carrega cadastro de pacientes."""
    try:
        if os.path.exists(ARQUIVO_PACIENTES):
            df = pd.read_csv(ARQUIVO_PACIENTES)
            return df
        else:
            return pd.DataFrame(columns=[
                "Nome", "CPF", "Telefone", "Email", "DataNascimento",
                "Endereco", "Observacoes", "DataCadastro"
            ])
    except Exception as e:
        logger.error(f"Erro ao carregar pacientes: {e}")
        return pd.DataFrame(columns=[
            "Nome", "CPF", "Telefone", "Email", "DataNascimento",
            "Endereco", "Observacoes", "DataCadastro"
        ])

def salvar_pacientes(df):
    """Salva cadastro de pacientes."""
    try:
        df.to_csv(ARQUIVO_PACIENTES, index=False)
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar pacientes: {e}")
        return False

def carregar_agendamentos():
    """Carrega agendamentos."""
    try:
        if os.path.exists(ARQUIVO_AGENDAMENTOS):
            df = pd.read_csv(ARQUIVO_AGENDAMENTOS)
            df['Data'] = pd.to_datetime(df['Data']).dt.date
            df['Hora'] = pd.to_datetime(df['Hora'], format='%H:%M:%S').dt.time
            return df
        else:
            return pd.DataFrame(columns=[
                "ID", "Paciente", "Data", "Hora", "Servico", 
                "Valor", "Desconto", "ValorFinal", "Pagamento", 
                "Status", "Observacoes", "Prontuario"
            ])
    except Exception as e:
        logger.error(f"Erro ao carregar agendamentos: {e}")
        return pd.DataFrame(columns=[
            "ID", "Paciente", "Data", "Hora", "Servico", 
            "Valor", "Desconto", "ValorFinal", "Pagamento", 
            "Status", "Observacoes", "Prontuario"
        ])

def salvar_agendamentos(df):
    """Salva agendamentos."""
    try:
        df_save = df.copy()
        df_save['Data'] = pd.to_datetime(df_save['Data']).dt.strftime('%Y-%m-%d')
        df_save['Hora'] = df_save['Hora'].astype(str)
        df_save.to_csv(ARQUIVO_AGENDAMENTOS, index=False)
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar agendamentos: {e}")
        return False

def carregar_pacotes():
    """Carrega pacotes."""
    try:
        if os.path.exists(ARQUIVO_PACOTES):
            df = pd.read_csv(ARQUIVO_PACOTES)
            df['DataCompra'] = pd.to_datetime(df['DataCompra']).dt.date
            df['Validade'] = pd.to_datetime(df['Validade']).dt.date
            return df
        else:
            return pd.DataFrame(columns=[
                "ID", "Paciente", "QtdSessoes", "Valor", 
                "DataCompra", "Validade", "Status"
            ])
    except Exception as e:
        logger.error(f"Erro ao carregar pacotes: {e}")
        return pd.DataFrame(columns=[
            "ID", "Paciente", "QtdSessoes", "Valor", 
            "DataCompra", "Validade", "Status"
        ])

def salvar_pacotes(df):
    """Salva pacotes."""
    try:
        df_save = df.copy()
        df_save['DataCompra'] = pd.to_datetime(df_save['DataCompra']).dt.strftime('%Y-%m-%d')
        df_save['Validade'] = pd.to_datetime(df_save['Validade']).dt.strftime('%Y-%m-%d')
        df_save.to_csv(ARQUIVO_PACOTES, index=False)
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar pacotes: {e}")
        return False

def registrar_historico(acao, detalhes):
    """Registra alterações no histórico."""
    try:
        novo_registro = pd.DataFrame([{
            "Timestamp": agora_brasil().strftime('%Y-%m-%d %H:%M:%S'),
            "Acao": acao,
            "Detalhes": detalhes
        }])
        
        if os.path.exists(ARQUIVO_HISTORICO):
            df_hist = pd.read_csv(ARQUIVO_HISTORICO)
            df_hist = pd.concat([df_hist, novo_registro], ignore_index=True)
        else:
            df_hist = novo_registro
        
        df_hist.to_csv(ARQUIVO_HISTORICO, index=False)
    except Exception as e:
        logger.error(f"Erro ao registrar histórico: {e}")

# ==============================================================================
# FUNÇÕES DE GERAÇÃO DE PDF
# ==============================================================================
def gerar_agenda_pdf(df, data_inicial, data_final):
    """Gera PDF com agenda de consultas."""
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
        elements = []
        styles = getSampleStyleSheet()
        
        # Título
        titulo_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=18,
            textColor=colors.HexColor('#2C5F7C'),
            spaceAfter=12
        )
        elements.append(Paragraph("Agenda de Consultas", titulo_style))
        elements.append(Paragraph(
            f"Período: {data_inicial.strftime('%d/%m/%Y')} a {data_final.strftime('%d/%m/%Y')}", 
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.5*cm))
        
        # Filtrar dados
        df_filtrado = df[
            (df['Data'] >= data_inicial) & 
            (df['Data'] <= data_final)
        ].sort_values(['Data', 'Hora'])
        
        if df_filtrado.empty:
            elements.append(Paragraph("Nenhum agendamento neste período.", styles['Normal']))
        else:
            # Preparar dados da tabela
            data_table = [['Data', 'Hora', 'Paciente', 'Serviço', 'Status']]
            
            for _, row in df_filtrado.iterrows():
                data_table.append([
                    row['Data'].strftime('%d/%m/%Y'),
                    row['Hora'].strftime('%H:%M'),
                    row['Paciente'][:25],
                    row['Servico'][:20],
                    row['Status'].replace('🔵 ', '').replace('🟢 ', '').replace('✅ ', '')
                ])
            
            # Criar tabela
            table = Table(data_table, colWidths=[3*cm, 2*cm, 5*cm, 5*cm, 3*cm])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C5F7C')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
            ]))
            
            elements.append(table)
        
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        logger.error(f"Erro ao gerar PDF: {e}")
        return None

def gerar_recibo_pdf(agendamento):
    """Gera recibo de pagamento."""
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=3*cm, bottomMargin=3*cm)
        elements = []
        styles = getSampleStyleSheet()
        
        # Cabeçalho
        titulo_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=20,
            textColor=colors.HexColor('#2C5F7C'),
            spaceAfter=20,
            alignment=1
        )
        elements.append(Paragraph("RECIBO DE PAGAMENTO", titulo_style))
        elements.append(Spacer(1, 1*cm))
        
        # Informações
        info_style = styles['Normal']
        elements.append(Paragraph(f"<b>Paciente:</b> {agendamento['Paciente']}", info_style))
        elements.append(Spacer(1, 0.3*cm))
        elements.append(Paragraph(f"<b>Serviço:</b> {agendamento['Servico']}", info_style))
        elements.append(Spacer(1, 0.3*cm))
        elements.append(Paragraph(
            f"<b>Data:</b> {agendamento['Data'].strftime('%d/%m/%Y')} às {agendamento['Hora'].strftime('%H:%M')}", 
            info_style
        ))
        elements.append(Spacer(1, 0.3*cm))
        
        if agendamento['Desconto'] > 0:
            elements.append(Paragraph(f"<b>Valor:</b> R$ {agendamento['Valor']:.2f}", info_style))
            elements.append(Paragraph(f"<b>Desconto:</b> {agendamento['Desconto']:.1f}%", info_style))
            elements.append(Spacer(1, 0.3*cm))
        
        valor_style = ParagraphStyle(
            'Valor',
            parent=styles['Normal'],
            fontSize=14,
            textColor=colors.HexColor('#2C5F7C'),
            spaceAfter=12
        )
        elements.append(Paragraph(
            f"<b>Valor Pago: R$ {agendamento['ValorFinal']:.2f}</b>", 
            valor_style
        ))
        
        elements.append(Spacer(1, 2*cm))
        elements.append(Paragraph(f"Nossa Senhora do Socorro/SE, {agora_brasil().strftime('%d/%m/%Y')}", info_style))
        elements.append(Spacer(1, 1.5*cm))
        elements.append(Paragraph("_" * 50, info_style))
        elements.append(Paragraph("Radamés - CRP 19/5223", info_style))
        
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        logger.error(f"Erro ao gerar recibo: {e}")
        return None

# ==============================================================================
# INICIALIZAÇÃO DO SESSION STATE
# ==============================================================================
if 'pacientes' not in st.session_state:
    st.session_state.pacientes = carregar_pacientes()

if 'agendamentos' not in st.session_state:
    st.session_state.agendamentos = carregar_agendamentos()

if 'pacotes' not in st.session_state:
    st.session_state.pacotes = carregar_pacotes()

# ==============================================================================
# INTERFACE - SIDEBAR
# ==============================================================================
with st.sidebar:
    st.markdown("### 🧠 Agenda Psicologia")
    st.markdown(f"**Dr. Radamés**")
    st.markdown(f"CRP 19/5223")
    st.divider()
    
    menu = st.radio(
        "Menu Principal",
        ["📊 Dashboard", "📅 Agendamentos", "👤 Pacientes", "📦 Pacotes", 
         "📱 Lembretes", "📈 Relatórios", "🛠️ Manutenção"],
        label_visibility="collapsed"
    )
    
    st.divider()
    st.caption(f"Versão {VERSAO}")
    st.caption(f"📅 {hoje_brasil().strftime('%d/%m/%Y')}")

# ==============================================================================
# DASHBOARD
# ==============================================================================
if menu == "📊 Dashboard":
    st.title("📊 Dashboard")
    
    # Filtro de período
    col1, col2 = st.columns(2)
    with col1:
        data_inicio = st.date_input(
            "Data Início", 
            value=hoje_brasil() - timedelta(days=30),
            max_value=hoje_brasil(),
            format="DD/MM/YYYY"
        )
    with col2:
        data_fim = st.date_input(
            "Data Fim",
            value=hoje_brasil(),
            max_value=hoje_brasil() + timedelta(days=365),
            format="DD/MM/YYYY"
        )
    
    # Filtrar agendamentos
    df_periodo = st.session_state.agendamentos[
        (st.session_state.agendamentos['Data'] >= data_inicio) &
        (st.session_state.agendamentos['Data'] <= data_fim)
    ]
    
    # Métricas
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_pacientes = len(st.session_state.pacientes)
        st.metric("👤 Pacientes Cadastrados", total_pacientes)
    
    with col2:
        total_agendamentos = len(df_periodo)
        st.metric("📅 Agendamentos", total_agendamentos)
    
    with col3:
        sessoes_realizadas = len(df_periodo[df_periodo['Status'] == '✅ Realizado'])
        st.metric("✅ Sessões Realizadas", sessoes_realizadas)
    
    with col4:
        receita = df_periodo[df_periodo['Status'] == '✅ Realizado']['ValorFinal'].sum()
        st.metric("💰 Receita", f"R$ {receita:,.2f}")
    
    st.divider()
    
    # Próximos agendamentos
    st.subheader("📅 Próximos Agendamentos")
    
    hoje = hoje_brasil()
    proximos = st.session_state.agendamentos[
        (st.session_state.agendamentos['Data'] >= hoje) &
        (st.session_state.agendamentos['Status'].isin(['🔵 Agendado', '🟢 Confirmado']))
    ].sort_values(['Data', 'Hora']).head(10)
    
    if proximos.empty:
        st.info("Nenhum agendamento próximo.")
    else:
        df_show = proximos[['Data', 'Hora', 'Paciente', 'Servico', 'Status']].copy()
        df_show['Data'] = df_show['Data'].apply(lambda x: x.strftime('%d/%m/%Y'))
        df_show['Hora'] = df_show['Hora'].apply(lambda x: x.strftime('%H:%M'))
        st.dataframe(df_show, use_container_width=True, hide_index=True)
    
    st.divider()
    
    # Gráficos
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Status dos Agendamentos")
        if not df_periodo.empty:
            status_counts = df_periodo['Status'].value_counts()
            st.bar_chart(status_counts)
        else:
            st.info("Sem dados para o período.")
    
    with col2:
        st.subheader("💼 Serviços Mais Solicitados")
        if not df_periodo.empty:
            servicos_counts = df_periodo['Servico'].value_counts()
            st.bar_chart(servicos_counts)
        else:
            st.info("Sem dados para o período.")

# ==============================================================================
# AGENDAMENTOS
# ==============================================================================
elif menu == "📅 Agendamentos":
    st.title("📅 Gestão de Agendamentos")
    
    tab1, tab2, tab3 = st.tabs(["➕ Novo Agendamento", "📋 Lista", "🔍 Buscar"])
    
    # --- TAB 1: NOVO AGENDAMENTO ---
    with tab1:
        st.subheader("Agendar Nova Sessão")
        
        if st.session_state.pacientes.empty:
            st.warning("⚠️ Cadastre pacientes primeiro na aba '👤 Pacientes'")
        else:
            with st.form("form_agendamento", clear_on_submit=True):
                col1, col2 = st.columns(2)
                
                with col1:
                    paciente_nome = st.selectbox(
                        "👤 Paciente *",
                        options=sorted(st.session_state.pacientes['Nome'].unique())
                    )
                    
                    data_consulta = st.date_input(
                        "📅 Data *",
                        value=hoje_brasil(),
                        min_value=hoje_brasil() - timedelta(days=7),
                        max_value=hoje_brasil() + timedelta(days=365),
                        format="DD/MM/YYYY"
                    )
                    
                    servico = st.selectbox(
                        "💼 Serviço *",
                        options=list(SERVICOS.keys())
                    )
                    
                    desconto = st.number_input(
                        "💵 Desconto (%)",
                        min_value=0.0,
                        max_value=100.0,
                        value=0.0,
                        step=5.0
                    )
                
                with col2:
                    hora_consulta = st.time_input(
                        "⏰ Horário *",
                        value=time(14, 0)
                    )
                    
                    # Verificar pacote ativo
                    info_pacote = calcular_sessoes_restantes(
                        paciente_nome,
                        st.session_state.agendamentos,
                        st.session_state.pacotes
                    )
                    
                    if info_pacote and info_pacote['restantes'] > 0:
                        st.info(f"📦 Pacote ativo: {info_pacote['restantes']}/{info_pacote['total']} sessões restantes")
                        st.info(f"⏰ Válido até: {info_pacote['validade'].strftime('%d/%m/%Y')}")
                        pagamento_default = "PACOTE"
                    else:
                        pagamento_default = "NÃO PAGO"
                    
                    pagamento = st.selectbox(
                        "💳 Pagamento *",
                        options=OPCOES_PAGAMENTO,
                        index=OPCOES_PAGAMENTO.index(pagamento_default)
                    )
                    
                    status = st.selectbox(
                        "📊 Status *",
                        options=OPCOES_STATUS,
                        index=0
                    )
                
                observacoes = st.text_area(
                    "📝 Observações",
                    placeholder="Ex: Primeira consulta, paciente ansioso..."
                )
                
                col_submit = st.columns([1, 1, 2])[1]
                with col_submit:
                    submitted = st.form_submit_button(
                        "✅ Confirmar Agendamento",
                        use_container_width=True,
                        type="primary"
                    )
                
                if submitted:
                    # Validações
                    data_valida, msg_data = validar_data(data_consulta)
                    hora_valida, msg_hora = validar_hora(hora_consulta)
                    
                    # Verificar conflito de horário
                    conflito = st.session_state.agendamentos[
                        (st.session_state.agendamentos['Data'] == data_valida) &
                        (st.session_state.agendamentos['Hora'] == hora_valida) &
                        (~st.session_state.agendamentos['Status'].isin(['🔴 Cancelado', '🟡 Remarcado']))
                    ]
                    
                    if not conflito.empty:
                        st.error(f"❌ Já existe agendamento para {data_valida.strftime('%d/%m/%Y')} às {hora_valida.strftime('%H:%M')}")
                    else:
                        # Verificar se pode usar pacote
                        if pagamento == "PACOTE":
                            if not info_pacote or info_pacote['restantes'] <= 0:
                                st.error("❌ Paciente não possui sessões disponíveis no pacote!")
                            else:
                                # Calcular valores
                                valor_base = SERVICOS[servico]
                                valor_final = calcular_valor_sessao(servico, desconto)
                                
                                # Criar novo agendamento
                                novo_id = gerar_id_sequencial(st.session_state.agendamentos)
                                novo_agendamento = pd.DataFrame([{
                                    "ID": novo_id,
                                    "Paciente": paciente_nome,
                                    "Data": data_valida,
                                    "Hora": hora_valida,
                                    "Servico": servico,
                                    "Valor": valor_base,
                                    "Desconto": desconto,
                                    "ValorFinal": valor_final,
                                    "Pagamento": pagamento,
                                    "Status": status,
                                    "Observacoes": observacoes,
                                    "Prontuario": ""
                                }])
                                
                                st.session_state.agendamentos = pd.concat(
                                    [st.session_state.agendamentos, novo_agendamento],
                                    ignore_index=True
                                )
                                
                                salvar_agendamentos(st.session_state.agendamentos)
                                registrar_historico(
                                    "AGENDAMENTO_CRIADO",
                                    f"ID {novo_id} - {paciente_nome} em {data_valida}"
                                )
                                
                                st.success(f"✅ Agendamento confirmado! ID: {novo_id}")
                                st.balloons()
                                st.rerun()
                        else:
                            # Agendamento normal (sem pacote)
                            valor_base = SERVICOS[servico]
                            valor_final = calcular_valor_sessao(servico, desconto)
                            
                            novo_id = gerar_id_sequencial(st.session_state.agendamentos)
                            novo_agendamento = pd.DataFrame([{
                                "ID": novo_id,
                                "Paciente": paciente_nome,
                                "Data": data_valida,
                                "Hora": hora_valida,
                                "Servico": servico,
                                "Valor": valor_base,
                                "Desconto": desconto,
                                "ValorFinal": valor_final,
                                "Pagamento": pagamento,
                                "Status": status,
                                "Observacoes": observacoes,
                                "Prontuario": ""
                            }])
                            
                            st.session_state.agendamentos = pd.concat(
                                [st.session_state.agendamentos, novo_agendamento],
                                ignore_index=True
                            )
                            
                            salvar_agendamentos(st.session_state.agendamentos)
                            registrar_historico(
                                "AGENDAMENTO_CRIADO",
                                f"ID {novo_id} - {paciente_nome} em {data_valida}"
                            )
                            
                            st.success(f"✅ Agendamento confirmado! ID: {novo_id}")
                            st.balloons()
                            st.rerun()
    
    # --- TAB 2: LISTA ---
    with tab2:
        st.subheader("Lista de Agendamentos")
        
        if st.session_state.agendamentos.empty:
            st.info("Nenhum agendamento cadastrado.")
        else:
            # Filtros
            col1, col2, col3 = st.columns(3)
            
            with col1:
                filtro_periodo = st.selectbox(
                    "Período",
                    ["Todos", "Hoje", "Esta Semana", "Este Mês", "Próximos 30 dias"]
                )
            
            with col2:
                filtro_status = st.multiselect(
                    "Status",
                    options=OPCOES_STATUS,
                    default=OPCOES_STATUS
                )
            
            with col3:
                filtro_paciente = st.text_input("🔍 Buscar paciente")
            
            # Aplicar filtros
            df_filtrado = st.session_state.agendamentos.copy()
            
            hoje = hoje_brasil()
            if filtro_periodo == "Hoje":
                df_filtrado = df_filtrado[df_filtrado['Data'] == hoje]
            elif filtro_periodo == "Esta Semana":
                inicio_semana = hoje - timedelta(days=hoje.weekday())
                fim_semana = inicio_semana + timedelta(days=6)
                df_filtrado = df_filtrado[
                    (df_filtrado['Data'] >= inicio_semana) &
                    (df_filtrado['Data'] <= fim_semana)
                ]
            elif filtro_periodo == "Este Mês":
                df_filtrado = df_filtrado[
                    (df_filtrado['Data'].apply(lambda x: x.month) == hoje.month) &
                    (df_filtrado['Data'].apply(lambda x: x.year) == hoje.year)
                ]
            elif filtro_periodo == "Próximos 30 dias":
                df_filtrado = df_filtrado[
                    (df_filtrado['Data'] >= hoje) &
                    (df_filtrado['Data'] <= hoje + timedelta(days=30))
                ]
            
            if filtro_status:
                df_filtrado = df_filtrado[df_filtrado['Status'].isin(filtro_status)]
            
            if filtro_paciente:
                df_filtrado = df_filtrado[
                    df_filtrado['Paciente'].str.contains(filtro_paciente, case=False, na=False)
                ]
            
            # Ordenar
            df_filtrado = df_filtrado.sort_values(['Data', 'Hora'], ascending=[False, False])
            
            # Exibir
            st.write(f"**{len(df_filtrado)} agendamento(s) encontrado(s)**")
            
            df_show = df_filtrado[[
                'ID', 'Data', 'Hora', 'Paciente', 'Servico', 
                'ValorFinal', 'Pagamento', 'Status'
            ]].copy()
            
            df_show['Data'] = df_show['Data'].apply(lambda x: x.strftime('%d/%m/%Y'))
            df_show['Hora'] = df_show['Hora'].apply(lambda x: x.strftime('%H:%M'))
            df_show['ValorFinal'] = df_show['ValorFinal'].apply(lambda x: f"R$ {x:.2f}")
            
            st.dataframe(df_show, use_container_width=True, hide_index=True)
            
            # Ações
            st.divider()
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("📄 Exportar Agenda PDF", use_container_width=True):
                    pdf = gerar_agenda_pdf(
                        df_filtrado,
                        df_filtrado['Data'].min(),
                        df_filtrado['Data'].max()
                    )
                    if pdf:
                        st.download_button(
                            "⬇️ Baixar PDF",
                            pdf,
                            "agenda.pdf",
                            "application/pdf",
                            use_container_width=True
                        )
            
            with col2:
                csv = df_filtrado.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "📊 Exportar CSV",
                    csv,
                    "agendamentos.csv",
                    "text/csv",
                    use_container_width=True
                )
    
    # --- TAB 3: BUSCAR E EDITAR ---
    with tab3:
        st.subheader("Buscar e Editar Agendamento")
        
        if st.session_state.agendamentos.empty:
            st.info("Nenhum agendamento cadastrado.")
        else:
            busca_id = st.number_input(
                "🔍 Digite o ID do agendamento:",
                min_value=1,
                step=1
            )
            
            agendamento = st.session_state.agendamentos[
                st.session_state.agendamentos['ID'] == busca_id
            ]
            
            if not agendamento.empty:
                ag = agendamento.iloc[0]
                
                st.success(f"✅ Agendamento encontrado!")
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.write(f"**Paciente:** {ag['Paciente']}")
                    st.write(f"**Data:** {ag['Data'].strftime('%d/%m/%Y')} às {ag['Hora'].strftime('%H:%M')}")
                    st.write(f"**Serviço:** {ag['Servico']}")
                    st.write(f"**Valor:** R$ {ag['ValorFinal']:.2f}")
                    st.write(f"**Pagamento:** {ag['Pagamento']}")
                    st.write(f"**Status:** {ag['Status']}")
                
                with col2:
                    # Gerar recibo se pago
                    if ag['Pagamento'] in ['PAGO', 'PACOTE']:
                        if st.button("📄 Gerar Recibo", use_container_width=True):
                            pdf = gerar_recibo_pdf(ag)
                            if pdf:
                                st.download_button(
                                    "⬇️ Baixar Recibo",
                                    pdf,
                                    f"recibo_{busca_id}.pdf",
                                    "application/pdf",
                                    use_container_width=True
                                )
                
                st.divider()
                
                # Formulário de edição
                with st.form("form_editar"):
                    st.subheader("Editar Agendamento")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        novo_status = st.selectbox(
                            "Status",
                            options=OPCOES_STATUS,
                            index=OPCOES_STATUS.index(ag['Status'])
                        )
                        
                        novo_pagamento = st.selectbox(
                            "Pagamento",
                            options=OPCOES_PAGAMENTO,
                            index=OPCOES_PAGAMENTO.index(ag['Pagamento'])
                        )
                    
                    with col2:
                        nova_data = st.date_input(
                            "Data",
                            value=ag['Data'],
                            format="DD/MM/YYYY"
                        )
                        
                        nova_hora = st.time_input(
                            "Hora",
                            value=ag['Hora']
                        )
                    
                    novas_obs = st.text_area(
                        "Observações",
                        value=ag['Observacoes']
                    )
                    
                    prontuario = st.text_area(
                        "📋 Prontuário (Informações Clínicas)",
                        value=ag['Prontuario'],
                        help="Campo confidencial para anotações clínicas"
                    )
                    
                    col_submit = st.columns([1, 1, 1])
                    
                    with col_submit[0]:
                        if st.form_submit_button("💾 Salvar Alterações", use_container_width=True, type="primary"):
                            idx = st.session_state.agendamentos[
                                st.session_state.agendamentos['ID'] == busca_id
                            ].index[0]
                            
                            st.session_state.agendamentos.at[idx, 'Status'] = novo_status
                            st.session_state.agendamentos.at[idx, 'Pagamento'] = novo_pagamento
                            st.session_state.agendamentos.at[idx, 'Data'] = nova_data
                            st.session_state.agendamentos.at[idx, 'Hora'] = nova_hora
                            st.session_state.agendamentos.at[idx, 'Observacoes'] = novas_obs
                            st.session_state.agendamentos.at[idx, 'Prontuario'] = prontuario
                            
                            salvar_agendamentos(st.session_state.agendamentos)
                            registrar_historico("AGENDAMENTO_EDITADO", f"ID {busca_id}")
                            
                            st.success("✅ Agendamento atualizado!")
                            st.rerun()
                    
                    with col_submit[2]:
                        if st.form_submit_button("🗑️ Excluir", use_container_width=True):
                            st.session_state.agendamentos = st.session_state.agendamentos[
                                st.session_state.agendamentos['ID'] != busca_id
                            ]
                            salvar_agendamentos(st.session_state.agendamentos)
                            registrar_historico("AGENDAMENTO_EXCLUIDO", f"ID {busca_id}")
                            st.success("✅ Agendamento excluído!")
                            st.rerun()
            else:
                if busca_id > 0:
                    st.warning("⚠️ Agendamento não encontrado.")

# ==============================================================================
# PACIENTES
# ==============================================================================
elif menu == "👤 Pacientes":
    st.title("👤 Gestão de Pacientes")
    
    tab1, tab2, tab3 = st.tabs(["➕ Cadastrar", "📋 Lista", "🔍 Buscar"])
    
    # --- TAB 1: CADASTRAR ---
    with tab1:
        st.subheader("Cadastrar Novo Paciente")
        
        with st.form("form_paciente", clear_on_submit=True):
            col1, col2 = st.columns(2)
            
            with col1:
                nome = st.text_input("👤 Nome Completo *", placeholder="Ex: João da Silva")
                cpf = st.text_input("🆔 CPF", placeholder="000.000.000-00")
                email = st.text_input("📧 Email", placeholder="exemplo@email.com")
                data_nasc = st.date_input(
                    "📅 Data de Nascimento",
                    value=None,
                    max_value=hoje_brasil(),
                    format="DD/MM/YYYY"
                )
            
            with col2:
                telefone = st.text_input("📱 Telefone *", placeholder="(79) 99999-9999")
                endereco = st.text_area("📍 Endereço", placeholder="Rua, número, bairro...")
            
            observacoes = st.text_area(
                "📝 Observações Gerais",
                placeholder="Ex: Preferências de horário, condições relevantes..."
            )
            
            col_submit = st.columns([1, 1, 2])[1]
            with col_submit:
                submitted = st.form_submit_button(
                    "💾 Cadastrar Paciente",
                    use_container_width=True,
                    type="primary"
                )
            
            if submitted:
                if not nome.strip():
                    st.error("❌ Nome é obrigatório!")
                elif not telefone.strip():
                    st.error("❌ Telefone é obrigatório!")
                else:
                    # Verificar duplicado
                    nomes_existentes = st.session_state.pacientes['Nome'].str.lower().str.strip().tolist()
                    if nome.lower().strip() in nomes_existentes:
                        st.warning(f"⚠️ Paciente '{nome}' já cadastrado!")
                    else:
                        # Validar dados
                        tel_limpo, msg_tel = validar_telefone(telefone)
                        cpf_limpo, msg_cpf = validar_cpf_basico(cpf)
                        
                        if msg_tel:
                            st.warning(msg_tel)
                        if msg_cpf:
                            st.warning(msg_cpf)
                        
                        # Criar novo paciente
                        novo_paciente = pd.DataFrame([{
                            "Nome": nome.strip(),
                            "CPF": cpf_limpo,
                            "Telefone": tel_limpo,
                            "Email": email.strip(),
                            "DataNascimento": data_nasc.strftime('%Y-%m-%d') if data_nasc else "",
                            "Endereco": endereco.strip(),
                            "Observacoes": observacoes.strip(),
                            "DataCadastro": hoje_brasil().strftime('%Y-%m-%d')
                        }])
                        
                        st.session_state.pacientes = pd.concat(
                            [st.session_state.pacientes, novo_paciente],
                            ignore_index=True
                        )
                        
                        salvar_pacientes(st.session_state.pacientes)
                        registrar_historico("PACIENTE_CADASTRADO", f"{nome}")
                        
                        st.success(f"✅ Paciente '{nome}' cadastrado com sucesso!")
                        st.balloons()
                        st.rerun()
    
    # --- TAB 2: LISTA ---
    with tab2:
        st.subheader("Lista de Pacientes")
        
        if st.session_state.pacientes.empty:
            st.info("Nenhum paciente cadastrado.")
        else:
            busca = st.text_input("🔍 Buscar paciente por nome")
            
            df_show = st.session_state.pacientes.copy()
            
            if busca:
                df_show = df_show[
                    df_show['Nome'].str.contains(busca, case=False, na=False)
                ]
            
            st.write(f"**{len(df_show)} paciente(s) encontrado(s)**")
            
            # Exibir lista compacta
            for idx, paciente in df_show.iterrows():
                with st.expander(f"👤 {paciente['Nome']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Telefone:** {paciente['Telefone']}")
                        st.write(f"**Email:** {paciente['Email']}")
                        if paciente['DataNascimento']:
                            st.write(f"**Data Nasc:** {paciente['DataNascimento']}")
                    
                    with col2:
                        if paciente['CPF']:
                            st.write(f"**CPF:** {paciente['CPF']}")
                        st.write(f"**Cadastro:** {paciente['DataCadastro']}")
                    
                    if paciente['Observacoes']:
                        st.write(f"**Observações:** {paciente['Observacoes']}")
                    
                    # Histórico de consultas
                    historico = st.session_state.agendamentos[
                        st.session_state.agendamentos['Paciente'] == paciente['Nome']
                    ]
                    
                    if not historico.empty:
                        st.divider()
                        st.write(f"**📅 Histórico: {len(historico)} consulta(s)**")
                        
                        hist_show = historico[['Data', 'Servico', 'Status']].copy()
                        hist_show['Data'] = hist_show['Data'].apply(lambda x: x.strftime('%d/%m/%Y'))
                        hist_show = hist_show.sort_values('Data', ascending=False).head(5)
                        st.dataframe(hist_show, hide_index=True, use_container_width=True)
            
            st.divider()
            csv = st.session_state.pacientes.to_csv(index=False).encode('utf-8')
            st.download_button(
                "📊 Exportar Lista CSV",
                csv,
                "pacientes.csv",
                "text/csv",
                use_container_width=True
            )
    
    # --- TAB 3: BUSCAR E EDITAR ---
    with tab3:
        st.subheader("Buscar e Editar Paciente")
        
        if st.session_state.pacientes.empty:
            st.info("Nenhum paciente cadastrado.")
        else:
            nome_busca = st.selectbox(
                "Selecione o paciente:",
                options=sorted(st.session_state.pacientes['Nome'].unique())
            )
            
            paciente = st.session_state.pacientes[
                st.session_state.pacientes['Nome'] == nome_busca
            ].iloc[0]
            
            with st.form("form_editar_paciente"):
                st.subheader(f"Editando: {nome_busca}")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    novo_nome = st.text_input("Nome", value=paciente['Nome'])
                    novo_cpf = st.text_input("CPF", value=paciente['CPF'])
                    novo_email = st.text_input("Email", value=paciente['Email'])
                    
                    data_nasc_atual = pd.to_datetime(paciente['DataNascimento']).date() if paciente['DataNascimento'] else None
                    nova_data_nasc = st.date_input(
                        "Data de Nascimento",
                        value=data_nasc_atual,
                        max_value=hoje_brasil(),
                        format="DD/MM/YYYY"
                    )
                
                with col2:
                    novo_telefone = st.text_input("Telefone", value=paciente['Telefone'])
                    novo_endereco = st.text_area("Endereço", value=paciente['Endereco'])
                
                novas_obs = st.text_area("Observações", value=paciente['Observacoes'])
                
                col_submit = st.columns([1, 1, 1])
                
                with col_submit[0]:
                    if st.form_submit_button("💾 Salvar", use_container_width=True, type="primary"):
                        idx = st.session_state.pacientes[
                            st.session_state.pacientes['Nome'] == nome_busca
                        ].index[0]
                        
                        st.session_state.pacientes.at[idx, 'Nome'] = novo_nome.strip()
                        st.session_state.pacientes.at[idx, 'CPF'] = validar_cpf_basico(novo_cpf)[0]
                        st.session_state.pacientes.at[idx, 'Telefone'] = validar_telefone(novo_telefone)[0]
                        st.session_state.pacientes.at[idx, 'Email'] = novo_email.strip()
                        st.session_state.pacientes.at[idx, 'DataNascimento'] = nova_data_nasc.strftime('%Y-%m-%d') if nova_data_nasc else ""
                        st.session_state.pacientes.at[idx, 'Endereco'] = novo_endereco.strip()
                        st.session_state.pacientes.at[idx, 'Observacoes'] = novas_obs.strip()
                        
                        salvar_pacientes(st.session_state.pacientes)
                        registrar_historico("PACIENTE_EDITADO", novo_nome)
                        
                        st.success("✅ Paciente atualizado!")
                        st.rerun()
                
                with col_submit[2]:
                    if st.form_submit_button("🗑️ Excluir", use_container_width=True):
                        # Verificar agendamentos
                        tem_agendamentos = not st.session_state.agendamentos[
                            st.session_state.agendamentos['Paciente'] == nome_busca
                        ].empty
                        
                        if tem_agendamentos:
                            st.error("❌ Não é possível excluir paciente com agendamentos!")
                        else:
                            st.session_state.pacientes = st.session_state.pacientes[
                                st.session_state.pacientes['Nome'] != nome_busca
                            ]
                            salvar_pacientes(st.session_state.pacientes)
                            registrar_historico("PACIENTE_EXCLUIDO", nome_busca)
                            st.success("✅ Paciente excluído!")
                            st.rerun()

# ==============================================================================
# PACOTES
# ==============================================================================
elif menu == "📦 Pacotes":
    st.title("📦 Gestão de Pacotes")
    
    tab1, tab2 = st.tabs(["➕ Novo Pacote", "📋 Lista"])
    
    # --- TAB 1: NOVO PACOTE ---
    with tab1:
        st.subheader("Criar Novo Pacote")
        
        if st.session_state.pacientes.empty:
            st.warning("⚠️ Cadastre pacientes primeiro.")
        else:
            with st.form("form_pacote", clear_on_submit=True):
                col1, col2 = st.columns(2)
                
                with col1:
                    paciente_pacote = st.selectbox(
                        "👤 Paciente *",
                        options=sorted(st.session_state.pacientes['Nome'].unique())
                    )
                    
                    qtd_sessoes = st.number_input(
                        "📊 Quantidade de Sessões *",
                        min_value=1,
                        max_value=20,
                        value=4,
                        step=1,
                        help="Quantidade de sessões incluídas no pacote"
                    )
                    
                    # Sugestão de valor (7% desconto em 4 sessões)
                    valor_sugerido = 4 * 150.00 * 0.93
                    st.info(f"💡 Sugestão: R$ {valor_sugerido:.2f} (4 sessões com ~7% desconto)")
                
                with col2:
                    valor_pacote = st.number_input(
                        "💰 Valor Total do Pacote *",
                        min_value=0.01,
                        max_value=10000.00,
                        value=valor_sugerido,
                        step=50.00,
                        format="%.2f"
                    )
                    
                    data_compra = st.date_input(
                        "📅 Data da Compra *",
                        value=hoje_brasil(),
                        max_value=hoje_brasil(),
                        format="DD/MM/YYYY"
                    )
                    
                    # Calcular validade (1 mês)
                    validade_auto = data_compra + timedelta(days=30)
                    st.info(f"⏰ Validade automática: {validade_auto.strftime('%d/%m/%Y')} (30 dias)")
                
                col_submit = st.columns([1, 1, 2])[1]
                with col_submit:
                    submitted = st.form_submit_button(
                        "✅ Criar Pacote",
                        use_container_width=True,
                        type="primary"
                    )
                
                if submitted:
                    # Verificar se já tem pacote ativo
                    pacote_ativo = st.session_state.pacotes[
                        (st.session_state.pacotes['Paciente'] == paciente_pacote) &
                        (st.session_state.pacotes['Status'] == 'ATIVO')
                    ]
                    
                    if not pacote_ativo.empty:
                        validade_antiga = pd.to_datetime(pacote_ativo.iloc[0]['Validade']).date()
                        if validade_antiga >= hoje_brasil():
                            st.warning(f"⚠️ Paciente já possui pacote ativo até {validade_antiga.strftime('%d/%m/%Y')}")
                        else:
                            # Desativar pacote vencido
                            idx = pacote_ativo.index[0]
                            st.session_state.pacotes.at[idx, 'Status'] = 'VENCIDO'
                    
                    # Criar novo pacote
                    novo_id = gerar_id_sequencial(st.session_state.pacotes)
                    novo_pacote = pd.DataFrame([{
                        "ID": novo_id,
                        "Paciente": paciente_pacote,
                        "QtdSessoes": qtd_sessoes,
                        "Valor": round(valor_pacote, 2),
                        "DataCompra": data_compra,
                        "Validade": validade_auto,
                        "Status": "ATIVO"
                    }])
                    
                    st.session_state.pacotes = pd.concat(
                        [st.session_state.pacotes, novo_pacote],
                        ignore_index=True
                    )
                    
                    salvar_pacotes(st.session_state.pacotes)
                    registrar_historico(
                        "PACOTE_CRIADO",
                        f"ID {novo_id} - {paciente_pacote} - {qtd_sessoes} sessões"
                    )
                    
                    st.success(f"✅ Pacote criado! ID: {novo_id}")
                    st.success(f"📅 Válido até: {validade_auto.strftime('%d/%m/%Y')}")
                    st.balloons()
                    st.rerun()
    
    # --- TAB 2: LISTA ---
    with tab2:
        st.subheader("Pacotes Cadastrados")
        
        if st.session_state.pacotes.empty:
            st.info("Nenhum pacote cadastrado.")
        else:
            # Atualizar status de pacotes vencidos
            hoje = hoje_brasil()
            for idx, pacote in st.session_state.pacotes.iterrows():
                if pacote['Status'] == 'ATIVO':
                    validade = pd.to_datetime(pacote['Validade']).date()
                    if validade < hoje:
                        st.session_state.pacotes.at[idx, 'Status'] = 'VENCIDO'
            
            salvar_pacotes(st.session_state.pacotes)
            
            # Filtros
            filtro_status_pacote = st.selectbox(
                "Filtrar por status:",
                ["Todos", "ATIVO", "VENCIDO", "CANCELADO"]
            )
            
            df_pacotes_show = st.session_state.pacotes.copy()
            
            if filtro_status_pacote != "Todos":
                df_pacotes_show = df_pacotes_show[
                    df_pacotes_show['Status'] == filtro_status_pacote
                ]
            
            # Calcular sessões utilizadas
            sessoes_info = []
            
            for _, pacote in df_pacotes_show.iterrows():
                info = calcular_sessoes_restantes(
                    pacote['Paciente'],
                    st.session_state.agendamentos,
                    st.session_state.pacotes
                )
                
                if info:
                    utilizadas = int(pacote['QtdSessoes']) - info['restantes']
                    sessoes_info.append(f"{utilizadas}/{int(pacote['QtdSessoes'])}")
                else:
                    sessoes_info.append("0/0")
            
            df_pacotes_show['Sessões'] = sessoes_info
            
            # Formatar datas
            df_display = df_pacotes_show[[
                'ID', 'Paciente', 'QtdSessoes', 'Sessões', 
                'Valor', 'DataCompra', 'Validade', 'Status'
            ]].copy()
            
            df_display['Valor'] = df_display['Valor'].apply(lambda x: f"R$ {x:.2f}")
            df_display['DataCompra'] = df_display['DataCompra'].apply(lambda x: x.strftime('%d/%m/%Y'))
            df_display['Validade'] = df_display['Validade'].apply(lambda x: x.strftime('%d/%m/%Y'))
            
            # Destacar status
            def highlight_status(row):
                if row['Status'] == 'ATIVO':
                    return ['background-color: #d4edda'] * len(row)
                elif row['Status'] == 'VENCIDO':
                    return ['background-color: #f8d7da'] * len(row)
                else:
                    return [''] * len(row)
            
            st.dataframe(
                df_display.style.apply(highlight_status, axis=1),
                use_container_width=True,
                hide_index=True
            )
            
            st.divider()
            
            # Resumo financeiro
            col1, col2, col3 = st.columns(3)
            
            with col1:
                total_pacotes = len(df_pacotes_show)
                st.metric("📦 Total de Pacotes", total_pacotes)
            
            with col2:
                ativos = len(df_pacotes_show[df_pacotes_show['Status'] == 'ATIVO'])
                st.metric("✅ Pacotes Ativos", ativos)
            
            with col3:
                receita_pacotes = df_pacotes_show['Valor'].sum()
                st.metric("💰 Receita Total", f"R$ {receita_pacotes:,.2f}")

# ==============================================================================
# LEMBRETES WHATSAPP
# ==============================================================================
elif menu == "📱 Lembretes":
    st.title("📱 Lembretes WhatsApp")
    
    st.info("💡 Envie lembretes automáticos de confirmação de consultas")
    
    # Buscar consultas nas próximas 48h
    hoje = hoje_brasil()
    amanha = hoje + timedelta(days=1)
    depois_amanha = hoje + timedelta(days=2)
    
    proximas = st.session_state.agendamentos[
        (st.session_state.agendamentos['Data'] >= hoje) &
        (st.session_state.agendamentos['Data'] <= depois_amanha) &
        (st.session_state.agendamentos['Status'].isin(['🔵 Agendado', '🟢 Confirmado']))
    ].sort_values(['Data', 'Hora'])
    
    if proximas.empty:
        st.info("Nenhuma consulta nas próximas 48 horas.")
    else:
        st.write(f"**{len(proximas)} consulta(s) encontrada(s)**")
        
        for idx, consulta in proximas.iterrows():
            with st.expander(
                f"📅 {consulta['Data'].strftime('%d/%m/%Y')} às {consulta['Hora'].strftime('%H:%M')} - {consulta['Paciente']}"
            ):
                # Buscar telefone do paciente
                paciente_info = st.session_state.pacientes[
                    st.session_state.pacientes['Nome'] == consulta['Paciente']
                ]
                
                if paciente_info.empty or not paciente_info.iloc[0]['Telefone']:
                    st.warning("⚠️ Paciente sem telefone cadastrado")
                else:
                    telefone = paciente_info.iloc[0]['Telefone']
                    
                    # Mensagem padrão
                    dias_falta = (consulta['Data'] - hoje).days
                    
                    if dias_falta == 0:
                        periodo = "hoje"
                    elif dias_falta == 1:
                        periodo = "amanhã"
                    else:
                        periodo = f"em {dias_falta} dias"
                    
                    mensagem = f"""Olá, {consulta['Paciente']}! 🧠

Este é um lembrete da sua consulta:

📅 Data: {consulta['Data'].strftime('%d/%m/%Y')} ({periodo})
⏰ Horário: {consulta['Hora'].strftime('%H:%M')}
💼 Serviço: {consulta['Servico']}

📍 Local: Consultório Dr. Radamés

Por favor, confirme sua presença ou avise caso precise remarcar.

Qualquer dúvida, estou à disposição! 😊"""
                    
                    msg_editada = st.text_area(
                        "Editar mensagem:",
                        value=mensagem,
                        height=200,
                        key=f"msg_{idx}"
                    )
                    
                    # Gerar link WhatsApp
                    tel_limpo = limpar_telefone(telefone)
                    msg_encoded = urllib.parse.quote(msg_editada)
                    link_whats = f"https://wa.me/55{tel_limpo}?text={msg_encoded}"
                    
                    st.link_button(
                        "📱 Enviar via WhatsApp",
                        link_whats,
                        use_container_width=True
                    )
    
    st.divider()
    
    # Envio manual
    st.subheader("📤 Envio Manual")
    
    with st.form("form_lembrete_manual"):
        paciente_manual = st.selectbox(
            "Selecione o paciente:",
            options=sorted(st.session_state.pacientes['Nome'].unique())
        )
        
        mensagem_manual = st.text_area(
            "Mensagem:",
            placeholder="Digite sua mensagem...",
            height=150
        )
        
        if st.form_submit_button("📱 Gerar Link WhatsApp", use_container_width=True, type="primary"):
            paciente_info = st.session_state.pacientes[
                st.session_state.pacientes['Nome'] == paciente_manual
            ].iloc[0]
            
            if not paciente_info['Telefone']:
                st.error("❌ Paciente sem telefone cadastrado")
            else:
                tel_limpo = limpar_telefone(paciente_info['Telefone'])
                msg_encoded = urllib.parse.quote(mensagem_manual)
                link_whats = f"https://wa.me/55{tel_limpo}?text={msg_encoded}"
                
                st.link_button(
                    "📱 Abrir WhatsApp",
                    link_whats,
                    use_container_width=True
                )

# ==============================================================================
# RELATÓRIOS
# ==============================================================================
elif menu == "📈 Relatórios":
    st.title("📈 Relatórios e Estatísticas")
    
    # Período
    col1, col2 = st.columns(2)
    with col1:
        data_inicio_rel = st.date_input(
            "Data Início",
            value=hoje_brasil().replace(day=1),  # Primeiro dia do mês
            format="DD/MM/YYYY"
        )
    with col2:
        data_fim_rel = st.date_input(
            "Data Fim",
            value=hoje_brasil(),
            format="DD/MM/YYYY"
        )
    
    # Filtrar dados
    df_rel = st.session_state.agendamentos[
        (st.session_state.agendamentos['Data'] >= data_inicio_rel) &
        (st.session_state.agendamentos['Data'] <= data_fim_rel)
    ]
    
    if df_rel.empty:
        st.info("Sem dados para o período selecionado.")
    else:
        # Métricas principais
        st.subheader("📊 Resumo do Período")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_consultas = len(df_rel)
            st.metric("📅 Total de Consultas", total_consultas)
        
        with col2:
            realizadas = len(df_rel[df_rel['Status'] == '✅ Realizado'])
            taxa = (realizadas / total_consultas * 100) if total_consultas > 0 else 0
            st.metric("✅ Realizadas", realizadas, f"{taxa:.1f}%")
        
        with col3:
            canceladas = len(df_rel[df_rel['Status'] == '🔴 Cancelado'])
            st.metric("🔴 Canceladas", canceladas)
        
        with col4:
            faltas = len(df_rel[df_rel['Status'] == '⚫ Faltou'])
            st.metric("⚫ Faltas", faltas)
        
        st.divider()
        
        # Receita
        st.subheader("💰 Análise Financeira")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            receita_total = df_rel[df_rel['Status'] == '✅ Realizado']['ValorFinal'].sum()
            st.metric("💰 Receita Total", f"R$ {receita_total:,.2f}")
        
        with col2:
            a_receber = df_rel[
                (df_rel['Pagamento'] == 'NÃO PAGO') &
                (df_rel['Status'] == '✅ Realizado')
            ]['ValorFinal'].sum()
            st.metric("⏳ A Receber", f"R$ {a_receber:,.2f}")
        
        with col3:
            ticket_medio = receita_total / realizadas if realizadas > 0 else 0
            st.metric("📊 Ticket Médio", f"R$ {ticket_medio:.2f}")
        
        st.divider()
        
        # Gráficos
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Consultas por Status")
            status_count = df_rel['Status'].value_counts()
            st.bar_chart(status_count)
        
        with col2:
            st.subheader("💼 Serviços Realizados")
            servicos_count = df_rel[df_rel['Status'] == '✅ Realizado']['Servico'].value_counts()
            st.bar_chart(servicos_count)
        
        st.divider()
        
        # Top pacientes
        st.subheader("👥 Top 10 Pacientes")
        top_pacientes = df_rel['Paciente'].value_counts().head(10)
        
        df_top = pd.DataFrame({
            'Paciente': top_pacientes.index,
            'Consultas': top_pacientes.values
        })
        
        st.dataframe(df_top, use_container_width=True, hide_index=True)
        
        st.divider()
        
        # Exportar relatório
        if st.button("📄 Gerar Relatório PDF", use_container_width=True, type="primary"):
            pdf = gerar_agenda_pdf(df_rel, data_inicio_rel, data_fim_rel)
            if pdf:
                st.download_button(
                    "⬇️ Baixar Relatório",
                    pdf,
                    f"relatorio_{data_inicio_rel}_{data_fim_rel}.pdf",
                    "application/pdf",
                    use_container_width=True
                )

# ==============================================================================
# MANUTENÇÃO
# ==============================================================================
elif menu == "🛠️ Manutenção":
    st.title("🛠️ Manutenção do Sistema")
    
    tab1, tab2, tab3 = st.tabs(["📋 Logs", "📜 Histórico", "⚙️ Configurações"])
    
    # --- TAB 1: LOGS ---
    with tab1:
        st.subheader("📋 Logs de Erro")
        
        if os.path.exists(ARQUIVO_LOG):
            with open(ARQUIVO_LOG, "r") as f:
                log_content = f.read()
            
            if log_content.strip():
                st.text_area("", log_content, height=300)
                
                if st.button("🗑️ Limpar Logs"):
                    open(ARQUIVO_LOG, 'w').close()
                    st.success("✅ Logs limpos!")
                    st.rerun()
            else:
                st.success("✅ Sem erros registrados!")
        else:
            st.success("✅ Sem erros registrados!")
    
    # --- TAB 2: HISTÓRICO ---
    with tab2:
        st.subheader("📜 Histórico de Alterações")
        
        if os.path.exists(ARQUIVO_HISTORICO):
            try:
                df_hist = pd.read_csv(ARQUIVO_HISTORICO)
                df_hist = df_hist.sort_values('Timestamp', ascending=False)
                
                st.dataframe(df_hist, use_container_width=True, hide_index=True)
                
                csv_hist = df_hist.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "📥 Exportar Histórico",
                    csv_hist,
                    "historico.csv",
                    "text/csv"
                )
                
                if st.button("🗑️ Limpar Histórico"):
                    os.remove(ARQUIVO_HISTORICO)
                    st.success("✅ Histórico limpo!")
                    st.rerun()
            except:
                st.info("Histórico vazio ou corrompido.")
        else:
            st.info("Nenhuma alteração registrada ainda.")
    
    # --- TAB 3: CONFIGURAÇÕES ---
    with tab3:
        st.subheader("⚙️ Configurações do Sistema")
        
        st.write("**Informações:**")
        st.write(f"- Versão: {VERSAO}")
        st.write(f"- Pacientes: {len(st.session_state.pacientes)}")
        st.write(f"- Agendamentos: {len(st.session_state.agendamentos)}")
        st.write(f"- Pacotes: {len(st.session_state.pacotes)}")
        
        st.divider()
        
        st.write("**Serviços e Preços:**")
        for servico, preco in SERVICOS.items():
            st.write(f"- {servico}: R$ {preco:.2f}")
        
        st.divider()
        
        st.write("**Arquivos:**")
        arquivos = [
            ARQUIVO_AGENDAMENTOS,
            ARQUIVO_PACIENTES,
            ARQUIVO_PACOTES,
            ARQUIVO_HISTORICO,
            ARQUIVO_LOG
        ]
        
        for arq in arquivos:
            if os.path.exists(arq):
                tamanho = os.path.getsize(arq) / 1024
                st.write(f"- ✅ {arq} ({tamanho:.1f} KB)")
            else:
                st.write(f"- ❌ {arq} (não existe)")
        
        st.divider()
        
        if st.button("🔄 Recarregar Dados", use_container_width=True):
            st.session_state.pacientes = carregar_pacientes()
            st.session_state.agendamentos = carregar_agendamentos()
            st.session_state.pacotes = carregar_pacotes()
            st.success("✅ Dados recarregados!")
            st.rerun()
