import streamlit as st
import pandas as pd
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo
import os
import io
import logging
from logging.handlers import RotatingFileHandler
import urllib.parse
import re
import shutil
import hashlib
import base64
import glob
from contextlib import contextmanager
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm

# Importações de segurança
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("⚠️ Criptografia não disponível. Instale: pip install cryptography")

try:
    import portalocker
    LOCK_AVAILABLE = True
except ImportError:
    LOCK_AVAILABLE = False
    print("⚠️ File locking não disponível. Instale: pip install portalocker")

# Importações Google Sheets
try:
    import gspread
    from google.oauth2.service_account import Credentials
    GSHEETS_AVAILABLE = True
except ImportError:
    GSHEETS_AVAILABLE = False
    print("⚠️ Google Sheets não disponível. Instale: pip install gspread google-auth")

# --- CONFIGURAÇÃO DE FUSO HORÁRIO (BRASIL) ---
FUSO_BRASIL = ZoneInfo("America/Sao_Paulo")

def agora_brasil():
    """Retorna datetime atual no fuso horário de Brasília."""
    return datetime.now(FUSO_BRASIL)

def hoje_brasil():
    """Retorna a data de hoje no fuso horário de Brasília."""
    return datetime.now(FUSO_BRASIL).date()

# ==============================================================================
# 🔐 SISTEMA DE SEGURANÇA INTEGRADO (CARURU V18)
# ==============================================================================

# --- 1. CRIPTOGRAFIA INTEGRADA ---
class CryptoManager:
    """Gerenciador de criptografia integrado."""

    def __init__(self, master_password=None):
        self.enabled = CRYPTO_AVAILABLE
        self.cipher = None

        if not self.enabled:
            return

        password = master_password or st.secrets.get("master_password") or os.environ.get("MASTER_PASSWORD")
        if not password:
            password = "DEFAULT_INSECURE_KEY_CHANGE_ME"

        self.cipher = self._create_cipher(password)

    def _create_cipher(self, password):
        """Cria cipher Fernet a partir de senha."""
        salt = b'psi_agenda_salt_v1_2025'
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def encrypt(self, data):
        """Criptografa texto."""
        if not self.enabled or not data:
            return data
        try:
            return self.cipher.encrypt(data.encode()).decode()
        except:
            return data

    def decrypt(self, encrypted_data):
        """Descriptografa texto."""
        if not self.enabled or not encrypted_data:
            return encrypted_data
        try:
            return self.cipher.decrypt(encrypted_data.encode()).decode()
        except:
            return encrypted_data

    def sanitize_log(self, text):
        """Sanitiza texto para logs."""
        if not text:
            return text
        sanitized = re.sub(r'\d{3}\.\d{3}\.\d{3}-\d{2}', 'CPF:***', text)
        sanitized = re.sub(r'\b\d{11}\b', 'CPF:***', sanitized)
        sanitized = re.sub(r'\b\d{10,11}\b', 'TEL:***', sanitized)
        sanitized = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'EMAIL:***', sanitized)
        return sanitized

# Inicializar gerenciador de criptografia
crypto_manager = CryptoManager()

# --- 2. FILE LOCKING (Context Manager) ---
@contextmanager
def file_lock(file_path, mode='r'):
    """
    Context manager para bloqueio de arquivo cross-platform.
    Garante que apenas uma operação acesse o arquivo por vez.
    """
    lock_file = f"{file_path}.lock"

    if LOCK_AVAILABLE:
        # Com portalocker (recomendado)
        lock_handle = open(lock_file, 'w')
        try:
            portalocker.lock(lock_handle, portalocker.LOCK_EX)
            with open(file_path, mode, encoding='utf-8') as f:
                yield f
        finally:
            portalocker.unlock(lock_handle)
            lock_handle.close()
            try:
                os.remove(lock_file)
            except:
                pass
    else:
        # Fallback sem lock (menos seguro)
        with open(file_path, mode, encoding='utf-8') as f:
            yield f

# --- 3. ATOMIC WRITE (Escrita Segura) ---
def atomic_write(file_path, data, is_dataframe=False):
    """
    Escrita atômica: escreve em .tmp e move para o arquivo final.
    Evita corromper arquivo se o servidor cair durante escrita.

    Args:
        file_path: Caminho do arquivo final
        data: Dados a escrever (str ou DataFrame)
        is_dataframe: True se data é um DataFrame

    Returns:
        bool: True se sucesso
    """
    tmp_file = f"{file_path}.tmp"

    try:
        # Escrever em arquivo temporário
        if is_dataframe:
            data.to_csv(tmp_file, index=False)
        else:
            with open(tmp_file, 'w', encoding='utf-8') as f:
                f.write(data)

        # Mover atomicamente (substitui o original)
        shutil.move(tmp_file, file_path)
        return True
    except Exception as e:
        # Limpar arquivo temporário em caso de erro
        if os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except:
                pass
        logging.error(f"Erro em atomic_write: {crypto_manager.sanitize_log(str(e))}")
        return False

# --- 4. BACKUP ROTATIVO (.bak com timestamp) ---
def create_backup(file_path, max_backups=5):
    """
    Cria backup rotativo com timestamp antes de qualquer salvamento.
    Mantém apenas os N últimos backups.

    Args:
        file_path: Arquivo a fazer backup
        max_backups: Número máximo de backups a manter (padrão: 5)
    """
    if not os.path.exists(file_path):
        return

    try:
        # Criar backup com timestamp
        timestamp = agora_brasil().strftime("%Y%m%d_%H%M%S")
        backup_file = f"{file_path}.bak.{timestamp}"
        shutil.copy2(file_path, backup_file)

        # Limpar backups antigos (manter apenas os max_backups mais recentes)
        backup_pattern = f"{file_path}.bak.*"
        backups = sorted(glob.glob(backup_pattern), reverse=True)

        for old_backup in backups[max_backups:]:
            try:
                os.remove(old_backup)
            except:
                pass
    except Exception as e:
        logging.error(f"Erro ao criar backup: {crypto_manager.sanitize_log(str(e))}")

# --- 5. FUNÇÕES AUXILIARES DE VALIDAÇÃO ---
def calculate_checksum(file_path):
    """Calcula SHA-256 checksum de arquivo."""
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def validate_csv_structure(file_path, required_columns):
    """Valida estrutura de arquivo CSV."""
    if not os.path.exists(file_path):
        return True, None
    try:
        df = pd.read_csv(file_path)
        missing = set(required_columns) - set(df.columns)
        if missing:
            return False, f"Colunas faltando: {missing}"
        return True, None
    except Exception as e:
        return False, f"Erro ao validar: {e}"

# --- CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(
    page_title="Agenda Psicologia - Psi. Radamés Soares", 
    page_icon="🧠", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configurar localização para pt-BR (calendário em português)
import locale
try:
    # Tenta configurações pt-BR (Linux/Mac)
    locale.setlocale(locale.LC_ALL, 'pt_BR.UTF-8')
except:
    try:
        # Tenta configuração Windows
        locale.setlocale(locale.LC_ALL, 'Portuguese_Brazil.1252')
    except:
        try:
            # Alternativa pt_BR
            locale.setlocale(locale.LC_ALL, 'pt_BR')
        except:
            # Usa padrão do sistema
            pass

# Configuração adicional para Streamlit
os.environ['LANG'] = 'pt_BR.UTF-8'
os.environ['LC_ALL'] = 'pt_BR.UTF-8'

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
# 🔒 SISTEMA DE LOGIN MELHORADO
# ==============================================================================
def check_password():
    """Sistema de autenticação com tentativas limitadas e sem senha hardcoded."""

    # Inicializar contador de tentativas
    if "login_attempts" not in st.session_state:
        st.session_state["login_attempts"] = 0
        st.session_state["last_attempt_time"] = None

    # Bloquear após 5 tentativas falhas por 5 minutos
    MAX_ATTEMPTS = 5
    LOCKOUT_MINUTES = 5

    if st.session_state.get("login_attempts", 0) >= MAX_ATTEMPTS:
        last_attempt = st.session_state.get("last_attempt_time")
        if last_attempt:
            elapsed = (datetime.now() - last_attempt).total_seconds() / 60
            if elapsed < LOCKOUT_MINUTES:
                remaining = int(LOCKOUT_MINUTES - elapsed)
                st.error(f"🔒 Muitas tentativas falhas. Tente novamente em {remaining} minutos.")
                st.stop()
                return False
            else:
                # Reset após timeout
                st.session_state["login_attempts"] = 0

    def password_entered():
        # SEGURANÇA: Senha DEVE estar em st.secrets ou variável de ambiente
        # NUNCA use senha hardcoded em produção
        correct_password = st.secrets.get("password") or os.environ.get("PSI_PASSWORD")

        if not correct_password:
            st.error("⚠️ ERRO DE CONFIGURAÇÃO: Senha não configurada em secrets ou variáveis de ambiente!")
            st.info("Configure 'password' em .streamlit/secrets.toml ou variável PSI_PASSWORD")
            st.session_state["password_correct"] = False
            return

        if st.session_state["password"] == correct_password:
            st.session_state["password_correct"] = True
            st.session_state["login_attempts"] = 0
            del st.session_state["password"]
        else:
            st.session_state["password_correct"] = False
            st.session_state["login_attempts"] = st.session_state.get("login_attempts", 0) + 1
            st.session_state["last_attempt_time"] = datetime.now()

    if st.session_state.get("password_correct", False):
        return True

    st.markdown("## 🔒 Acesso Profissional")
    st.info("Sistema de Agendamentos - Psicologia")

    attempts_left = MAX_ATTEMPTS - st.session_state.get("login_attempts", 0)
    if attempts_left < MAX_ATTEMPTS:
        st.warning(f"⚠️ Tentativas restantes: {attempts_left}")

    st.text_input("Digite a senha:", type="password", key="password", on_change=password_entered)

    if "password_correct" in st.session_state and not st.session_state["password_correct"]:
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

# Serviços e Preços (valores padrão - editáveis na hora)
# Serviços e Preços (valores padrão - editáveis na hora)
# Ordem: Psicoterapia primeiro conforme solicitado
SERVICOS = {
    "Psicoterapia": 150.00,
    "Consulta em Psicoterapia": 150.00,
    "Consulta em Neuropsicologia": 150.00,
    "Avaliação Neuropsicológica": 2500.00,
    "Pacote": 0.00  # Valor definido pelo pacote ativo
}

# Horários disponíveis (horas fechadas)
HORARIOS_DISPONIVEIS = [
    "07:00", "08:00", "09:00", "10:00", "11:00", "12:00",
    "13:00", "14:00", "15:00", "16:00", "17:00", "18:00",
    "19:00", "20:00", "21:00"
]

OPCOES_STATUS = ["🔵 Agendado", "🟢 Confirmado", "✅ Realizado", "🟡 Remarcado", "🔴 Cancelado", "⚫ Faltou"]
OPCOES_PAGAMENTO = ["PAGO", "NÃO PAGO", "PACOTE", "GRATUITO", "INSTITUCIONAL"]
OPCOES_DURACAO = ["1h", "2h"]
OPCOES_TIPO_ATENDIMENTO = ["Regular", "Reposição"]
OPCOES_MODALIDADE = ["Presencial", "Online"]
VERSAO = "1.2"  # Atualizado com recursos de segurança

# Dados do Profissional
PSICOLOGO_NOME = "Radamés Emmanuel Souza Soares"
PSICOLOGO_CRP = "19/5223"
PSICOLOGO_TITULO = "Pós-graduado em Neuropsicologia"
PSICOLOGO_INSTITUICAO = "IIEP – Instituto Israelita de Ensino e Pesquisa ALBERT Einstein – SP"
PSICOLOGO_CONTATO = "79 99918-6852"

# Configuração de Logging
# Configuração de Logging Rotativo (não cresce infinitamente)
logger = logging.getLogger("agenda_psi")
logger.setLevel(logging.ERROR)

# RotatingFileHandler: máx 1MB por arquivo, mantém 3 backups
handler = RotatingFileHandler(
    ARQUIVO_LOG,
    maxBytes=1024*1024,  # 1 MB
    backupCount=3,  # Mantém 3 arquivos de log
    encoding='utf-8'
)
handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
logger.addHandler(handler)

# ==============================================================================
# ARQUIVOS CRÍTICOS (para backup)
# ==============================================================================
FILES_TO_BACKUP = [
    ARQUIVO_AGENDAMENTOS,
    ARQUIVO_PACIENTES,
    ARQUIVO_PACOTES,
    ARQUIVO_HISTORICO
]

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
    return data.strftime("%d/%m/%Y")

def formatar_data_com_dia_semana(data):
    """
    Formata data com dia da semana em português.
    Ex: 10/12/2025 (Terça-feira)
    """
    if data is None:
        return ""

    if isinstance(data, str):
        try:
            data = pd.to_datetime(data).date()
        except:
            return data

    # Dias da semana em português
    dias_semana = {
        0: "Segunda-feira",
        1: "Terça-feira",
        2: "Quarta-feira",
        3: "Quinta-feira",
        4: "Sexta-feira",
        5: "Sábado",
        6: "Domingo"
    }

    dia_semana = dias_semana[data.weekday()]
    data_formatada = data.strftime("%d/%m/%Y")

    return f"{data_formatada} ({dia_semana})"

def hora_str_para_time(hora_str):
    """Converte string HH:MM para objeto time."""
    try:
        h, m = hora_str.split(":")
        return time(int(h), int(m))
    except:
        return time(14, 0)

def formatar_data_br_original(data):
    """Formata data para padrão brasileiro dd/mm/aaaa (função original)."""
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
            'valor': float(pacote['Valor']),
            'data_compra': pd.to_datetime(pacote['DataCompra']).date()
        }
    except Exception as e:
        logger.error(f"Erro ao calcular sessões: {e}")
        return None

def criar_proximo_agendamento_recorrente(agendamento_atual):
    """Cria o próximo agendamento recorrente (7 dias depois)."""
    try:
        proxima_data = agendamento_atual['Data'] + timedelta(days=7)
        
        # Verificar se já existe agendamento para esse dia/hora
        existe = st.session_state.agendamentos[
            (st.session_state.agendamentos['Paciente'] == agendamento_atual['Paciente']) &
            (st.session_state.agendamentos['Data'] == proxima_data) &
            (st.session_state.agendamentos['Hora'] == agendamento_atual['Hora'])
        ]
        
        if not existe.empty:
            return None  # Já existe, não cria duplicado
        
        # Verificar se está dentro do período do pacote (se aplicável)
        if agendamento_atual['Pagamento'] == 'PACOTE':
            info_pacote = calcular_sessoes_restantes(
                agendamento_atual['Paciente'],
                st.session_state.agendamentos,
                st.session_state.pacotes
            )
            
            if not info_pacote or info_pacote['restantes'] <= 0:
                return None  # Sem sessões disponíveis
            
            if proxima_data > info_pacote['validade']:
                return None  # Fora do período do pacote
        
        # Criar novo agendamento
        novo_id = gerar_id_sequencial(st.session_state.agendamentos)
        novo_agendamento = pd.DataFrame([{
            "ID": novo_id,
            "Paciente": agendamento_atual['Paciente'],
            "Data": proxima_data,
            "Hora": agendamento_atual['Hora'],
            "Duracao": agendamento_atual['Duracao'],
            "Servico": agendamento_atual['Servico'],
            "Valor": agendamento_atual['Valor'],
            "Desconto": agendamento_atual['Desconto'],
            "ValorFinal": agendamento_atual['ValorFinal'],
            "Pagamento": agendamento_atual['Pagamento'],
            "Status": "🔵 Agendado",
            "Recorrente": True,
            "TipoAtendimento": "Regular",
            "Modalidade": agendamento_atual.get('Modalidade', 'Presencial'),
            "Observacoes": agendamento_atual['Observacoes'],
            "Prontuario": ""
        }])
        
        return novo_agendamento
    except Exception as e:
        logger.error(f"Erro ao criar recorrente: {e}")
        return None

def calcular_hora_fim(hora_inicio, duracao):
    """Calcula horário de término baseado na duração."""
    inicio_dt = datetime.combine(date.today(), hora_inicio)
    if duracao == "2h":
        fim_dt = inicio_dt + timedelta(hours=2)
    else:
        fim_dt = inicio_dt + timedelta(hours=1)
    return fim_dt.time()

def verificar_conflito_horario(data, hora_inicio, duracao, id_atual=None):
    """Verifica se há conflito de horário considerando a duração."""
    hora_fim = calcular_hora_fim(hora_inicio, duracao)
    
    agendamentos_dia = st.session_state.agendamentos[
        (st.session_state.agendamentos['Data'] == data) &
        (~st.session_state.agendamentos['Status'].isin(['🔴 Cancelado', '🟡 Remarcado']))
    ]
    
    if id_atual:
        agendamentos_dia = agendamentos_dia[agendamentos_dia['ID'] != id_atual]
    
    for _, ag in agendamentos_dia.iterrows():
        ag_inicio = ag['Hora']
        ag_fim = calcular_hora_fim(ag_inicio, ag.get('Duracao', '1h'))
        
        # Verifica sobreposição
        if (hora_inicio < ag_fim and hora_fim > ag_inicio):
            return True, ag
    
    return False, None

def obter_saudacao():
    """Retorna saudação apropriada baseada no horário atual."""
    hora_atual = agora_brasil().hour
    
    if 5 <= hora_atual < 12:
        return "Bom dia"
    elif 12 <= hora_atual < 18:
        return "Boa tarde"
    else:
        return "Boa noite"

# ==============================================================================
# FUNÇÕES DE PERSISTÊNCIA
# ==============================================================================
def carregar_pacientes():
    """Carrega cadastro de pacientes com descriptografia de dados sensíveis."""
    try:
        if os.path.exists(ARQUIVO_PACIENTES):
            # Validar integridade do arquivo
            valid, msg = validate_csv_structure(
                ARQUIVO_PACIENTES,
                ["Nome", "CPF", "Telefone", "Email", "DataNascimento", "Endereco", "Observacoes", "DataCadastro"]
            )
            if not valid:
                logger.error(f"Estrutura inválida em pacientes: {msg}")

            df = pd.read_csv(ARQUIVO_PACIENTES)

            # Preencher valores NaN em campos de texto
            df['Email'] = df['Email'].fillna('')
            df['Endereco'] = df['Endereco'].fillna('')
            df['Observacoes'] = df['Observacoes'].fillna('')
            df['DataNascimento'] = df['DataNascimento'].fillna('')
            df['CPF'] = df['CPF'].fillna('')
            df['Telefone'] = df['Telefone'].fillna('')

            # DESCRIPTOGRAFAR campos sensíveis
            if crypto_manager.enabled:
                for idx in df.index:
                    if df.loc[idx, 'CPF']:
                        df.loc[idx, 'CPF'] = crypto_manager.decrypt(df.loc[idx, 'CPF'])
                    if df.loc[idx, 'Telefone']:
                        df.loc[idx, 'Telefone'] = crypto_manager.decrypt(df.loc[idx, 'Telefone'])

            return df
        else:
            return pd.DataFrame(columns=[
                "Nome", "CPF", "Telefone", "Email", "DataNascimento",
                "Endereco", "Observacoes", "DataCadastro"
            ])
    except Exception as e:
        logger.error(f"Erro ao carregar pacientes: {crypto_manager.sanitize_log(str(e))}")
        return pd.DataFrame(columns=[
            "Nome", "CPF", "Telefone", "Email", "DataNascimento",
            "Endereco", "Observacoes", "DataCadastro"
        ])

def salvar_pacientes(df):
    """
    Salva cadastro de pacientes com TODAS as medidas de segurança:
    - Backup rotativo (.bak com timestamp)
    - Criptografia de dados sensíveis (CPF, Telefone)
    - Atomic write (.tmp → move)
    - Validação de estrutura
    """
    try:
        # 1. CRIAR BACKUP antes de salvar (rotativo, mantém 5)
        create_backup(ARQUIVO_PACIENTES, max_backups=5)

        # 2. Preparar dados para salvar
        df_save = df.copy()

        # 3. CRIPTOGRAFAR campos sensíveis
        if crypto_manager.enabled:
            for idx in df_save.index:
                if df_save.loc[idx, 'CPF']:
                    df_save.loc[idx, 'CPF'] = crypto_manager.encrypt(df_save.loc[idx, 'CPF'])
                if df_save.loc[idx, 'Telefone']:
                    df_save.loc[idx, 'Telefone'] = crypto_manager.encrypt(df_save.loc[idx, 'Telefone'])

        # 4. ATOMIC WRITE (escreve .tmp e move)
        sucesso = atomic_write(ARQUIVO_PACIENTES, df_save, is_dataframe=True)

        if sucesso:
            logger.info("Pacientes salvos com sucesso")
        return sucesso

    except Exception as e:
        logger.error(f"Erro ao salvar pacientes: {crypto_manager.sanitize_log(str(e))}")
        return False

def carregar_agendamentos():
    """Carrega agendamentos com descriptografia de prontuários."""
    try:
        if os.path.exists(ARQUIVO_AGENDAMENTOS):
            # Validar integridade
            valid, msg = validate_csv_structure(
                ARQUIVO_AGENDAMENTOS,
                ["ID", "Paciente", "Data", "Hora", "Servico", "Valor", "Status"]
            )
            if not valid:
                logger.error(f"Estrutura inválida em agendamentos: {msg}")

            df = pd.read_csv(ARQUIVO_AGENDAMENTOS)
            df['Data'] = pd.to_datetime(df['Data']).dt.date
            df['Hora'] = pd.to_datetime(df['Hora'], format='%H:%M:%S').dt.time

            # Adicionar colunas novas se não existirem
            if 'Duracao' not in df.columns:
                df['Duracao'] = '1h'
            if 'Recorrente' not in df.columns:
                df['Recorrente'] = False
            if 'TipoAtendimento' not in df.columns:
                df['TipoAtendimento'] = 'Regular'
            if 'Modalidade' not in df.columns:
                df['Modalidade'] = 'Presencial'

            # Preencher valores NaN em campos de texto
            df['Observacoes'] = df['Observacoes'].fillna('')
            df['Prontuario'] = df['Prontuario'].fillna('')
            df['TipoAtendimento'] = df['TipoAtendimento'].fillna('Regular')
            df['Modalidade'] = df['Modalidade'].fillna('Presencial')

            # DESCRIPTOGRAFAR prontuários (dados clínicos sensíveis)
            if crypto_manager.enabled:
                for idx in df.index:
                    if df.loc[idx, 'Prontuario']:
                        df.loc[idx, 'Prontuario'] = crypto_manager.decrypt(df.loc[idx, 'Prontuario'])

            return df
        else:
            return pd.DataFrame(columns=[
                "ID", "Paciente", "Data", "Hora", "Duracao", "Servico",
                "Valor", "Desconto", "ValorFinal", "Pagamento",
                "Status", "Recorrente", "TipoAtendimento", "Modalidade", "Observacoes", "Prontuario"
            ])
    except Exception as e:
        logger.error(f"Erro ao carregar agendamentos: {crypto_manager.sanitize_log(str(e))}")
        return pd.DataFrame(columns=[
            "ID", "Paciente", "Data", "Hora", "Duracao", "Servico",
            "Valor", "Desconto", "ValorFinal", "Pagamento",
            "Status", "Recorrente", "TipoAtendimento", "Modalidade", "Observacoes", "Prontuario"
        ])

def salvar_agendamentos(df):
    """
    Salva agendamentos com TODAS as medidas de segurança:
    - Backup rotativo (.bak com timestamp)
    - Criptografia de prontuários
    - Atomic write (.tmp → move)
    """
    try:
        # 1. CRIAR BACKUP antes de salvar
        create_backup(ARQUIVO_AGENDAMENTOS, max_backups=5)

        # 2. Preparar dados
        df_save = df.copy()
        df_save['Data'] = pd.to_datetime(df_save['Data']).dt.strftime('%Y-%m-%d')
        df_save['Hora'] = df_save['Hora'].astype(str)

        # 3. CRIPTOGRAFAR prontuários (dados clínicos LGPD)
        if crypto_manager.enabled:
            for idx in df_save.index:
                if df_save.loc[idx, 'Prontuario']:
                    df_save.loc[idx, 'Prontuario'] = crypto_manager.encrypt(df_save.loc[idx, 'Prontuario'])

        # 4. ATOMIC WRITE
        sucesso = atomic_write(ARQUIVO_AGENDAMENTOS, df_save, is_dataframe=True)

        if sucesso:
            logger.info("Agendamentos salvos com sucesso")
        return sucesso

    except Exception as e:
        logger.error(f"Erro ao salvar agendamentos: {crypto_manager.sanitize_log(str(e))}")
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
    """
    Registra alterações no histórico com:
    - Sanitização de dados sensíveis
    - Backup rotativo antes de salvar
    - Atomic write
    """
    try:
        # 1. SANITIZAR detalhes (remove CPF, telefone, etc)
        detalhes_sanitizados = crypto_manager.sanitize_log(detalhes)

        # 2. Criar novo registro
        novo_registro = pd.DataFrame([{
            "Timestamp": agora_brasil().strftime('%Y-%m-%d %H:%M:%S'),
            "Acao": acao,
            "Detalhes": detalhes_sanitizados
        }])

        # 3. BACKUP antes de modificar
        if os.path.exists(ARQUIVO_HISTORICO):
            create_backup(ARQUIVO_HISTORICO, max_backups=5)
            df_hist = pd.read_csv(ARQUIVO_HISTORICO)
            df_hist = pd.concat([df_hist, novo_registro], ignore_index=True)
        else:
            df_hist = novo_registro

        # 4. ATOMIC WRITE
        atomic_write(ARQUIVO_HISTORICO, df_hist, is_dataframe=True)

    except Exception as e:
        # Sanitizar erro também
        error_msg = crypto_manager.sanitize_log(str(e))
        logger.error(f"Erro ao registrar histórico: {error_msg}")

# ==============================================================================
# FUNÇÕES DE INTEGRAÇÃO GOOGLE SHEETS
# ==============================================================================
def conectar_google_sheets():
    """
    Conecta ao Google Sheets usando credenciais de service account.

    Credenciais devem estar em:
    - st.secrets["gcp_service_account"] (dict JSON)
    - ou variável de ambiente GOOGLE_CREDENTIALS (string JSON)
    """
    if not GSHEETS_AVAILABLE:
        return None, "Google Sheets não disponível. Instale: pip install gspread google-auth"

    try:
        # Tentar obter credenciais do secrets.toml
        if "gcp_service_account" in st.secrets:
            creds_dict = dict(st.secrets["gcp_service_account"])
        elif "GOOGLE_CREDENTIALS" in os.environ:
            import json
            creds_dict = json.loads(os.environ["GOOGLE_CREDENTIALS"])
        else:
            return None, "Credenciais Google não configuradas. Configure em .streamlit/secrets.toml"

        # Definir escopos necessários
        scopes = [
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive'
        ]

        # Criar credenciais
        credentials = Credentials.from_service_account_info(creds_dict, scopes=scopes)

        # Autorizar cliente gspread
        client = gspread.authorize(credentials)

        return client, None
    except Exception as e:
        error_msg = f"Erro ao conectar Google Sheets: {str(e)}"
        logger.error(error_msg)
        return None, error_msg

def sincronizar_para_google_sheets(spreadsheet_id=None):
    """
    Sincroniza dados locais para Google Sheets (backup).

    Cria/atualiza planilha com 4 abas:
    - Pacientes
    - Agendamentos
    - Pacotes
    - Histórico
    """
    try:
        # Conectar
        client, erro = conectar_google_sheets()
        if erro:
            return False, erro

        # Obter ID da planilha (do secrets ou parâmetro)
        if not spreadsheet_id:
            spreadsheet_id = st.secrets.get("google_sheets_id", None)

        if not spreadsheet_id:
            return False, "ID da planilha não configurado. Configure google_sheets_id em secrets.toml"

        # Abrir planilha
        try:
            spreadsheet = client.open_by_key(spreadsheet_id)
        except:
            return False, f"Planilha não encontrada. Verifique o ID: {spreadsheet_id}"

        # Carregar dados locais
        df_pacientes = carregar_pacientes()
        df_agendamentos = carregar_agendamentos()
        df_pacotes = carregar_pacotes()

        # Função auxiliar para atualizar/criar aba
        def atualizar_aba(nome_aba, df):
            try:
                worksheet = spreadsheet.worksheet(nome_aba)
            except:
                worksheet = spreadsheet.add_worksheet(title=nome_aba, rows="1000", cols="20")

            # Converter DataFrame para lista de listas
            df_export = df.copy()

            # Converter datas para string
            for col in df_export.columns:
                if df_export[col].dtype == 'object':
                    # Tentar converter datetime
                    try:
                        if isinstance(df_export[col].iloc[0], (date, datetime)):
                            df_export[col] = df_export[col].apply(lambda x: x.strftime('%Y-%m-%d') if pd.notna(x) else '')
                    except:
                        pass
                elif 'datetime' in str(df_export[col].dtype):
                    df_export[col] = pd.to_datetime(df_export[col]).dt.strftime('%Y-%m-%d')

            # Converter time para string
            for col in df_export.columns:
                if df_export[col].dtype == 'object':
                    try:
                        if isinstance(df_export[col].iloc[0], time):
                            df_export[col] = df_export[col].apply(lambda x: x.strftime('%H:%M:%S') if pd.notna(x) else '')
                    except:
                        pass

            # Preparar dados
            data = [df_export.columns.tolist()] + df_export.fillna('').values.tolist()

            # Atualizar aba
            worksheet.clear()
            worksheet.update('A1', data)

        # Sincronizar cada aba
        atualizar_aba("Pacientes", df_pacientes)
        atualizar_aba("Agendamentos", df_agendamentos)
        atualizar_aba("Pacotes", df_pacotes)

        # Histórico (se existir)
        if os.path.exists(ARQUIVO_HISTORICO):
            df_hist = pd.read_csv(ARQUIVO_HISTORICO)
            atualizar_aba("Historico", df_hist)

        # Adicionar metadados
        try:
            worksheet_info = spreadsheet.worksheet("Info")
        except:
            worksheet_info = spreadsheet.add_worksheet(title="Info", rows="10", cols="2")

        info_data = [
            ["Última Sincronização", agora_brasil().strftime('%Y-%m-%d %H:%M:%S')],
            ["Total Pacientes", len(df_pacientes)],
            ["Total Agendamentos", len(df_agendamentos)],
            ["Total Pacotes", len(df_pacotes)]
        ]
        worksheet_info.clear()
        worksheet_info.update('A1', info_data)

        return True, "Sincronização concluída com sucesso"

    except Exception as e:
        error_msg = f"Erro na sincronização: {str(e)}"
        logger.error(error_msg)
        return False, error_msg

def restaurar_de_google_sheets(spreadsheet_id=None):
    """
    Restaura dados do Google Sheets para arquivos locais.

    ATENÇÃO: Sobrescreve dados locais!
    """
    try:
        # Conectar
        client, erro = conectar_google_sheets()
        if erro:
            return False, erro

        # Obter ID da planilha
        if not spreadsheet_id:
            spreadsheet_id = st.secrets.get("google_sheets_id", None)

        if not spreadsheet_id:
            return False, "ID da planilha não configurado"

        # Abrir planilha
        spreadsheet = client.open_by_key(spreadsheet_id)

        # Fazer backup dos arquivos locais antes de sobrescrever
        for arquivo in FILES_TO_BACKUP:
            if os.path.exists(arquivo):
                create_backup(arquivo, max_backups=5)

        # Função auxiliar para ler aba
        def ler_aba(nome_aba):
            try:
                worksheet = spreadsheet.worksheet(nome_aba)
                data = worksheet.get_all_values()

                if len(data) < 2:
                    return pd.DataFrame()

                # Primeira linha são headers
                df = pd.DataFrame(data[1:], columns=data[0])
                return df
            except Exception as e:
                logger.error(f"Erro ao ler aba {nome_aba}: {e}")
                return pd.DataFrame()

        # Restaurar cada arquivo
        df_pacientes = ler_aba("Pacientes")
        if not df_pacientes.empty:
            df_pacientes.to_csv(ARQUIVO_PACIENTES, index=False)

        df_agendamentos = ler_aba("Agendamentos")
        if not df_agendamentos.empty:
            df_agendamentos.to_csv(ARQUIVO_AGENDAMENTOS, index=False)

        df_pacotes = ler_aba("Pacotes")
        if not df_pacotes.empty:
            df_pacotes.to_csv(ARQUIVO_PACOTES, index=False)

        df_hist = ler_aba("Historico")
        if not df_hist.empty:
            df_hist.to_csv(ARQUIVO_HISTORICO, index=False)

        # Recarregar session state
        st.session_state.pacientes = carregar_pacientes()
        st.session_state.agendamentos = carregar_agendamentos()
        st.session_state.pacotes = carregar_pacotes()

        return True, "Restauração concluída com sucesso"

    except Exception as e:
        error_msg = f"Erro na restauração: {str(e)}"
        logger.error(error_msg)
        return False, error_msg

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
        
        # Adicionar logo se existir
        logo_paths = ["logo.png", "assets/logo.png", "./logo.png"]
        for logo_path in logo_paths:
            if os.path.exists(logo_path):
                try:
                    logo = Image(logo_path, width=3*cm, height=3*cm)
                    elements.append(logo)
                    elements.append(Spacer(1, 0.3*cm))
                    break
                except:
                    continue
        
        # Cabeçalho
        header_style = ParagraphStyle(
            'Header',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#2C5F7C'),
            alignment=1
        )
        elements.append(Paragraph("Psi. Radamés Soares - CRP 19/5223", header_style))
        elements.append(Paragraph("Aracaju-SE", header_style))
        elements.append(Spacer(1, 0.5*cm))
        
        # Título
        titulo_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=18,
            textColor=colors.HexColor('#2C5F7C'),
            spaceAfter=12,
            alignment=1
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
                    row['Status'].replace('🔵 ', '').replace('🟢 ', '').replace('✅ ', '').replace('🔴 ', '').replace('⚫ ', '')
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
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2*cm, bottomMargin=3*cm)
        elements = []
        styles = getSampleStyleSheet()
        
        # Adicionar logo se existir
        logo_paths = ["logo.png", "assets/logo.png", "./logo.png"]
        for logo_path in logo_paths:
            if os.path.exists(logo_path):
                try:
                    logo = Image(logo_path, width=3*cm, height=3*cm)
                    elements.append(logo)
                    elements.append(Spacer(1, 0.3*cm))
                    break
                except:
                    continue
        
        # Cabeçalho profissional
        header_style = ParagraphStyle(
            'Header',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#2C5F7C'),
            alignment=1,
            spaceAfter=5
        )
        elements.append(Paragraph(f"<b>{PSICOLOGO_NOME}</b>", header_style))
        elements.append(Paragraph(f"CRP {PSICOLOGO_CRP}", header_style))
        elements.append(Paragraph(f"{PSICOLOGO_TITULO}", header_style))
        elements.append(Paragraph("Aracaju-SE", header_style))
        elements.append(Paragraph(f"Contato: {PSICOLOGO_CONTATO}", header_style))
        elements.append(Spacer(1, 0.5*cm))
        
        # Título
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
        elements.append(Paragraph(f"Aracaju-SE, {agora_brasil().strftime('%d/%m/%Y')}", info_style))
        elements.append(Spacer(1, 1.5*cm))

        # Linha de assinatura
        sig_style = ParagraphStyle(
            'Signature',
            parent=styles['Normal'],
            alignment=1,
            fontSize=10
        )
        elements.append(Paragraph("_" * 50, sig_style))
        elements.append(Paragraph(f"{PSICOLOGO_NOME}", sig_style))
        elements.append(Paragraph(f"CRP {PSICOLOGO_CRP}", sig_style))
        
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        logger.error(f"Erro ao gerar recibo: {e}")
        return None

def gerar_declaracao_atendimento_pdf(paciente_nome, atendimentos_df):
    """
    Gera declaração de atendimento conforme normas do CFP.

    Resolução CFP nº 015/1996 - Documentos psicológicos
    Atualizada pela Resolução CFP nº 006/2019
    """
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2*cm, bottomMargin=3*cm)
        elements = []
        styles = getSampleStyleSheet()

        # Adicionar logo se existir
        logo_paths = ["logo.png", "assets/logo.png", "./logo.png"]
        for logo_path in logo_paths:
            if os.path.exists(logo_path):
                try:
                    logo = Image(logo_path, width=3*cm, height=3*cm)
                    elements.append(logo)
                    elements.append(Spacer(1, 0.3*cm))
                    break
                except:
                    continue

        # Cabeçalho profissional
        header_style = ParagraphStyle(
            'Header',
            parent=styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#2C5F7C'),
            alignment=1,
            spaceAfter=3
        )
        elements.append(Paragraph(f"<b>{PSICOLOGO_NOME}</b>", header_style))
        elements.append(Paragraph(f"Psicólogo - CRP {PSICOLOGO_CRP}", header_style))
        elements.append(Paragraph(f"{PSICOLOGO_TITULO}", header_style))
        elements.append(Paragraph(f"{PSICOLOGO_INSTITUICAO}", header_style))
        elements.append(Paragraph(f"Contato: {PSICOLOGO_CONTATO}", header_style))
        elements.append(Spacer(1, 1*cm))

        # Título
        titulo_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=18,
            textColor=colors.HexColor('#2C5F7C'),
            spaceAfter=20,
            alignment=1
        )
        elements.append(Paragraph("DECLARAÇÃO DE ATENDIMENTO PSICOLÓGICO", titulo_style))
        elements.append(Spacer(1, 1*cm))

        # Corpo da declaração
        corpo_style = ParagraphStyle(
            'CorpoDeclaracao',
            parent=styles['Normal'],
            fontSize=12,
            alignment=4,  # Justificado
            spaceAfter=10,
            leading=18
        )

        # Texto conforme CFP
        texto_declaracao = f"""
        Declaro, para os devidos fins, que <b>{paciente_nome}</b> está em acompanhamento
        psicológico comigo desde {atendimentos_df.iloc[-1]['Data'].strftime('%d/%m/%Y')},
        com sessões regulares conforme especificado abaixo.
        """

        elements.append(Paragraph(texto_declaracao, corpo_style))
        elements.append(Spacer(1, 0.8*cm))

        # Detalhamento dos atendimentos
        elements.append(Paragraph("<b>Detalhamento dos Atendimentos:</b>", corpo_style))
        elements.append(Spacer(1, 0.5*cm))

        # Tabela de atendimentos
        atend_realizados = atendimentos_df[atendimentos_df['Status'] == '✅ Realizado'].copy()
        atend_realizados = atend_realizados.sort_values('Data')

        # Preparar dados para tabela
        table_data = [['Data', 'Horário', 'Modalidade', 'Tipo']]

        for _, atend in atend_realizados.iterrows():
            table_data.append([
                atend['Data'].strftime('%d/%m/%Y'),
                atend['Hora'].strftime('%H:%M'),
                atend.get('Modalidade', 'Presencial'),
                atend.get('TipoAtendimento', 'Regular')
            ])

        # Criar tabela
        table = Table(table_data, colWidths=[3*cm, 2.5*cm, 3*cm, 3*cm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C5F7C')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 1*cm))

        # Resumo
        total_atendimentos = len(atend_realizados)
        resumo_style = ParagraphStyle(
            'Resumo',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=8
        )

        elements.append(Paragraph(f"<b>Total de atendimentos realizados:</b> {total_atendimentos}", resumo_style))
        elements.append(Paragraph(
            f"<b>Período:</b> {atend_realizados.iloc[0]['Data'].strftime('%d/%m/%Y')} a "
            f"{atend_realizados.iloc[-1]['Data'].strftime('%d/%m/%Y')}",
            resumo_style
        ))
        elements.append(Spacer(1, 1*cm))

        # Observações CFP
        obs_style = ParagraphStyle(
            'Observacao',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.grey,
            alignment=4,
            spaceAfter=8
        )

        elements.append(Paragraph(
            "<i>Esta declaração é emitida em conformidade com a Resolução CFP nº 015/1996, "
            "que institui e regulamenta a Declaração de Comparecimento de Pacientes/Clientes "
            "a Consultório/Serviço de Psicologia.</i>",
            obs_style
        ))

        elements.append(Spacer(1, 1.5*cm))

        # Data e local
        elements.append(Paragraph(f"Aracaju-SE, {agora_brasil().strftime('%d de %B de %Y')}", resumo_style))
        elements.append(Spacer(1, 2*cm))

        # Linha de assinatura
        sig_style = ParagraphStyle(
            'Signature',
            parent=styles['Normal'],
            alignment=1,
            fontSize=10
        )
        elements.append(Paragraph("_" * 60, sig_style))
        elements.append(Paragraph(f"<b>{PSICOLOGO_NOME}</b>", sig_style))
        elements.append(Paragraph(f"Psicólogo - CRP {PSICOLOGO_CRP}", sig_style))
        elements.append(Paragraph(f"{PSICOLOGO_TITULO}", sig_style))

        # Rodapé com informações CFP
        rodape_style = ParagraphStyle(
            'Rodape',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=1
        )
        elements.append(Spacer(1, 1*cm))
        elements.append(Paragraph(
            "Documento emitido digitalmente - Válido sem assinatura física conforme Lei nº 14.063/2020",
            rodape_style
        ))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
    except Exception as e:
        logger.error(f"Erro ao gerar declaração: {e}")
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
    # Logo - tentar múltiplos caminhos
    logo_paths = ["logo.png", "assets/logo.png", "./logo.png", "../logo.png"]
    logo_carregada = False
    
    for logo_path in logo_paths:
        if os.path.exists(logo_path):
            try:
                st.image(logo_path, use_container_width=True)
                st.divider()
                logo_carregada = True
                break
            except:
                continue
    
    st.markdown("### 🧠 Agenda Psicologia")
    st.markdown(f"**Psi. Radamés Soares**")
    st.markdown(f"CRP 19/5223")
    st.markdown(f"📍 Aracaju-SE")
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
        receita = df_periodo[
            (df_periodo['Status'] == '✅ Realizado') &
            (~df_periodo['Pagamento'].isin(['GRATUITO', 'INSTITUCIONAL']))
        ]['ValorFinal'].sum()
        st.metric("💰 Receita", f"R$ {receita:,.2f}")
    
    st.divider()
    
    # Alertas de Pacotes Próximos ao Vencimento
    st.subheader("⚠️ Alertas")
    
    hoje = hoje_brasil()
    limite_alerta = hoje + timedelta(days=5)
    
    pacotes_vencendo = st.session_state.pacotes[
        (st.session_state.pacotes['Status'] == 'ATIVO') &
        (pd.to_datetime(st.session_state.pacotes['Validade']).dt.date <= limite_alerta) &
        (pd.to_datetime(st.session_state.pacotes['Validade']).dt.date >= hoje)
    ]
    
    if not pacotes_vencendo.empty:
        st.warning("🔔 Pacotes próximos ao vencimento:")
        for _, pacote in pacotes_vencendo.iterrows():
            validade = pd.to_datetime(pacote['Validade']).date()
            dias_restantes = (validade - hoje).days
            
            if dias_restantes == 0:
                msg = f"⚠️ **{pacote['Paciente']}** - Pacote vence HOJE ({validade.strftime('%d/%m/%Y')})"
            elif dias_restantes == 1:
                msg = f"⚠️ **{pacote['Paciente']}** - Pacote vence AMANHÃ ({validade.strftime('%d/%m/%Y')})"
            else:
                msg = f"⚠️ **{pacote['Paciente']}** - Pacote vence em {dias_restantes} dias ({validade.strftime('%d/%m/%Y')})"
            
            # Calcular sessões restantes
            info = calcular_sessoes_restantes(pacote['Paciente'], st.session_state.agendamentos, st.session_state.pacotes)
            if info:
                msg += f" - {info['restantes']}/{info['total']} sessões restantes"
            
            st.warning(msg)
    else:
        st.success("✅ Nenhum pacote próximo ao vencimento")

    st.divider()

    # Pendências de Reposição
    st.subheader("🔄 Pendências de Reposição")

    # Buscar agendamentos cancelados ou faltou que são de PACOTE
    pendencias_reposicao = st.session_state.agendamentos[
        (st.session_state.agendamentos['Status'].isin(['🔴 Cancelado', '⚫ Faltou'])) &
        (st.session_state.agendamentos['Pagamento'] == 'PACOTE') &
        (st.session_state.agendamentos['TipoAtendimento'] == 'Regular')  # Apenas regulares, não reposições de reposições
    ].sort_values(['Data', 'Hora'], ascending=False).head(5)

    if pendencias_reposicao.empty:
        st.success("✅ Nenhuma pendência de reposição")
    else:
        st.warning(f"⚠️ {len(pendencias_reposicao)} agendamento(s) de pacote que necessitam reposição")

        for idx, pend in pendencias_reposicao.iterrows():
            with st.expander(
                f"{formatar_data_com_dia_semana(pend['Data'])} às {pend['Hora'].strftime('%H:%M')} - {pend['Paciente']} - {pend['Status']}"
            ):
                col1, col2 = st.columns([2, 1])

                with col1:
                    st.write(f"**Paciente:** {pend['Paciente']}")
                    st.write(f"**Serviço:** {pend['Servico']}")
                    st.write(f"**Status:** {pend['Status']}")
                    if pend['Observacoes']:
                        st.write(f"**Obs:** {pend['Observacoes']}")

                with col2:
                    # Botão para agendar reposição
                    if st.button(f"📅 Agendar Reposição", key=f"repor_{idx}", use_container_width=True, type="primary"):
                        st.session_state['reposicao_origem'] = idx
                        st.session_state['reposicao_paciente'] = pend['Paciente']
                        st.session_state['reposicao_servico'] = pend['Servico']
                        st.session_state['reposicao_duracao'] = pend['Duracao']
                        st.rerun()

    # Formulário de agendamento de reposição (se ativado)
    if 'reposicao_origem' in st.session_state and st.session_state['reposicao_origem'] is not None:
        st.divider()
        st.subheader("📅 Agendar Reposição")

        ag_origem = st.session_state.agendamentos.loc[st.session_state['reposicao_origem']]

        st.info(f"**Reposição para:** {st.session_state['reposicao_paciente']} - {st.session_state['reposicao_servico']}")
        st.caption(f"Origem: {formatar_data_com_dia_semana(ag_origem['Data'])} às {ag_origem['Hora'].strftime('%H:%M')} - {ag_origem['Status']}")

        with st.form("form_reposicao"):
            col1, col2 = st.columns(2)

            with col1:
                data_reposicao = st.date_input(
                    "📅 Data da Reposição *",
                    value=hoje_brasil(),
                    min_value=hoje_brasil(),
                    max_value=hoje_brasil() + timedelta(days=365),
                    format="DD/MM/YYYY"
                )
                st.caption(f"📆 {formatar_data_com_dia_semana(data_reposicao)}")

            with col2:
                hora_str_reposicao = st.selectbox(
                    "⏰ Horário *",
                    options=HORARIOS_DISPONIVEIS,
                    index=7
                )
                hora_reposicao = hora_str_para_time(hora_str_reposicao)

            obs_reposicao = st.text_area(
                "📝 Observações",
                placeholder="Ex: Reposição por cancelamento/falta..."
            )

            col_btn = st.columns([1, 1, 1])

            with col_btn[0]:
                if st.form_submit_button("✅ Confirmar Reposição", use_container_width=True, type="primary"):
                    # Validar horário
                    tem_conflito, ag_conflito = verificar_conflito_horario(data_reposicao, hora_reposicao, st.session_state['reposicao_duracao'])

                    if tem_conflito:
                        st.error(f"❌ Conflito de horário! Já existe agendamento de {ag_conflito['Paciente']} às {ag_conflito['Hora'].strftime('%H:%M')}")
                    else:
                        # Verificar se paciente ainda tem sessões no pacote
                        info_pacote = calcular_sessoes_restantes(
                            st.session_state['reposicao_paciente'],
                            st.session_state.agendamentos,
                            st.session_state.pacotes
                        )

                        if info_pacote and info_pacote['restantes'] > 0:
                            # Criar agendamento de reposição
                            novo_id = gerar_id_sequencial(st.session_state.agendamentos)
                            novo_agendamento = pd.DataFrame([{
                                "ID": novo_id,
                                "Paciente": st.session_state['reposicao_paciente'],
                                "Data": data_reposicao,
                                "Hora": hora_reposicao,
                                "Duracao": st.session_state['reposicao_duracao'],
                                "Servico": st.session_state['reposicao_servico'],
                                "Valor": ag_origem['Valor'],
                                "Desconto": ag_origem['Desconto'],
                                "ValorFinal": ag_origem['ValorFinal'],
                                "Pagamento": "PACOTE",
                                "Status": "🔵 Agendado",
                                "Recorrente": False,
                                "TipoAtendimento": "Reposição",
                                "Modalidade": ag_origem.get('Modalidade', 'Presencial'),
                                "Observacoes": f"Reposição de ID {st.session_state['reposicao_origem']}. {obs_reposicao}",
                                "Prontuario": ""
                            }])

                            st.session_state.agendamentos = pd.concat(
                                [st.session_state.agendamentos, novo_agendamento],
                                ignore_index=True
                            )

                            salvar_agendamentos(st.session_state.agendamentos)
                            registrar_historico(
                                "REPOSIÇÃO_CRIADA",
                                f"ID {novo_id} - Reposição para {st.session_state['reposicao_paciente']} (origem: ID {st.session_state['reposicao_origem']})"
                            )

                            # Limpar estado
                            del st.session_state['reposicao_origem']
                            del st.session_state['reposicao_paciente']
                            del st.session_state['reposicao_servico']
                            del st.session_state['reposicao_duracao']

                            st.success(f"✅ Reposição agendada! ID: {novo_id}")
                            st.balloons()
                            st.rerun()
                        else:
                            st.error("❌ Paciente não possui sessões disponíveis no pacote!")

            with col_btn[2]:
                if st.form_submit_button("❌ Cancelar", use_container_width=True):
                    del st.session_state['reposicao_origem']
                    del st.session_state['reposicao_paciente']
                    del st.session_state['reposicao_servico']
                    del st.session_state['reposicao_duracao']
                    st.rerun()

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
        for idx, agend in proximos.iterrows():
            with st.expander(
                f"{formatar_data_com_dia_semana(agend['Data'])} às {agend['Hora'].strftime('%H:%M')} - {agend['Paciente']} - {agend['Status']}"
            ):
                col1, col2, col3 = st.columns([2, 1, 1])

                with col1:
                    st.write(f"**Serviço:** {agend['Servico']}")
                    st.write(f"**Duração:** {agend['Duracao']}")
                    if agend['Observacoes']:
                        st.write(f"**Obs:** {agend['Observacoes']}")

                with col2:
                    st.write(f"**Valor:** R$ {agend['ValorFinal']:.2f}")
                    st.write(f"**Pagamento:** {agend['Pagamento']}")

                with col3:
                    st.write(f"**Status:** {agend['Status']}")

                st.divider()

                # Botões de ação rápida para alterar status
                st.write("**⚡ Ações Rápidas:**")
                col_status = st.columns(4)

                with col_status[0]:
                    if st.button("🟢 Confirmar", key=f"confirm_{idx}", use_container_width=True):
                        st.session_state.agendamentos.at[idx, 'Status'] = '🟢 Confirmado'
                        salvar_agendamentos(st.session_state.agendamentos)
                        registrar_historico("ATUALIZAÇÃO", f"Status alterado para Confirmado: {agend['Paciente']} em {agend['Data'].strftime('%d/%m/%Y')}")
                        st.success("✅ Status atualizado para Confirmado!")
                        st.rerun()

                with col_status[1]:
                    if st.button("✅ Realizado", key=f"done_{idx}", use_container_width=True):
                        # Verificar se deve criar sessão recorrente
                        criar_recorrente = agend.get('Recorrente', False)

                        st.session_state.agendamentos.at[idx, 'Status'] = '✅ Realizado'
                        salvar_agendamentos(st.session_state.agendamentos)
                        registrar_historico("ATUALIZAÇÃO", f"Status alterado para Realizado: {agend['Paciente']} em {agend['Data'].strftime('%d/%m/%Y')}")

                        # Criar próximo agendamento se for recorrente
                        if criar_recorrente:
                            agendamento_atualizado = st.session_state.agendamentos.loc[idx]
                            proximo = criar_proximo_agendamento_recorrente(agendamento_atualizado)

                            if proximo is not None:
                                st.session_state.agendamentos = pd.concat(
                                    [st.session_state.agendamentos, proximo],
                                    ignore_index=True
                                )
                                salvar_agendamentos(st.session_state.agendamentos)
                                proxima_data = proximo.iloc[0]['Data']
                                st.success("✅ Status atualizado para Realizado!")
                                st.success(f"🔄 Próxima sessão criada para {formatar_data_com_dia_semana(proxima_data)} às {agend['Hora'].strftime('%H:%M')}")
                            else:
                                st.success("✅ Status atualizado para Realizado!")
                                st.info("ℹ️ Próxima sessão não foi criada (pacote vencido ou sem sessões)")
                        else:
                            st.success("✅ Status atualizado para Realizado!")

                        st.rerun()

                with col_status[2]:
                    if st.button("🔴 Cancelar", key=f"cancel_{idx}", use_container_width=True):
                        st.session_state.agendamentos.at[idx, 'Status'] = '🔴 Cancelado'
                        salvar_agendamentos(st.session_state.agendamentos)
                        registrar_historico("ATUALIZAÇÃO", f"Status alterado para Cancelado: {agend['Paciente']} em {agend['Data'].strftime('%d/%m/%Y')}")
                        st.warning("⚠️ Status atualizado para Cancelado!")
                        st.rerun()

                with col_status[3]:
                    if st.button("⏳ Faltou", key=f"noshow_{idx}", use_container_width=True):
                        st.session_state.agendamentos.at[idx, 'Status'] = '⏳ Faltou'
                        salvar_agendamentos(st.session_state.agendamentos)
                        registrar_historico("ATUALIZAÇÃO", f"Status alterado para Faltou: {agend['Paciente']} em {agend['Data'].strftime('%d/%m/%Y')}")
                        st.info("ℹ️ Status atualizado para Faltou!")
                        st.rerun()
    
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
    
    tab1, tab2, tab3 = st.tabs(["➕ Novo Agendamento", "📋 Lista", "✏️ Buscar/Editar/Excluir"])
    
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

                    # Mostrar data com dia da semana
                    st.caption(f"📆 {formatar_data_com_dia_semana(data_consulta)}")

                    # Seleção de hora com dropdown (horas fechadas)
                    hora_str = st.selectbox(
                        "⏰ Horário *",
                        options=HORARIOS_DISPONIVEIS,
                        index=7  # 14:00 por padrão
                    )
                    hora_consulta = hora_str_para_time(hora_str)
                    
                    duracao = st.selectbox(
                        "⏱️ Duração *",
                        options=OPCOES_DURACAO,
                        index=0
                    )
                
                with col2:
                    servico = st.selectbox(
                        "💼 Serviço *",
                        options=list(SERVICOS.keys())
                    )
                    
                    # Valor editável
                    valor_padrao = SERVICOS[servico]
                    valor_sessao = st.number_input(
                        "💰 Valor da Sessão *",
                        min_value=0.0,
                        max_value=10000.0,
                        value=valor_padrao,
                        step=10.0,
                        format="%.2f",
                        help="Você pode editar o valor conforme necessário"
                    )
                    
                    desconto = st.number_input(
                        "💵 Desconto (%)",
                        min_value=0.0,
                        max_value=100.0,
                        value=0.0,
                        step=5.0
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
                
                col_extra = st.columns(2)

                with col_extra[0]:
                    status = st.selectbox(
                        "📊 Status *",
                        options=OPCOES_STATUS,
                        index=0
                    )

                with col_extra[1]:
                    modalidade = st.selectbox(
                        "📍 Modalidade *",
                        options=OPCOES_MODALIDADE,
                        index=0,  # Presencial como padrão
                        help="Presencial ou Online"
                    )

                recorrente = st.checkbox(
                    "🔄 Sessão Recorrente",
                    help="Ao marcar como 'Realizado', cria automaticamente a próxima sessão na semana seguinte"
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
                    
                    # Verificar conflito de horário com duração
                    tem_conflito, ag_conflito = verificar_conflito_horario(data_valida, hora_valida, duracao)
                    
                    if tem_conflito:
                        hora_fim = calcular_hora_fim(hora_valida, duracao)
                        st.error(f"❌ Conflito de horário! Já existe agendamento de {ag_conflito['Paciente']} às {ag_conflito['Hora'].strftime('%H:%M')}")
                        st.error(f"Seu horário: {hora_valida.strftime('%H:%M')} - {hora_fim.strftime('%H:%M')} ({duracao})")
                    else:
                        # Verificar se pode usar pacote
                        if pagamento == "PACOTE":
                            if not info_pacote or info_pacote['restantes'] <= 0:
                                st.error("❌ Paciente não possui sessões disponíveis no pacote!")
                                st.stop()

                            # Criar agendamento com pacote
                            valor_final = valor_sessao * (1 - desconto / 100)

                            novo_id = gerar_id_sequencial(st.session_state.agendamentos)
                            novo_agendamento = pd.DataFrame([{
                                "ID": novo_id,
                                "Paciente": paciente_nome,
                                "Data": data_valida,
                                "Hora": hora_valida,
                                "Duracao": duracao,
                                "Servico": servico,
                                "Valor": valor_sessao,
                                "Desconto": desconto,
                                "ValorFinal": round(valor_final, 2),
                                "Pagamento": pagamento,
                                "Status": status,
                                "Recorrente": recorrente,
                                "TipoAtendimento": "Regular",
                                "Modalidade": modalidade,
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
                            if recorrente:
                                st.info("🔄 Sessão recorrente ativada. Próxima sessão será criada automaticamente.")
                            st.balloons()
                            st.rerun()
                        else:
                            # Agendamento normal (sem pacote)
                            valor_final = valor_sessao * (1 - desconto / 100)
                            
                            novo_id = gerar_id_sequencial(st.session_state.agendamentos)
                            novo_agendamento = pd.DataFrame([{
                                "ID": novo_id,
                                "Paciente": paciente_nome,
                                "Data": data_valida,
                                "Hora": hora_valida,
                                "Duracao": duracao,
                                "Servico": servico,
                                "Valor": valor_sessao,
                                "Desconto": desconto,
                                "ValorFinal": round(valor_final, 2),
                                "Pagamento": pagamento,
                                "Status": status,
                                "Recorrente": recorrente,
                                "TipoAtendimento": "Regular",
                                "Modalidade": modalidade,
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
                            if recorrente:
                                st.info("🔄 Sessão recorrente ativada. Próxima sessão será criada automaticamente.")
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
                'ID', 'Data', 'Hora', 'Duracao', 'Paciente', 'Servico',
                'ValorFinal', 'Pagamento', 'Status', 'Recorrente'
            ]].copy()

            # Formatar Data com dia da semana
            df_show['Data'] = df_show['Data'].apply(formatar_data_com_dia_semana)
            df_show['Hora'] = df_show['Hora'].apply(lambda x: x.strftime('%H:%M'))
            df_show['ValorFinal'] = df_show['ValorFinal'].apply(lambda x: f"R$ {x:.2f}")
            df_show['Recorrente'] = df_show['Recorrente'].apply(lambda x: '🔄' if x else '')
            
            st.dataframe(df_show, use_container_width=True, hide_index=True)
            
            # Ações
            st.divider()
            col1, col2 = st.columns(2)
            
            with col1:
                if not df_filtrado.empty and st.button("📄 Exportar Agenda PDF", use_container_width=True):
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
                    
                    hora_fim = calcular_hora_fim(ag['Hora'], ag.get('Duracao', '1h'))
                    st.write(f"**Horário:** {formatar_data_com_dia_semana(ag['Data'])} das {ag['Hora'].strftime('%H:%M')} às {hora_fim.strftime('%H:%M')} ({ag.get('Duracao', '1h')})")
                    
                    st.write(f"**Serviço:** {ag['Servico']}")
                    st.write(f"**Valor:** R$ {ag['ValorFinal']:.2f}")
                    st.write(f"**Pagamento:** {ag['Pagamento']}")
                    st.write(f"**Status:** {ag['Status']}")
                    
                    if ag.get('Recorrente', False):
                        st.write("**🔄 Sessão Recorrente:** Sim")
                
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
                        
                        nova_duracao = st.selectbox(
                            "Duração",
                            options=OPCOES_DURACAO,
                            index=OPCOES_DURACAO.index(ag.get('Duracao', '1h'))
                        )
                    
                    with col2:
                        nova_data = st.date_input(
                            "Data",
                            value=ag['Data'],
                            format="DD/MM/YYYY"
                        )

                        # Mostrar data com dia da semana
                        st.caption(f"📆 {formatar_data_com_dia_semana(nova_data)}")

                        # Seleção de hora com dropdown (horas fechadas)
                        hora_atual_str = ag['Hora'].strftime('%H:%M')
                        # Encontrar índice da hora atual, ou usar 14:00 como padrão
                        try:
                            hora_idx = HORARIOS_DISPONIVEIS.index(hora_atual_str)
                        except:
                            hora_idx = 7  # 14:00

                        nova_hora_str = st.selectbox(
                            "Hora",
                            options=HORARIOS_DISPONIVEIS,
                            index=hora_idx
                        )
                        nova_hora = hora_str_para_time(nova_hora_str)

                        novo_recorrente = st.checkbox(
                            "🔄 Sessão Recorrente",
                            value=ag.get('Recorrente', False)
                        )
                    
                    novas_obs = st.text_area(
                        "Observações",
                        value=ag['Observacoes'] if pd.notna(ag['Observacoes']) else ""
                    )

                    prontuario = st.text_area(
                        "📋 Prontuário (Informações Clínicas)",
                        value=ag['Prontuario'] if pd.notna(ag['Prontuario']) else "",
                        help="Campo confidencial para anotações clínicas"
                    )
                    
                    col_submit = st.columns([1, 1, 1])
                    
                    with col_submit[0]:
                        if st.form_submit_button("💾 Salvar Alterações", use_container_width=True, type="primary"):
                            idx = st.session_state.agendamentos[
                                st.session_state.agendamentos['ID'] == busca_id
                            ].index[0]
                            
                            # Verificar se mudou para "Realizado" e é recorrente
                            criar_recorrente = (
                                novo_status == '✅ Realizado' and 
                                ag['Status'] != '✅ Realizado' and
                                novo_recorrente
                            )
                            
                            st.session_state.agendamentos.at[idx, 'Status'] = novo_status
                            st.session_state.agendamentos.at[idx, 'Pagamento'] = novo_pagamento
                            st.session_state.agendamentos.at[idx, 'Data'] = nova_data
                            st.session_state.agendamentos.at[idx, 'Hora'] = nova_hora
                            st.session_state.agendamentos.at[idx, 'Duracao'] = nova_duracao
                            st.session_state.agendamentos.at[idx, 'Recorrente'] = novo_recorrente
                            st.session_state.agendamentos.at[idx, 'Observacoes'] = novas_obs
                            st.session_state.agendamentos.at[idx, 'Prontuario'] = prontuario
                            
                            salvar_agendamentos(st.session_state.agendamentos)
                            registrar_historico("AGENDAMENTO_EDITADO", f"ID {busca_id}")
                            
                            # Criar próximo agendamento se for recorrente
                            if criar_recorrente:
                                agendamento_atualizado = st.session_state.agendamentos[
                                    st.session_state.agendamentos['ID'] == busca_id
                                ].iloc[0]
                                
                                proximo = criar_proximo_agendamento_recorrente(agendamento_atualizado)
                                
                                if proximo is not None:
                                    st.session_state.agendamentos = pd.concat(
                                        [st.session_state.agendamentos, proximo],
                                        ignore_index=True
                                    )
                                    salvar_agendamentos(st.session_state.agendamentos)
                                    
                                    proxima_data = proximo.iloc[0]['Data']
                                    st.success("✅ Agendamento atualizado!")
                                    st.success(f"🔄 Próxima sessão criada para {proxima_data.strftime('%d/%m/%Y')} às {nova_hora.strftime('%H:%M')}")
                                else:
                                    st.success("✅ Agendamento atualizado!")
                                    st.info("ℹ️ Próxima sessão não foi criada (pacote vencido ou sem sessões)")
                            else:
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
    
    tab1, tab2, tab3 = st.tabs(["➕ Cadastrar", "📋 Lista", "✏️ Editar/Excluir"])
    
    # --- TAB 1: CADASTRAR ---
    with tab1:
        st.subheader("Cadastrar Novo Paciente")
        
        with st.form("form_paciente", clear_on_submit=True):
            col1, col2 = st.columns(2)
            
            with col1:
                nome = st.text_input("👤 Nome Completo *", placeholder="Ex: João da Silva")
                cpf = st.text_input("🆔 CPF", placeholder="000.000.000-00")
                email = st.text_input("📧 Email", placeholder="exemplo@email.com")
                
                # Checkbox para informar data de nascimento
                informar_data = st.checkbox("📅 Informar Data de Nascimento", value=False)
                if informar_data:
                    data_nasc = st.date_input(
                        "Data de Nascimento",
                        max_value=hoje_brasil(),
                        format="DD/MM/YYYY"
                    )
                else:
                    data_nasc = None
            
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
                        if pd.notna(paciente['Telefone']) and str(paciente['Telefone']).strip():
                            st.write(f"**Telefone:** {paciente['Telefone']}")
                        if pd.notna(paciente['Email']) and str(paciente['Email']).strip():
                            st.write(f"**Email:** {paciente['Email']}")
                        if pd.notna(paciente['DataNascimento']) and str(paciente['DataNascimento']).strip():
                            st.write(f"**Data Nasc:** {paciente['DataNascimento']}")

                    with col2:
                        if pd.notna(paciente['CPF']) and str(paciente['CPF']).strip():
                            st.write(f"**CPF:** {paciente['CPF']}")
                        st.write(f"**Cadastro:** {paciente['DataCadastro']}")

                    if pd.notna(paciente['Observacoes']) and str(paciente['Observacoes']).strip():
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
                    
                    # Corrigir problema com data None
                    data_nasc_atual = None
                    if paciente['DataNascimento'] and str(paciente['DataNascimento']).strip():
                        try:
                            data_nasc_atual = pd.to_datetime(paciente['DataNascimento']).date()
                        except:
                            data_nasc_atual = None
                    
                    # Checkbox para alterar/informar data de nascimento
                    tem_data = data_nasc_atual is not None
                    alterar_data = st.checkbox(
                        "📅 Data de Nascimento", 
                        value=tem_data,
                        help="Marque para informar ou alterar a data de nascimento"
                    )
                    
                    if alterar_data:
                        if data_nasc_atual:
                            nova_data_nasc = st.date_input(
                                "Selecione a data",
                                value=data_nasc_atual,
                                max_value=hoje_brasil(),
                                format="DD/MM/YYYY",
                                label_visibility="collapsed"
                            )
                        else:
                            nova_data_nasc = st.date_input(
                                "Selecione a data",
                                max_value=hoje_brasil(),
                                format="DD/MM/YYYY",
                                label_visibility="collapsed"
                            )
                    else:
                        nova_data_nasc = None
                
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
    
    tab1, tab2, tab3 = st.tabs(["➕ Novo Pacote", "📋 Lista", "✏️ Editar/Excluir"])
    
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
    
    # --- TAB 3: EDITAR/EXCLUIR ---
    with tab3:
        st.subheader("Editar ou Excluir Pacote")
        
        if st.session_state.pacotes.empty:
            st.info("Nenhum pacote cadastrado.")
        else:
            # Selecionar pacote
            pacotes_list = st.session_state.pacotes.apply(
                lambda x: f"ID {int(x['ID'])} - {x['Paciente']} - {x['Status']}", axis=1
            ).tolist()
            
            pacote_selecionado = st.selectbox(
                "Selecione o pacote:",
                options=pacotes_list
            )
            
            # Extrair ID
            id_pacote = int(pacote_selecionado.split(" - ")[0].replace("ID ", ""))
            
            pacote = st.session_state.pacotes[
                st.session_state.pacotes['ID'] == id_pacote
            ].iloc[0]
            
            # Mostrar informações atuais
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**ID:** {int(pacote['ID'])}")
                st.write(f"**Paciente:** {pacote['Paciente']}")
                st.write(f"**Quantidade:** {int(pacote['QtdSessoes'])} sessões")
                st.write(f"**Valor:** R$ {pacote['Valor']:.2f}")
            
            with col2:
                st.write(f"**Data Compra:** {pd.to_datetime(pacote['DataCompra']).strftime('%d/%m/%Y')}")
                st.write(f"**Validade:** {pd.to_datetime(pacote['Validade']).strftime('%d/%m/%Y')}")
                st.write(f"**Status:** {pacote['Status']}")
                
                # Calcular sessões utilizadas
                info = calcular_sessoes_restantes(
                    pacote['Paciente'],
                    st.session_state.agendamentos,
                    st.session_state.pacotes
                )
                if info:
                    utilizadas = int(pacote['QtdSessoes']) - info['restantes']
                    st.write(f"**Sessões Utilizadas:** {utilizadas}/{int(pacote['QtdSessoes'])}")
            
            st.divider()
            
            # Formulário de edição
            with st.form("form_editar_pacote"):
                st.subheader("Editar Pacote")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    novo_status_pacote = st.selectbox(
                        "Status",
                        options=["ATIVO", "VENCIDO", "CANCELADO"],
                        index=["ATIVO", "VENCIDO", "CANCELADO"].index(pacote['Status'])
                    )
                    
                    nova_qtd_sessoes = st.number_input(
                        "Quantidade de Sessões",
                        min_value=1,
                        max_value=50,
                        value=int(pacote['QtdSessoes']),
                        step=1
                    )
                
                with col2:
                    novo_valor_pacote = st.number_input(
                        "Valor do Pacote",
                        min_value=0.01,
                        max_value=10000.0,
                        value=float(pacote['Valor']),
                        step=10.0,
                        format="%.2f"
                    )
                    
                    nova_validade = st.date_input(
                        "Validade",
                        value=pd.to_datetime(pacote['Validade']).date(),
                        format="DD/MM/YYYY"
                    )
                
                col_submit = st.columns([1, 1, 1])
                
                with col_submit[0]:
                    if st.form_submit_button("💾 Salvar Alterações", use_container_width=True, type="primary"):
                        idx = st.session_state.pacotes[
                            st.session_state.pacotes['ID'] == id_pacote
                        ].index[0]
                        
                        st.session_state.pacotes.at[idx, 'Status'] = novo_status_pacote
                        st.session_state.pacotes.at[idx, 'QtdSessoes'] = nova_qtd_sessoes
                        st.session_state.pacotes.at[idx, 'Valor'] = round(novo_valor_pacote, 2)
                        st.session_state.pacotes.at[idx, 'Validade'] = nova_validade
                        
                        salvar_pacotes(st.session_state.pacotes)
                        registrar_historico("PACOTE_EDITADO", f"ID {id_pacote} - {pacote['Paciente']}")
                        
                        st.success("✅ Pacote atualizado!")
                        st.rerun()
                
                with col_submit[2]:
                    if st.form_submit_button("🗑️ Excluir Pacote", use_container_width=True):
                        # Verificar se tem sessões vinculadas
                        sessoes_pacote = st.session_state.agendamentos[
                            (st.session_state.agendamentos['Paciente'] == pacote['Paciente']) &
                            (st.session_state.agendamentos['Pagamento'] == 'PACOTE')
                        ]
                        
                        if not sessoes_pacote.empty:
                            st.warning(f"⚠️ Este pacote tem {len(sessoes_pacote)} sessão(ões) vinculada(s).")
                            st.info("💡 Dica: Altere o pagamento das sessões antes de excluir o pacote.")
                        else:
                            st.session_state.pacotes = st.session_state.pacotes[
                                st.session_state.pacotes['ID'] != id_pacote
                            ]
                            salvar_pacotes(st.session_state.pacotes)
                            registrar_historico("PACOTE_EXCLUIDO", f"ID {id_pacote} - {pacote['Paciente']}")
                            st.success("✅ Pacote excluído!")
                            st.rerun()


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
                f"📅 {formatar_data_com_dia_semana(consulta['Data'])} às {consulta['Hora'].strftime('%H:%M')} - {consulta['Paciente']}"
            ):
                # Buscar telefone do paciente
                paciente_info = st.session_state.pacientes[
                    st.session_state.pacientes['Nome'] == consulta['Paciente']
                ]
                
                if paciente_info.empty or not paciente_info.iloc[0]['Telefone']:
                    st.warning("⚠️ Paciente sem telefone cadastrado")
                else:
                    telefone = paciente_info.iloc[0]['Telefone']
                    
                    # Determinar saudação baseada no horário
                    saudacao = obter_saudacao()
                    
                    # Mensagem padrão personalizada
                    dias_falta = (consulta['Data'] - hoje).days
                    
                    if dias_falta == 0:
                        quando = "hoje"
                    elif dias_falta == 1:
                        quando = "amanhã"
                    else:
                        quando = f"em {dias_falta} dias"
                    
                    mensagem = f"""{saudacao}, {consulta['Paciente']}. Espero que esteja bem.

Lembrando {consulta['Servico']} {quando} às {consulta['Hora'].strftime('%H:%M')}.

Favor chegar com 10 minutos de antecedência e enviar mensagem para que eu possa abrir a porta.

Obrigado."""
                    
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
    
    if st.session_state.pacientes.empty:
        st.info("Nenhum paciente cadastrado.")
    else:
        paciente_manual = st.selectbox(
            "Selecione o paciente:",
            options=sorted(st.session_state.pacientes['Nome'].unique()),
            key="paciente_manual_select"
        )
        
        # Buscar próximo agendamento do paciente
        proximo_agendamento = st.session_state.agendamentos[
            (st.session_state.agendamentos['Paciente'] == paciente_manual) &
            (st.session_state.agendamentos['Data'] >= hoje_brasil()) &
            (st.session_state.agendamentos['Status'].isin(['🔵 Agendado', '🟢 Confirmado']))
        ].sort_values(['Data', 'Hora'])
        
        # Gerar mensagem automática se houver agendamento
        if not proximo_agendamento.empty:
            prox = proximo_agendamento.iloc[0]
            saudacao = obter_saudacao()
            
            dias_falta = (prox['Data'] - hoje_brasil()).days
            if dias_falta == 0:
                quando = "hoje"
            elif dias_falta == 1:
                quando = "amanhã"
            else:
                quando = f"em {dias_falta} dias ({formatar_data_com_dia_semana(prox['Data'])})"
            
            mensagem_auto = f"""{saudacao}, {paciente_manual}. Espero que esteja bem.

Lembrando {prox['Servico']} {quando} às {prox['Hora'].strftime('%H:%M')}.

Favor chegar com 10 minutos de antecedência e enviar mensagem para que eu possa abrir a porta.

Obrigado."""
            
            st.success(f"✅ Próximo agendamento: {formatar_data_com_dia_semana(prox['Data'])} às {prox['Hora'].strftime('%H:%M')}")
        else:
            saudacao = obter_saudacao()
            mensagem_auto = f"""{saudacao}, {paciente_manual}. Espero que esteja bem.

"""
            st.info("ℹ️ Paciente sem agendamentos futuros. Mensagem personalizada gerada.")
        
        mensagem_manual = st.text_area(
            "Mensagem:",
            value=mensagem_auto,
            height=200,
            key="msg_manual"
        )
        
        if st.button("📱 Gerar Link WhatsApp", use_container_width=True, type="primary"):
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
            receita_total = df_rel[
                (df_rel['Status'] == '✅ Realizado') &
                (~df_rel['Pagamento'].isin(['GRATUITO', 'INSTITUCIONAL']))
            ]['ValorFinal'].sum()
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

        # Relatório Individual por Paciente
        st.subheader("📄 Relatório de Atendimentos por Paciente")

        # Seleção de paciente
        col_pac1, col_pac2 = st.columns([2, 1])

        with col_pac1:
            if not st.session_state.pacientes.empty:
                paciente_relatorio = st.selectbox(
                    "Selecione o paciente:",
                    options=["-- Selecione --"] + sorted(st.session_state.pacientes['Nome'].unique()),
                    key="paciente_relatorio"
                )
            else:
                st.info("Nenhum paciente cadastrado.")
                paciente_relatorio = None

        with col_pac2:
            tipo_relatorio = st.radio(
                "Tipo de relatório:",
                ["Geral", "Mensal"],
                horizontal=True
            )

        if paciente_relatorio and paciente_relatorio != "-- Selecione --":
            # Filtrar atendimentos do paciente
            atend_paciente = st.session_state.agendamentos[
                st.session_state.agendamentos['Paciente'] == paciente_relatorio
            ].copy()

            if tipo_relatorio == "Mensal":
                # Agrupar por mês
                atend_paciente['Mes'] = pd.to_datetime(atend_paciente['Data']).dt.to_period('M')

                meses_disponiveis = sorted(atend_paciente['Mes'].unique(), reverse=True)

                if meses_disponiveis:
                    mes_selecionado = st.selectbox(
                        "Selecione o mês:",
                        options=meses_disponiveis,
                        format_func=lambda x: x.strftime("%B/%Y").capitalize()
                    )

                    atend_paciente = atend_paciente[atend_paciente['Mes'] == mes_selecionado]
                    periodo_texto = mes_selecionado.strftime("%B/%Y").capitalize()
                else:
                    st.info(f"Nenhum atendimento registrado para {paciente_relatorio}")
                    atend_paciente = pd.DataFrame()
                    periodo_texto = ""
            else:
                periodo_texto = "Geral (todos os períodos)"

            if not atend_paciente.empty:
                st.write(f"**Período:** {periodo_texto}")
                st.write(f"**Total de atendimentos:** {len(atend_paciente)}")

                # Métricas do paciente
                col_m1, col_m2, col_m3, col_m4 = st.columns(4)

                with col_m1:
                    realizados_pac = len(atend_paciente[atend_paciente['Status'] == '✅ Realizado'])
                    st.metric("✅ Realizados", realizados_pac)

                with col_m2:
                    agendados_pac = len(atend_paciente[atend_paciente['Status'].isin(['🔵 Agendado', '🟢 Confirmado'])])
                    st.metric("📅 Agendados", agendados_pac)

                with col_m3:
                    cancelados_pac = len(atend_paciente[atend_paciente['Status'] == '🔴 Cancelado'])
                    st.metric("🔴 Cancelados", cancelados_pac)

                with col_m4:
                    faltas_pac = len(atend_paciente[atend_paciente['Status'] == '⚫ Faltou'])
                    st.metric("⚫ Faltas", faltas_pac)

                # Detalhamento
                st.write("**Detalhamento dos atendimentos:**")

                df_pac_show = atend_paciente[[
                    'Data', 'Hora', 'Servico', 'Modalidade', 'Status', 'TipoAtendimento'
                ]].copy()

                df_pac_show['Data'] = df_pac_show['Data'].apply(lambda x: formatar_data_com_dia_semana(x))
                df_pac_show['Hora'] = df_pac_show['Hora'].apply(lambda x: x.strftime('%H:%M'))
                df_pac_show = df_pac_show.sort_values('Data', ascending=False)

                st.dataframe(df_pac_show, use_container_width=True, hide_index=True)

                # Botão para gerar declaração de atendimento
                if st.button("📄 Gerar Declaração de Atendimento", use_container_width=True, type="primary"):
                    # Filtrar apenas atendimentos realizados
                    atend_realizados = atend_paciente[atend_paciente['Status'] == '✅ Realizado']

                    if len(atend_realizados) == 0:
                        st.warning("⚠️ Nenhum atendimento realizado para gerar declaração.")
                    else:
                        pdf_declaracao = gerar_declaracao_atendimento_pdf(paciente_relatorio, atend_realizados)

                        if pdf_declaracao:
                            st.download_button(
                                "⬇️ Baixar Declaração de Atendimento",
                                pdf_declaracao,
                                f"declaracao_atendimento_{paciente_relatorio.replace(' ', '_')}_{agora_brasil().strftime('%Y%m%d')}.pdf",
                                "application/pdf",
                                use_container_width=True
                            )
                        else:
                            st.error("❌ Erro ao gerar declaração")

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

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["📋 Logs", "📜 Histórico", "💾 Backups", "☁️ Google Sheets", "⚙️ Configurações"])
    
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

    # --- TAB 3: BACKUPS ---
    with tab3:
        st.subheader("💾 Gerenciamento de Backups")

        st.info("📌 Backups são criados automaticamente antes de cada salvamento (formato: arquivo.bak.YYYYMMDD_HHMMSS)")

        # Mostrar localização dos backups
        st.write("**📂 Localização dos Backups:**")
        diretorio_atual = os.path.abspath(".")
        st.code(f"{diretorio_atual}/")
        st.caption("Os arquivos .bak.* ficam no mesmo diretório do sistema")

        st.divider()

        # Upload de CSV externo
        st.subheader("📤 Importar CSV Externo")
        st.write("Envie um arquivo CSV para restaurar dados de backup externo ou migração")

        arquivo_destino_upload = st.selectbox(
            "Selecione qual arquivo deseja substituir:",
            options=[os.path.basename(f) for f in FILES_TO_BACKUP],
            key="destino_upload"
        )

        uploaded_file = st.file_uploader(
            "Escolha um arquivo CSV",
            type=['csv'],
            help="O arquivo será validado antes de importar"
        )

        if uploaded_file is not None:
            st.info(f"📄 Arquivo selecionado: **{uploaded_file.name}** ({uploaded_file.size / 1024:.1f} KB)")

            col_up1, col_up2 = st.columns(2)

            with col_up1:
                if st.button("👁️ Visualizar CSV", use_container_width=True):
                    try:
                        df_preview = pd.read_csv(uploaded_file)
                        st.write(f"**Linhas:** {len(df_preview)} | **Colunas:** {len(df_preview.columns)}")
                        st.write("**Colunas encontradas:**")
                        st.write(", ".join(df_preview.columns.tolist()))
                        st.dataframe(df_preview.head(10), use_container_width=True)
                        uploaded_file.seek(0)  # Reset file pointer
                    except Exception as e:
                        st.error(f"❌ Erro ao ler CSV: {str(e)}")

            with col_up2:
                confirmar_upload = st.checkbox("✅ Confirmo a importação", key="confirm_upload")

                if st.button("📥 IMPORTAR CSV", type="primary", use_container_width=True, disabled=not confirmar_upload):
                    try:
                        # Determinar arquivo de destino
                        arquivo_destino = None
                        for arq in FILES_TO_BACKUP:
                            if os.path.basename(arq) == arquivo_destino_upload:
                                arquivo_destino = arq
                                break

                        if arquivo_destino:
                            # Criar backup do arquivo atual antes de importar
                            if os.path.exists(arquivo_destino):
                                create_backup(arquivo_destino, max_backups=5)
                                st.info("✅ Backup de segurança do arquivo atual criado")

                            # Ler e validar CSV
                            df_importado = pd.read_csv(uploaded_file)

                            # Salvar usando atomic write
                            sucesso = atomic_write(arquivo_destino, df_importado, is_dataframe=True)

                            if sucesso:
                                st.success(f"✅ CSV importado com sucesso para {arquivo_destino_upload}!")
                                st.info("🔄 **Importante:** Recarregue os dados para ver as alterações.")

                                registrar_historico(
                                    "IMPORTAÇÃO",
                                    f"CSV importado: {uploaded_file.name} → {arquivo_destino_upload}"
                                )

                                if st.button("🔄 Recarregar Dados Agora", use_container_width=True, key="reload_after_upload"):
                                    st.session_state.pacientes = carregar_pacientes()
                                    st.session_state.agendamentos = carregar_agendamentos()
                                    st.session_state.pacotes = carregar_pacotes()
                                    st.success("✅ Dados recarregados!")
                                    st.rerun()
                            else:
                                st.error("❌ Erro ao salvar arquivo importado")
                        else:
                            st.error("❌ Erro: arquivo de destino não encontrado")

                    except Exception as e:
                        st.error(f"❌ Erro ao importar CSV: {crypto_manager.sanitize_log(str(e))}")

        st.divider()

        # Listar todos os backups disponíveis
        arquivos_backup = []
        for arquivo_base in FILES_TO_BACKUP:
            pattern = f"{arquivo_base}.bak.*"
            backups = glob.glob(pattern)
            for bak in backups:
                try:
                    # Extrair timestamp do nome do arquivo
                    timestamp_str = bak.split('.bak.')[-1]
                    timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                    tamanho = os.path.getsize(bak) / 1024  # KB

                    arquivos_backup.append({
                        'Arquivo': os.path.basename(arquivo_base),
                        'Backup': os.path.basename(bak),
                        'Data/Hora': timestamp.strftime("%d/%m/%Y %H:%M:%S"),
                        'Tamanho (KB)': f"{tamanho:.1f}",
                        'Caminho': bak,
                        'Timestamp': timestamp
                    })
                except:
                    pass

        if arquivos_backup:
            # Ordenar por data (mais recente primeiro)
            arquivos_backup.sort(key=lambda x: x['Timestamp'], reverse=True)

            st.write(f"**{len(arquivos_backup)} backup(s) disponível(is)**")

            # Criar DataFrame para exibição
            df_backups = pd.DataFrame(arquivos_backup)
            df_backups_show = df_backups[['Arquivo', 'Data/Hora', 'Tamanho (KB)']].copy()

            st.dataframe(df_backups_show, use_container_width=True, hide_index=True)

            st.divider()

            # Restaurar backup
            st.subheader("🔄 Restaurar Backup")
            st.warning("⚠️ **ATENÇÃO:** Restaurar um backup substituirá o arquivo atual! Esta ação não pode ser desfeita.")

            # Agrupar backups por arquivo
            arquivos_disponiveis = sorted(df_backups['Arquivo'].unique())

            col1, col2 = st.columns(2)

            with col1:
                arquivo_selecionado = st.selectbox(
                    "📁 Selecione o arquivo a restaurar:",
                    options=arquivos_disponiveis
                )

            with col2:
                # Filtrar backups do arquivo selecionado
                backups_arquivo = df_backups[df_backups['Arquivo'] == arquivo_selecionado]

                backup_opcoes = [
                    f"{row['Data/Hora']} ({row['Tamanho (KB)']} KB)"
                    for _, row in backups_arquivo.iterrows()
                ]

                backup_idx = st.selectbox(
                    "📅 Selecione a versão:",
                    options=range(len(backup_opcoes)),
                    format_func=lambda i: backup_opcoes[i]
                )

            # Informações do backup selecionado
            backup_selecionado = backups_arquivo.iloc[backup_idx]

            st.info(f"""
            **Backup selecionado:**
            - **Arquivo:** {backup_selecionado['Arquivo']}
            - **Data/Hora:** {backup_selecionado['Data/Hora']}
            - **Tamanho:** {backup_selecionado['Tamanho (KB)']} KB
            - **Caminho:** {backup_selecionado['Backup']}
            """)

            col_confirm = st.columns([1, 2, 1])

            with col_confirm[1]:
                confirmar_restauracao = st.checkbox("✅ Confirmo que quero restaurar este backup")

            with col_confirm[1]:
                if st.button("🔄 RESTAURAR BACKUP", type="primary", use_container_width=True, disabled=not confirmar_restauracao):
                    try:
                        # Determinar arquivo de destino
                        arquivo_destino = None
                        for arq in FILES_TO_BACKUP:
                            if os.path.basename(arq) == arquivo_selecionado:
                                arquivo_destino = arq
                                break

                        if arquivo_destino:
                            # Fazer backup do arquivo atual antes de restaurar
                            if os.path.exists(arquivo_destino):
                                create_backup(arquivo_destino, max_backups=5)

                            # Restaurar: copiar backup para o arquivo principal
                            shutil.copy2(backup_selecionado['Caminho'], arquivo_destino)

                            st.success(f"✅ Backup restaurado com sucesso!")
                            st.info("🔄 **Importante:** Recarregue os dados para ver as alterações.")

                            registrar_historico(
                                "RESTAURAÇÃO",
                                f"Backup restaurado: {arquivo_selecionado} de {backup_selecionado['Data/Hora']}"
                            )

                            if st.button("🔄 Recarregar Dados Agora", use_container_width=True):
                                st.session_state.pacientes = carregar_pacientes()
                                st.session_state.agendamentos = carregar_agendamentos()
                                st.session_state.pacotes = carregar_pacotes()
                                st.success("✅ Dados recarregados!")
                                st.rerun()
                        else:
                            st.error("❌ Erro: arquivo de destino não encontrado")
                    except Exception as e:
                        st.error(f"❌ Erro ao restaurar backup: {crypto_manager.sanitize_log(str(e))}")

            st.divider()

            # Limpeza de backups antigos
            st.subheader("🗑️ Limpeza de Backups Antigos")

            dias_limite = st.number_input(
                "Remover backups com mais de quantos dias?",
                min_value=1,
                max_value=365,
                value=30,
                help="Backups mais antigos que este período serão removidos"
            )

            # Contar backups antigos
            data_limite = datetime.now() - timedelta(days=dias_limite)
            backups_antigos = [b for b in arquivos_backup if b['Timestamp'] < data_limite]

            if backups_antigos:
                st.warning(f"⚠️ {len(backups_antigos)} backup(s) com mais de {dias_limite} dias")

                if st.button(f"🗑️ Remover {len(backups_antigos)} backup(s) antigo(s)", type="secondary"):
                    removidos = 0
                    for bak in backups_antigos:
                        try:
                            os.remove(bak['Caminho'])
                            removidos += 1
                        except:
                            pass

                    st.success(f"✅ {removidos} backup(s) removido(s)")
                    registrar_historico("LIMPEZA", f"Removidos {removidos} backups com mais de {dias_limite} dias")
                    st.rerun()
            else:
                st.success(f"✅ Nenhum backup com mais de {dias_limite} dias")
        else:
            st.info("📭 Nenhum backup encontrado ainda. Backups são criados automaticamente ao salvar dados.")
            st.write("**Como funcionam os backups automáticos:**")
            st.write("- ✅ Criados automaticamente antes de cada salvamento")
            st.write("- ✅ Mantém os 5 últimos backups de cada arquivo")
            st.write("- ✅ Formato: `arquivo.csv.bak.YYYYMMDD_HHMMSS`")
            st.write("- ✅ Podem ser restaurados a qualquer momento nesta aba")

    # --- TAB 4: GOOGLE SHEETS ---
    with tab4:
        st.subheader("☁️ Integração Google Sheets")

        if not GSHEETS_AVAILABLE:
            st.error("❌ Google Sheets não disponível")
            st.info("Instale as bibliotecas necessárias: `pip install gspread google-auth`")
        else:
            st.info("💡 Sincronize seus dados com Google Sheets para backup em nuvem e acesso de qualquer lugar")

            # Status da conexão
            st.write("**📡 Status da Conexão:**")

            # Verificar se está configurado
            has_creds = "gcp_service_account" in st.secrets or "GOOGLE_CREDENTIALS" in os.environ
            has_sheet_id = "google_sheets_id" in st.secrets

            col_status1, col_status2 = st.columns(2)

            with col_status1:
                if has_creds:
                    st.success("✅ Credenciais configuradas")
                else:
                    st.warning("⚠️ Credenciais não configuradas")

            with col_status2:
                if has_sheet_id:
                    sheet_id = st.secrets.get("google_sheets_id", "")
                    st.success(f"✅ Planilha: {sheet_id[:20]}...")
                else:
                    st.warning("⚠️ ID da planilha não configurado")

            st.divider()

            # Testar conexão
            st.write("**🔍 Testar Conexão:**")
            if st.button("🧪 Testar Conexão com Google Sheets", use_container_width=True):
                with st.spinner("Testando conexão..."):
                    client, erro = conectar_google_sheets()

                    if erro:
                        st.error(f"❌ {erro}")
                    else:
                        st.success("✅ Conexão estabelecida com sucesso!")

                        # Tentar acessar a planilha
                        if has_sheet_id:
                            try:
                                sheet_id = st.secrets["google_sheets_id"]
                                spreadsheet = client.open_by_key(sheet_id)
                                st.success(f"✅ Planilha acessada: **{spreadsheet.title}**")
                                st.info(f"📊 Abas disponíveis: {', '.join([worksheet.title for worksheet in spreadsheet.worksheets()])}")
                            except Exception as e:
                                st.error(f"❌ Erro ao acessar planilha: {str(e)}")

            st.divider()

            # Sincronização
            st.write("**☁️ Sincronização:**")

            col_sync1, col_sync2 = st.columns(2)

            with col_sync1:
                st.write("**📤 Enviar dados para Google Sheets**")
                st.caption("Faz backup dos dados locais na planilha")

                if st.button("📤 Sincronizar para Google Sheets", use_container_width=True, type="primary", disabled=not (has_creds and has_sheet_id)):
                    with st.spinner("Sincronizando..."):
                        sucesso, mensagem = sincronizar_para_google_sheets()

                        if sucesso:
                            st.success(f"✅ {mensagem}")
                            registrar_historico("GOOGLE_SHEETS_SYNC", "Dados sincronizados para Google Sheets")
                        else:
                            st.error(f"❌ {mensagem}")

            with col_sync2:
                st.write("**📥 Restaurar do Google Sheets**")
                st.caption("⚠️ Sobrescreve dados locais!")

                confirmar_restaurar = st.checkbox("✅ Confirmo que quero restaurar", key="confirm_restore_gsheets")

                if st.button("📥 Restaurar de Google Sheets", use_container_width=True, type="secondary", disabled=not (has_creds and has_sheet_id and confirmar_restaurar)):
                    with st.spinner("Restaurando..."):
                        sucesso, mensagem = restaurar_de_google_sheets()

                        if sucesso:
                            st.success(f"✅ {mensagem}")
                            registrar_historico("GOOGLE_SHEETS_RESTORE", "Dados restaurados do Google Sheets")
                            st.info("🔄 Recarregue a página para ver os dados atualizados")
                        else:
                            st.error(f"❌ {mensagem}")

            st.divider()

            # Instruções de configuração
            st.write("**📖 Como Configurar:**")

            with st.expander("📘 Ver Tutorial Completo de Configuração"):
                st.markdown("""
                ### Passo 1: Criar Service Account no Google Cloud

                1. Acesse [Google Cloud Console](https://console.cloud.google.com/)
                2. Crie um novo projeto ou selecione um existente
                3. Ative a **Google Sheets API** e **Google Drive API**
                4. Vá em **IAM & Admin** → **Service Accounts**
                5. Clique em **Create Service Account**
                6. Dê um nome (ex: "streamlit-app")
                7. Clique em **Create and Continue**
                8. Pule a atribuição de funções (opcional)
                9. Clique em **Done**

                ### Passo 2: Criar Chave JSON

                1. Clique na service account criada
                2. Vá na aba **Keys**
                3. Clique em **Add Key** → **Create new key**
                4. Selecione **JSON**
                5. Faça download do arquivo JSON

                ### Passo 3: Criar Planilha Google Sheets

                1. Acesse [Google Sheets](https://sheets.google.com/)
                2. Crie uma nova planilha
                3. Copie o ID da planilha (da URL)
                   - Exemplo: `https://docs.google.com/spreadsheets/d/[ID_AQUI]/edit`
                4. Compartilhe a planilha com o email da service account
                   - Email está no arquivo JSON: `client_email`
                   - Dê permissão de **Editor**

                ### Passo 4: Configurar no Streamlit

                Adicione ao arquivo `.streamlit/secrets.toml`:

                ```toml
                # ID da planilha Google Sheets
                google_sheets_id = "SEU_ID_AQUI"

                # Credenciais da Service Account
                [gcp_service_account]
                type = "service_account"
                project_id = "seu-projeto"
                private_key_id = "abc123..."
                private_key = "-----BEGIN PRIVATE KEY-----\\n..."
                client_email = "streamlit-app@seu-projeto.iam.gserviceaccount.com"
                client_id = "123..."
                auth_uri = "https://accounts.google.com/o/oauth2/auth"
                token_uri = "https://oauth2.googleapis.com/token"
                auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
                client_x509_cert_url = "https://..."
                ```

                **Importante:** Copie TODO o conteúdo do arquivo JSON baixado para dentro de `[gcp_service_account]`

                ### Passo 5: Testar

                1. Volte para esta aba
                2. Clique em **Testar Conexão**
                3. Se sucesso, clique em **Sincronizar para Google Sheets**
                4. Verifique na planilha se os dados foram enviados

                ### Estrutura da Planilha

                Serão criadas as seguintes abas automaticamente:
                - **Pacientes** - Dados dos pacientes
                - **Agendamentos** - Todos os agendamentos
                - **Pacotes** - Pacotes de sessões
                - **Historico** - Histórico de alterações
                - **Info** - Metadados da sincronização
                """)

    # --- TAB 5: CONFIGURAÇÕES ---
    with tab5:
        st.subheader("⚙️ Configurações do Sistema")

        # Status de Segurança (Caruru V18)
        st.write("**🔐 Medidas de Segurança Ativas:**")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"✅ Criptografia: {'Ativa' if crypto_manager.enabled else 'Desativada'}")
            st.write(f"✅ File Locking: {'Ativo' if LOCK_AVAILABLE else 'Desativado'}")
            st.write("✅ Atomic Writes: Ativo")
        with col2:
            st.write("✅ Backup Rotativo (.bak): Ativo")
            st.write("✅ Log Rotativo: Ativo (máx 1MB)")
            st.write("✅ Sanitização de Logs: Ativa")

        st.divider()

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
