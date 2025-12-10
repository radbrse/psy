"""
Módulo de Segurança e Proteção de Dados
========================================
Fornece criptografia, backup automático e validação de integridade para dados sensíveis.
"""

import os
import hashlib
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.backends import default_backend
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("⚠️ Módulo cryptography não disponível. Instale com: pip install cryptography")

logger = logging.getLogger("security_manager")


class SecurityManager:
    """Gerenciador de segurança para criptografia e proteção de dados."""

    def __init__(self, master_password: Optional[str] = None):
        """
        Inicializa o gerenciador de segurança.

        Args:
            master_password: Senha mestra para derivar chave de criptografia.
                           Se None, usa variável de ambiente MASTER_PASSWORD.
        """
        self.enabled = CRYPTO_AVAILABLE
        self.cipher = None

        if not self.enabled:
            logger.warning("Criptografia desabilitada - módulo cryptography não disponível")
            return

        # Obter senha mestra de forma segura
        password = master_password or os.environ.get('MASTER_PASSWORD')
        if not password:
            logger.warning("Senha mestra não configurada - usando padrão (INSEGURO)")
            password = "DEFAULT_PASSWORD_CHANGE_ME"

        # Derivar chave de criptografia da senha
        self.cipher = self._create_cipher(password)

    def _create_cipher(self, password: str) -> Fernet:
        """Cria cipher Fernet a partir de senha."""
        # Salt fixo armazenado de forma segura (idealmente em arquivo separado)
        salt = b'psi_agenda_salt_v1_2025'  # Em produção, gerar e armazenar de forma segura

        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def encrypt(self, data: str) -> str:
        """
        Criptografa uma string.

        Args:
            data: Texto a ser criptografado

        Returns:
            Texto criptografado em base64 (ou texto original se criptografia desabilitada)
        """
        if not self.enabled or not data:
            return data

        try:
            encrypted = self.cipher.encrypt(data.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Erro ao criptografar: {e}")
            return data

    def decrypt(self, encrypted_data: str) -> str:
        """
        Descriptografa uma string.

        Args:
            encrypted_data: Texto criptografado

        Returns:
            Texto original (ou texto criptografado se falhar)
        """
        if not self.enabled or not encrypted_data:
            return encrypted_data

        try:
            decrypted = self.cipher.decrypt(encrypted_data.encode())
            return decrypted.decode()
        except Exception as e:
            # Se falhar, pode ser dado não criptografado (retrocompatibilidade)
            logger.debug(f"Não foi possível descriptografar (pode ser dado não criptografado): {e}")
            return encrypted_data

    def hash_data(self, data: str) -> str:
        """Gera hash SHA-256 de dados (para validação de integridade)."""
        return hashlib.sha256(data.encode()).hexdigest()

    def sanitize_for_log(self, text: str, fields_to_hide: List[str] = None) -> str:
        """
        Sanitiza texto para logs, removendo informações sensíveis.

        Args:
            text: Texto a ser sanitizado
            fields_to_hide: Lista de padrões a esconder (CPF, telefone, etc)

        Returns:
            Texto sanitizado
        """
        if not text:
            return text

        import re
        sanitized = text

        # Padrões sensíveis
        patterns = {
            r'\d{3}\.\d{3}\.\d{3}-\d{2}': 'CPF:***',  # CPF formatado
            r'\b\d{11}\b': 'CPF:***',  # CPF sem formatação
            r'\b\d{10,11}\b': 'TEL:***',  # Telefone
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}': 'EMAIL:***',  # Email
        }

        for pattern, replacement in patterns.items():
            sanitized = re.sub(pattern, replacement, sanitized)

        return sanitized


class BackupManager:
    """Gerenciador de backups automáticos com versionamento."""

    def __init__(self, backup_dir: str = "backups", max_versions: int = 10):
        """
        Inicializa gerenciador de backups.

        Args:
            backup_dir: Diretório para armazenar backups
            max_versions: Número máximo de versões a manter
        """
        self.backup_dir = Path(backup_dir)
        self.max_versions = max_versions
        self.backup_dir.mkdir(exist_ok=True)

        # Subdiretórios organizados
        self.daily_dir = self.backup_dir / "daily"
        self.weekly_dir = self.backup_dir / "weekly"
        self.monthly_dir = self.backup_dir / "monthly"

        for dir_path in [self.daily_dir, self.weekly_dir, self.monthly_dir]:
            dir_path.mkdir(exist_ok=True)

    def create_backup(self, files_to_backup: List[str], backup_type: str = "daily") -> Optional[str]:
        """
        Cria backup de arquivos.

        Args:
            files_to_backup: Lista de caminhos de arquivos para backup
            backup_type: Tipo de backup (daily, weekly, monthly)

        Returns:
            Caminho do arquivo de backup criado ou None se falhar
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Determinar diretório de destino
        if backup_type == "weekly":
            target_dir = self.weekly_dir
        elif backup_type == "monthly":
            target_dir = self.monthly_dir
        else:
            target_dir = self.daily_dir

        backup_subdir = target_dir / timestamp
        backup_subdir.mkdir(exist_ok=True)

        # Metadados do backup
        metadata = {
            "timestamp": timestamp,
            "type": backup_type,
            "files": [],
            "checksums": {}
        }

        try:
            # Copiar e validar cada arquivo
            for file_path in files_to_backup:
                if not os.path.exists(file_path):
                    logger.warning(f"Arquivo não existe para backup: {file_path}")
                    continue

                file_name = os.path.basename(file_path)
                backup_file = backup_subdir / file_name

                # Copiar arquivo
                shutil.copy2(file_path, backup_file)

                # Calcular checksum para integridade
                with open(file_path, 'rb') as f:
                    checksum = hashlib.sha256(f.read()).hexdigest()

                metadata["files"].append(file_name)
                metadata["checksums"][file_name] = checksum

            # Salvar metadados
            metadata_file = backup_subdir / "backup_metadata.json"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)

            logger.info(f"Backup criado: {backup_subdir}")

            # Limpar backups antigos
            self._cleanup_old_backups(target_dir)

            return str(backup_subdir)

        except Exception as e:
            logger.error(f"Erro ao criar backup: {e}")
            # Limpar backup parcial
            if backup_subdir.exists():
                shutil.rmtree(backup_subdir, ignore_errors=True)
            return None

    def _cleanup_old_backups(self, backup_dir: Path):
        """Remove backups antigos mantendo apenas max_versions."""
        try:
            backups = sorted([d for d in backup_dir.iterdir() if d.is_dir()],
                           reverse=True)

            # Manter apenas max_versions mais recentes
            for old_backup in backups[self.max_versions:]:
                shutil.rmtree(old_backup, ignore_errors=True)
                logger.info(f"Backup antigo removido: {old_backup}")

        except Exception as e:
            logger.error(f"Erro ao limpar backups antigos: {e}")

    def restore_backup(self, backup_path: str, target_dir: str = ".") -> bool:
        """
        Restaura arquivos de um backup.

        Args:
            backup_path: Caminho do diretório de backup
            target_dir: Diretório de destino para restauração

        Returns:
            True se restauração bem-sucedida
        """
        backup_path = Path(backup_path)

        if not backup_path.exists():
            logger.error(f"Backup não encontrado: {backup_path}")
            return False

        try:
            # Ler metadados
            metadata_file = backup_path / "backup_metadata.json"
            if not metadata_file.exists():
                logger.error("Metadados de backup não encontrados")
                return False

            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)

            # Restaurar cada arquivo
            for file_name in metadata["files"]:
                backup_file = backup_path / file_name
                target_file = Path(target_dir) / file_name

                if not backup_file.exists():
                    logger.warning(f"Arquivo de backup não encontrado: {file_name}")
                    continue

                # Verificar checksum antes de restaurar
                with open(backup_file, 'rb') as f:
                    checksum = hashlib.sha256(f.read()).hexdigest()

                if checksum != metadata["checksums"].get(file_name):
                    logger.error(f"Checksum inválido para {file_name} - backup pode estar corrompido")
                    return False

                # Restaurar arquivo
                shutil.copy2(backup_file, target_file)
                logger.info(f"Arquivo restaurado: {file_name}")

            logger.info(f"Backup restaurado com sucesso de: {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Erro ao restaurar backup: {e}")
            return False

    def list_backups(self, backup_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Lista backups disponíveis.

        Args:
            backup_type: Filtrar por tipo (daily, weekly, monthly) ou None para todos

        Returns:
            Lista de dicionários com informações dos backups
        """
        backups = []

        dirs_to_check = []
        if backup_type == "daily" or backup_type is None:
            dirs_to_check.append(("daily", self.daily_dir))
        if backup_type == "weekly" or backup_type is None:
            dirs_to_check.append(("weekly", self.weekly_dir))
        if backup_type == "monthly" or backup_type is None:
            dirs_to_check.append(("monthly", self.monthly_dir))

        for btype, bdir in dirs_to_check:
            if not bdir.exists():
                continue

            for backup_dir in sorted(bdir.iterdir(), reverse=True):
                if not backup_dir.is_dir():
                    continue

                metadata_file = backup_dir / "backup_metadata.json"
                if metadata_file.exists():
                    try:
                        with open(metadata_file, 'r', encoding='utf-8') as f:
                            metadata = json.load(f)

                        backups.append({
                            "path": str(backup_dir),
                            "timestamp": metadata["timestamp"],
                            "type": btype,
                            "files": metadata["files"],
                            "size_mb": sum(
                                (backup_dir / f).stat().st_size
                                for f in metadata["files"]
                                if (backup_dir / f).exists()
                            ) / (1024 * 1024)
                        })
                    except Exception as e:
                        logger.error(f"Erro ao ler metadados de backup: {e}")

        return backups

    def should_create_backup(self, backup_type: str) -> bool:
        """
        Verifica se deve criar backup baseado no tipo e último backup.

        Args:
            backup_type: Tipo de backup (daily, weekly, monthly)

        Returns:
            True se deve criar novo backup
        """
        backups = self.list_backups(backup_type)

        if not backups:
            return True

        last_backup = backups[0]
        last_time = datetime.strptime(last_backup["timestamp"], "%Y%m%d_%H%M%S")
        now = datetime.now()

        # Determinar intervalo baseado no tipo
        if backup_type == "daily":
            return (now - last_time) >= timedelta(days=1)
        elif backup_type == "weekly":
            return (now - last_time) >= timedelta(days=7)
        elif backup_type == "monthly":
            return (now - last_time) >= timedelta(days=30)

        return False


class DataIntegrityValidator:
    """Validador de integridade de dados."""

    @staticmethod
    def validate_csv_structure(file_path: str, required_columns: List[str]) -> tuple[bool, Optional[str]]:
        """
        Valida estrutura de arquivo CSV.

        Args:
            file_path: Caminho do arquivo CSV
            required_columns: Colunas obrigatórias

        Returns:
            (válido, mensagem de erro)
        """
        if not os.path.exists(file_path):
            return True, None  # Arquivo novo, OK

        try:
            import pandas as pd
            df = pd.read_csv(file_path)

            missing_cols = set(required_columns) - set(df.columns)
            if missing_cols:
                return False, f"Colunas faltando: {missing_cols}"

            return True, None

        except Exception as e:
            return False, f"Erro ao validar CSV: {e}"

    @staticmethod
    def calculate_file_hash(file_path: str) -> Optional[str]:
        """Calcula hash SHA-256 de arquivo."""
        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.error(f"Erro ao calcular hash: {e}")
            return None

    @staticmethod
    def verify_file_integrity(file_path: str, expected_hash: str) -> bool:
        """Verifica integridade de arquivo comparando hash."""
        current_hash = DataIntegrityValidator.calculate_file_hash(file_path)
        return current_hash == expected_hash if current_hash else False


# Funções auxiliares para facilitar uso
def create_security_manager(password: Optional[str] = None) -> SecurityManager:
    """Cria instância de SecurityManager."""
    return SecurityManager(password)


def create_backup_manager(backup_dir: str = "backups", max_versions: int = 10) -> BackupManager:
    """Cria instância de BackupManager."""
    return BackupManager(backup_dir, max_versions)
