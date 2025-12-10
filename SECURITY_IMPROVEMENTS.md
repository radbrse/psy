# 🔐 Melhorias de Segurança, Estabilidade e Funcionalidade

## Versão 1.2 - Atualização de Segurança

Este documento descreve as melhorias implementadas no sistema de agendamento de psicologia para aumentar a segurança, estabilidade e funcionalidade do sistema.

---

## 📋 Sumário Executivo

### Problemas Críticos Resolvidos:

1. ✅ **Senha hardcoded removida** - eliminado risco de acesso não autorizado
2. ✅ **Criptografia de dados sensíveis** - CPF, telefones e prontuários agora protegidos
3. ✅ **Sistema de backup automático** - proteção contra perda de dados
4. ✅ **Sanitização de logs** - informações sensíveis não aparecem mais em logs
5. ✅ **Validação de integridade** - detecção de corrupção de dados
6. ✅ **Proteção contra força bruta** - limite de tentativas de login
7. ✅ **Sistema de recuperação** - restauração de backups com validação

---

## 🔒 Melhorias de Segurança

### 1. Sistema de Autenticação Aprimorado

#### Antes:
```python
# VULNERÁVEL - Senha hardcoded no código
if password == "psi2025":
    login_ok = True
```

#### Depois:
```python
# SEGURO - Senha em secrets ou variável de ambiente
correct_password = st.secrets.get("password") or os.environ.get("PSI_PASSWORD")

# Proteção contra força bruta
- Máximo 5 tentativas
- Bloqueio de 5 minutos após exceder limite
- Contador de tentativas por sessão
```

**Configuração necessária:**
```toml
# .streamlit/secrets.toml
password = "sua_senha_forte_aqui"
master_password = "senha_para_criptografia"
```

Ou via variáveis de ambiente:
```bash
export PSI_PASSWORD="sua_senha_forte"
export MASTER_PASSWORD="senha_criptografia"
```

---

### 2. Criptografia de Dados Sensíveis

#### Campos Criptografados:
- ✅ CPF dos pacientes
- ✅ Telefones
- ✅ Prontuários clínicos (dados LGPD)

#### Tecnologia:
- **Algoritmo**: Fernet (criptografia simétrica AES-128)
- **Derivação de chave**: PBKDF2-SHA256 (100.000 iterações)
- **Retrocompatibilidade**: Dados antigos são migrados automaticamente

#### Exemplo de uso:
```python
# Ao salvar - criptografa automaticamente
df.loc[idx, 'CPF'] = security_manager.encrypt(cpf)

# Ao carregar - descriptografa automaticamente
cpf = security_manager.decrypt(df.loc[idx, 'CPF'])
```

---

### 3. Sanitização de Logs

#### Proteção contra vazamento de dados em logs:

**Antes:**
```
Erro ao processar paciente: João Silva, CPF 123.456.789-00, Tel (11) 98765-4321
```

**Depois:**
```
Erro ao processar paciente: João Silva, CPF:***, Tel:***
```

#### Padrões sanitizados automaticamente:
- CPF (formatado e não formatado)
- Telefones
- E-mails
- Outros dados sensíveis conforme regex configurável

---

## 💾 Sistema de Backup e Recuperação

### Funcionalidades:

#### 1. Backup Automático
- **Diário**: Criado automaticamente a cada salvamento (se passar 24h do último)
- **Semanal**: Retenção de 7 dias
- **Mensal**: Retenção de longo prazo

#### 2. Versionamento
- Mantém até 10 versões de cada tipo
- Limpeza automática de backups antigos
- Metadados JSON para cada backup

#### 3. Validação de Integridade
- Checksum SHA-256 de cada arquivo
- Verificação antes de restaurar
- Detecção de corrupção

#### 4. Estrutura de Diretórios:
```
backups/
├── daily/
│   ├── 20251210_143022/
│   │   ├── banco_agendamentos.csv
│   │   ├── banco_pacientes.csv
│   │   ├── banco_pacotes.csv
│   │   ├── historico_alteracoes_psi.csv
│   │   └── backup_metadata.json
│   └── ...
├── weekly/
│   └── ...
└── monthly/
    └── ...
```

#### 5. Metadados de Backup:
```json
{
  "timestamp": "20251210_143022",
  "type": "daily",
  "files": ["banco_agendamentos.csv", "banco_pacientes.csv", ...],
  "checksums": {
    "banco_agendamentos.csv": "a3f5e2...",
    "banco_pacientes.csv": "b7c9d1..."
  }
}
```

---

## ✅ Validação de Integridade

### Verificações Implementadas:

1. **Estrutura de CSV**
   - Valida colunas obrigatórias
   - Detecta arquivos corrompidos
   - Registra erros no log

2. **Checksums de Arquivos**
   - SHA-256 para cada arquivo
   - Verificação antes de restaurar backup
   - Proteção contra adulteração

3. **Tratamento de Erros Robusto**
   - Try/catch em todas as operações críticas
   - Logging detalhado de erros
   - Mensagens amigáveis ao usuário

---

## 🎯 Melhorias de Estabilidade

### 1. Gerenciamento de Erros
- Todos os try/except agora com logging adequado
- Rollback em caso de falha
- Mensagens de erro sanitizadas

### 2. Retrocompatibilidade
- Suporta dados antigos não criptografados
- Migração automática na primeira leitura
- Sem quebra de funcionalidade

### 3. Validação de Entrada
- Verificação de estrutura de dados
- Tratamento de valores None/NaN
- Preenchimento de valores padrão

---

## 🚀 Novas Funcionalidades

### Interface de Backup & Recuperação

Nova aba no menu "Manutenção" com:

1. **Dashboard de Status**
   - Status da criptografia
   - Número de backups
   - Espaço utilizado

2. **Criação Manual de Backups**
   - Botões para criar backup imediato
   - Três tipos: Diário, Semanal, Mensal
   - Feedback visual do processo

3. **Listagem de Backups**
   - Tabela com todos os backups
   - Filtro por tipo
   - Informações de data, tamanho e arquivos

4. **Restauração de Dados**
   - Seleção de backup para restaurar
   - Confirmação obrigatória
   - Validação de integridade antes de restaurar

5. **Exportação Individual**
   - Download de cada arquivo CSV
   - Backup externo manual
   - Formato original preservado

---

## 📊 Comparação Antes x Depois

| Aspecto | Antes | Depois |
|---------|-------|--------|
| **Senha** | Hardcoded no código | Secrets/Env obrigatório |
| **Tentativas de login** | Ilimitadas | Máximo 5 (bloqueio 5min) |
| **Dados sensíveis** | Texto plano | Criptografados AES-128 |
| **Backup** | Nenhum | Automático + Manual |
| **Recuperação** | Impossível | Sistema completo |
| **Logs** | Expõem dados sensíveis | Sanitizados |
| **Integridade** | Sem validação | Checksums SHA-256 |
| **Auditoria** | Básica | Detalhada + Sanitizada |

---

## 🔧 Instalação e Configuração

### 1. Instalar Dependências
```bash
pip install -r requirements.txt
```

### 2. Configurar Secrets
Criar arquivo `.streamlit/secrets.toml`:
```toml
# Senha de acesso ao sistema
password = "SuaSenhaForteAqui123!"

# Senha mestra para criptografia (manter em segredo!)
master_password = "ChaveCriptografiaForte456@"
```

### 3. Ou Usar Variáveis de Ambiente
```bash
export PSI_PASSWORD="SuaSenhaForteAqui123!"
export MASTER_PASSWORD="ChaveCriptografiaForte456@"
```

### 4. Executar Sistema
```bash
streamlit run app.py
```

---

## ⚠️ Considerações Importantes

### Segurança:

1. **NUNCA** compartilhe a `master_password`
2. **SEMPRE** faça backups antes de atualizações
3. **Configure** senhas fortes e únicas
4. **Mantenha** o arquivo `secrets.toml` fora do Git
5. **Monitore** os logs regularmente

### LGPD e Conformidade:

- ✅ Dados sensíveis criptografados
- ✅ Logs sanitizados sem dados pessoais
- ✅ Sistema de backup e recuperação
- ✅ Auditoria de alterações
- ✅ Controle de acesso robusto

### Backup:

1. **Automático**: Criado ao salvar dados (diário)
2. **Manual**: Disponível no menu Manutenção
3. **Externo**: Exporte CSVs periodicamente
4. **Teste**: Restaure backups periodicamente para validar

---

## 📈 Próximas Melhorias Recomendadas

### Curto Prazo:
- [ ] Autenticação de dois fatores (2FA)
- [ ] Criptografia adicional em repouso
- [ ] Backup em nuvem (opcional)
- [ ] Notificações de backup via email

### Médio Prazo:
- [ ] Controle de acesso baseado em roles
- [ ] Auditoria completa de acessos
- [ ] Relatórios de segurança
- [ ] Testes de penetração

### Longo Prazo:
- [ ] Migração para banco de dados
- [ ] API REST segura
- [ ] Integração com sistemas externos
- [ ] Dashboard de analytics

---

## 📞 Suporte e Manutenção

### Em caso de problemas:

1. **Verificar logs**: Menu Manutenção → Logs
2. **Histórico**: Menu Manutenção → Histórico
3. **Restaurar backup**: Menu Manutenção → Backup & Recuperação
4. **Recarregar dados**: Menu Manutenção → Configurações → Recarregar

### Arquivos importantes:
- `app.py` - Aplicação principal
- `security_manager.py` - Módulo de segurança
- `requirements.txt` - Dependências
- `.streamlit/secrets.toml` - Configuração sensível (NÃO versionar)
- `backups/` - Diretório de backups

---

## 📄 Licença e Responsabilidade

Este sistema contém dados sensíveis de saúde. É responsabilidade do operador:
- Manter senhas seguras
- Realizar backups regulares
- Monitorar acessos
- Cumprir legislação vigente (LGPD, CFP, etc.)
- Manter sistema atualizado

---

## ✅ Checklist de Implementação

- [x] Remover senha hardcoded
- [x] Implementar criptografia de dados
- [x] Criar sistema de backup
- [x] Adicionar sanitização de logs
- [x] Validação de integridade
- [x] Interface de recuperação
- [x] Proteção contra força bruta
- [x] Documentação completa
- [x] Testes de sintaxe
- [ ] Testes de integração
- [ ] Treinamento de usuários
- [ ] Deploy em produção

---

**Versão do documento:** 1.0
**Data:** 10/12/2025
**Autor:** Sistema de Melhorias Automáticas
**Versão do sistema:** 1.2
