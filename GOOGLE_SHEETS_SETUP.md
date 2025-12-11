# 📊 Guia Completo: Integração Google Sheets

Este guia detalha como configurar a sincronização automática com Google Sheets para backup em nuvem dos seus dados.

## 🎯 Benefícios

- ✅ **Backup automático em nuvem** - Seus dados seguros no Google Drive
- ✅ **Acesso de qualquer lugar** - Visualize dados pela planilha
- ✅ **Sincronização bidirecional** - Upload e download
- ✅ **Colaboração facilitada** - Compartilhe com equipe
- ✅ **Histórico completo** - Todas as alterações registradas

## 📋 Pré-requisitos

- Conta Google (Gmail)
- Acesso ao [Google Cloud Console](https://console.cloud.google.com/)
- Projeto Streamlit rodando localmente

## 🚀 Configuração Passo a Passo

### Passo 1: Criar Projeto no Google Cloud

1. Acesse: https://console.cloud.google.com/
2. Clique em **Select a project** (topo da página)
3. Clique em **NEW PROJECT**
4. Nome do projeto: `streamlit-psi` (ou outro nome)
5. Clique em **CREATE**
6. Aguarde a criação (alguns segundos)
7. Selecione o projeto recém-criado

### Passo 2: Ativar APIs Necessárias

#### Google Sheets API:
1. No menu lateral, vá em **APIs & Services** → **Library**
2. Busque por "Google Sheets API"
3. Clique no resultado
4. Clique em **ENABLE**
5. Aguarde a ativação

#### Google Drive API:
1. Ainda em **Library**, busque por "Google Drive API"
2. Clique no resultado
3. Clique em **ENABLE**
4. Aguarde a ativação

### Passo 3: Criar Service Account

1. No menu lateral, vá em **IAM & Admin** → **Service Accounts**
2. Clique em **+ CREATE SERVICE ACCOUNT**
3. Preencha:
   - **Service account name:** `streamlit-app`
   - **Service account ID:** (gerado automaticamente)
   - **Description:** `Service account para Streamlit`
4. Clique em **CREATE AND CONTINUE**
5. **Grant this service account access to project:**
   - Pode pular esta etapa (opcional)
   - Clique em **CONTINUE**
6. **Grant users access to this service account:**
   - Pode pular esta etapa (opcional)
   - Clique em **DONE**

### Passo 4: Gerar Chave JSON

1. Na lista de Service Accounts, clique na que você acabou de criar
2. Vá na aba **KEYS** (no topo)
3. Clique em **ADD KEY** → **Create new key**
4. Selecione **JSON**
5. Clique em **CREATE**
6. Um arquivo JSON será baixado automaticamente
7. **IMPORTANTE:** Guarde este arquivo com segurança! Não compartilhe!

### Passo 5: Criar Planilha Google Sheets

1. Acesse: https://sheets.google.com/
2. Clique em **+ Blank** (nova planilha em branco)
3. Dê um nome: **Sistema Psi - Backup**
4. Copie o **ID da planilha** da URL:
   ```
   https://docs.google.com/spreadsheets/d/[COPIE_ESTE_ID]/edit
   ```
   Exemplo: `1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms`

### Passo 6: Compartilhar Planilha com Service Account

1. Na planilha, clique em **Share** (topo direito)
2. No campo "Add people", cole o email da service account:
   - Abra o arquivo JSON baixado no Passo 4
   - Procure por `"client_email":`
   - Copie o email (algo como: `streamlit-app@seu-projeto.iam.gserviceaccount.com`)
3. Cole o email no campo
4. Selecione **Editor** (não Viewer!)
5. **Desmarque** "Notify people"
6. Clique em **Share**

### Passo 7: Configurar secrets.toml no Streamlit

1. No diretório do projeto, crie a pasta `.streamlit` se não existir:
   ```bash
   mkdir -p .streamlit
   ```

2. Crie/edite o arquivo `.streamlit/secrets.toml`:
   ```bash
   nano .streamlit/secrets.toml
   ```

3. Adicione as seguintes configurações:

```toml
# ========================================
# GOOGLE SHEETS CONFIGURATION
# ========================================

# ID da planilha (da URL do Passo 5)
google_sheets_id = "COLE_O_ID_AQUI"

# Credenciais da Service Account
# IMPORTANTE: Copie TODO o conteúdo do arquivo JSON (Passo 4)
[gcp_service_account]
type = "service_account"
project_id = "seu-projeto-123456"
private_key_id = "abc123def456..."
private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQE..."
client_email = "streamlit-app@seu-projeto.iam.gserviceaccount.com"
client_id = "123456789..."
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"
auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
client_x509_cert_url = "https://www.googleapis.com/robot/v1/metadata/x509/..."
universe_domain = "googleapis.com"
```

**Dica:** Abra o arquivo JSON no editor e copie TODO o conteúdo para dentro de `[gcp_service_account]`

4. Salve o arquivo (Ctrl+O, Enter, Ctrl+X no nano)

### Passo 8: Testar a Integração

1. Execute o Streamlit:
   ```bash
   streamlit run app.py
   ```

2. No menu, vá em: **🛠️ Manutenção** → **☁️ Google Sheets**

3. Verifique o **Status da Conexão:**
   - ✅ Credenciais configuradas
   - ✅ Planilha: [ID]...

4. Clique em **🧪 Testar Conexão com Google Sheets**
   - Se sucesso: ✅ Conexão estabelecida!
   - Se erro: Verifique as configurações

5. Clique em **📤 Sincronizar para Google Sheets**
   - Aguarde alguns segundos
   - Se sucesso: ✅ Sincronização concluída!

6. Acesse a planilha no Google Sheets
   - Você verá 5 abas criadas:
     - **Pacientes**
     - **Agendamentos**
     - **Pacotes**
     - **Historico**
     - **Info** (metadados)

## 🔧 Uso Diário

### Fazer Backup (Upload)

1. Vá em **Manutenção** → **Google Sheets**
2. Clique em **📤 Sincronizar para Google Sheets**
3. Aguarde a confirmação
4. Seus dados estão salvos na nuvem!

### Restaurar Dados (Download)

⚠️ **ATENÇÃO:** Isso sobrescreve os dados locais!

1. Vá em **Manutenção** → **Google Sheets**
2. Marque **✅ Confirmo que quero restaurar**
3. Clique em **📥 Restaurar de Google Sheets**
4. Aguarde a confirmação
5. Recarregue a página (F5)

## 📊 Estrutura da Planilha

### Aba: Pacientes
Contém todos os dados dos pacientes cadastrados:
- ID, Nome, CPF, Data de Nascimento, Telefone, Email, Endereço, Observações

### Aba: Agendamentos
Todos os agendamentos do sistema:
- ID, Paciente, Data, Hora, Duração, Serviço, Valor, Desconto, ValorFinal
- Pagamento, Status, Recorrente, TipoAtendimento, Modalidade, Observações

### Aba: Pacotes
Pacotes de sessões:
- ID, Paciente, QtdSessoes, Valor, DataCompra, Validade, Status

### Aba: Historico
Registro de todas as alterações:
- Timestamp, Acao, Detalhes

### Aba: Info
Metadados da sincronização:
- Última Sincronização
- Total Pacientes
- Total Agendamentos
- Total Pacotes

## 🔒 Segurança

### ✅ Boas Práticas

1. **Nunca compartilhe** o arquivo JSON das credenciais
2. **Não commite** o arquivo `secrets.toml` no Git
3. **Adicione** ao `.gitignore`:
   ```
   .streamlit/secrets.toml
   ```
4. **Use permissões mínimas** na planilha
5. **Revise** quem tem acesso à planilha periodicamente

### ⚠️ Se Comprometer as Credenciais

1. Vá no Google Cloud Console
2. **IAM & Admin** → **Service Accounts**
3. Clique na service account comprometida
4. Aba **KEYS**
5. Encontre a chave comprometida
6. Clique nos 3 pontos → **Delete**
7. Crie uma nova chave (Passo 4)
8. Atualize o `secrets.toml`

## 🐛 Solução de Problemas

### Erro: "Credenciais não configuradas"

**Solução:**
- Verifique se o arquivo `.streamlit/secrets.toml` existe
- Confirme que `[gcp_service_account]` está preenchido
- Reinicie o Streamlit

### Erro: "Planilha não encontrada"

**Solução:**
- Verifique o ID da planilha no `secrets.toml`
- Confirme que a planilha foi compartilhada com o `client_email`
- Certifique-se de dar permissão de **Editor** (não Viewer)

### Erro: "Permission denied"

**Solução:**
- A service account precisa de permissão de **Editor**
- Compartilhe novamente a planilha (Passo 6)
- Verifique se o email está correto

### Erro: "API not enabled"

**Solução:**
- Ative a Google Sheets API (Passo 2)
- Ative a Google Drive API (Passo 2)
- Aguarde alguns minutos para propagação

### Sincronização lenta

**Normal para:**
- Primeira sincronização
- Muitos dados (>1000 registros)

**Otimizações:**
- Sincronize durante horários de baixo uso
- Considere sincronizar semanalmente se tiver muitos dados

## 📞 Suporte

### Recursos Oficiais

- [Google Sheets API Docs](https://developers.google.com/sheets/api)
- [gspread Documentation](https://docs.gspread.org/)
- [Service Accounts Guide](https://cloud.google.com/iam/docs/service-accounts)

### Verificar Logs

1. Vá em **Manutenção** → **Logs**
2. Procure por erros relacionados a "Google Sheets"
3. Use os logs para diagnóstico

## 🎉 Pronto!

Sua integração com Google Sheets está configurada!

Seus dados agora têm:
- ✅ Backup automático em nuvem
- ✅ Acesso de qualquer dispositivo
- ✅ Segurança do Google Drive
- ✅ Histórico de alterações

---

**Última atualização:** 2025-12-11
**Versão do Sistema:** 1.2
**Status:** Produção ✅
