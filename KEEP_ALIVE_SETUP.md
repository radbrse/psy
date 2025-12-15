# 🤖 Sistema Keep-Alive - Configuração

Sistema automático para manter sua aplicação Streamlit sempre ativa usando GitHub Actions.

## 📋 O que é o Keep-Alive?

O Keep-Alive é um "robô vigilante" que acessa sua aplicação Streamlit periodicamente para evitar que ela entre em modo "sleep" (hibernação) em plataformas de hospedagem gratuitas.

### Como funciona:
- 🤖 **Robô automático** roda a cada 14 minutos
- 🌐 Faz ping na sua aplicação Streamlit
- ✅ Mantém app sempre ativo e pronto
- 📊 Registra logs de cada execução

---

## 🚀 Configuração (Passo a Passo)

### **Passo 1: Fazer Deploy da Aplicação Streamlit**

Primeiro, você precisa ter sua aplicação rodando em algum serviço de hospedagem. Opções recomendadas:

**Streamlit Cloud (Recomendado - Grátis):**
1. Acesse: https://streamlit.io/cloud
2. Faça login com sua conta GitHub
3. Clique em "New app"
4. Selecione seu repositório: `radbrse/psy`
5. Branch: `main` (ou sua branch principal)
6. Main file path: `app.py`
7. Clique em "Deploy"

Sua aplicação ficará disponível em uma URL como:
```
https://radbrse-psy-app-abc123.streamlit.app
```

**COPIE ESSA URL!** Você vai precisar dela no próximo passo.

---

### **Passo 2: Configurar GitHub Secret**

Agora você precisa configurar a URL da sua aplicação no GitHub:

1. **Acesse seu repositório no GitHub:**
   - https://github.com/radbrse/psy

2. **Vá em Settings (Configurações):**
   - Clique na aba "Settings" no topo do repositório

3. **Secrets and variables → Actions:**
   - No menu lateral esquerdo, clique em "Secrets and variables"
   - Depois clique em "Actions"

4. **Criar novo secret:**
   - Clique no botão verde "New repository secret"

5. **Preencher os dados:**
   - **Name:** `STREAMLIT_APP_URL`
   - **Secret:** Cole a URL completa da sua aplicação
     - Exemplo: `https://radbrse-psy-app-abc123.streamlit.app`
   - Clique em "Add secret"

✅ **Pronto!** O secret está configurado.

---

### **Passo 3: Habilitar GitHub Actions**

1. **Acesse a aba Actions:**
   - No seu repositório, clique em "Actions" no topo

2. **Habilitar workflows:**
   - Se aparecer uma mensagem pedindo para habilitar Actions, clique em "I understand my workflows, go ahead and enable them"

3. **Verificar workflow Keep-Alive:**
   - Você deverá ver o workflow "Keep Streamlit App Alive" na lista

---

### **Passo 4: Executar Manualmente (Teste)**

Antes de deixar rodar automaticamente, vamos testar:

1. **Acesse Actions → Keep Streamlit App Alive**

2. **Executar manualmente:**
   - Clique em "Run workflow" (botão cinza à direita)
   - Selecione a branch `main`
   - Clique em "Run workflow" (botão verde)

3. **Acompanhar execução:**
   - Clique na execução que acabou de aparecer
   - Clique em "keep-alive" para ver os logs
   - Aguarde alguns segundos

4. **Resultado esperado:**
   ```
   ✅ Keep-alive executado com sucesso
   🌐 URL: https://radbrse-psy-app-abc123.streamlit.app
   ✅ Status Code: 200
   ✅ Aplicação está ATIVA e RESPONDENDO!
   ```

---

## 🔄 Funcionamento Automático

Após a configuração, o sistema roda automaticamente:

### **Agendamento:**
- ⏰ **A cada 14 minutos** (24 horas por dia)
- 📅 **Todos os dias** (incluindo fins de semana)
- 🔁 **Aproximadamente 100 execuções por dia**

### **Execuções:**
- 🟢 **Scheduled** = Execução automática (robô)
- 🔵 **Manually run** = Execução manual (você)

### **Plano Gratuito - Limitações:**
⚠️ **Importante:** No plano gratuito do GitHub Actions:
- Execuções podem atrasar 30-60 minutos
- Alguns horários podem ser "pulados"
- Prioridade para clientes pagantes

**Isso é normal!** O robô continua funcionando, apenas com atrasos ocasionais.

---

## 📊 Monitoramento

### **Ver histórico de execuções:**
1. Acesse: Actions → Keep Streamlit App Alive
2. Veja a lista de execuções:
   - ✅ Verde = Sucesso
   - ❌ Vermelho = Falha
   - 🟡 Amarelo = Em execução

### **Ver logs detalhados:**
1. Clique em uma execução
2. Clique em "keep-alive"
3. Expanda "Ping Streamlit App"
4. Veja informações detalhadas:
   - URL acessada
   - Status code
   - Tempo de resposta
   - Mensagens de erro (se houver)

---

## 🔧 Ajustes e Personalização

### **Mudar intervalo de execução:**

Edite o arquivo `.github/workflows/keep-alive.yml`:

```yaml
schedule:
  # A cada 14 minutos (atual)
  - cron: '*/14 * * * *'

  # A cada 10 minutos (mais frequente)
  - cron: '*/10 * * * *'

  # A cada 30 minutos (menos frequente)
  - cron: '*/30 * * * *'
```

### **Desabilitar temporariamente:**

Adicione `#` na frente das linhas de schedule:

```yaml
schedule:
  # - cron: '*/14 * * * *'  # DESABILITADO
```

---

## ❓ Troubleshooting (Solução de Problemas)

### **Erro: "URL não configurada"**
**Solução:**
- Verifique se criou o secret `STREAMLIT_APP_URL`
- Confira se o nome está EXATAMENTE como indicado (case-sensitive)

### **Erro: "Status Code: 404"**
**Solução:**
- Verifique se a URL da aplicação está correta
- Teste abrindo a URL no navegador
- Pode ser que a aplicação ainda esteja fazendo deploy

### **Erro: "Timeout"**
**Solução:**
- Normal em primeira execução
- Streamlit demora ~30s para "acordar" quando está dormindo
- Aguarde próxima execução automática

### **Nenhuma execução automática acontecendo**
**Solução:**
1. Verifique se Actions estão habilitadas (Settings → Actions)
2. Verifique se o arquivo `.github/workflows/keep-alive.yml` existe
3. Aguarde até 20-30 minutos (atraso do plano gratuito)

---

## 📈 Status e Estatísticas

Com o Keep-Alive ativo, sua aplicação terá:
- 🟢 **Uptime:** ~95-99% (depende do plano GitHub)
- ⚡ **Response time:** 1-3 segundos (app já acordado)
- 🔄 **Execuções/dia:** ~100 (1 a cada 14 min)
- 💰 **Custo:** $0 (plano gratuito)

---

## 🎯 Próximos Passos

Após configurar o Keep-Alive:

1. ✅ Aguarde 15-20 minutos
2. ✅ Verifique primeiras execuções automáticas
3. ✅ Confirme que aparecem como "Scheduled"
4. ✅ Teste acessar sua aplicação (deve estar sempre rápida)

**Tudo certo?** Seu robô vigilante está funcionando! 🎉

---

## 📚 Recursos Adicionais

- 📖 [Documentação GitHub Actions](https://docs.github.com/en/actions)
- 🚀 [Streamlit Cloud Docs](https://docs.streamlit.io/streamlit-community-cloud)
- 🤖 [Cron Expression Guide](https://crontab.guru/)

---

**Desenvolvido para Sistema Psi - Psi. Radamés Soares**
CRP 19/5223
