# Guia de Execução - Assessment Zabbix

> Documentação técnica de execução e troubleshooting para a equipe de infraestrutura.
> Script: [zabbix_assessment.py](zabbix_assessment.py) · Compatível com Zabbix **5.0 a 7.x** · Python **3.8+**

---

## 1. Objetivo

Ferramenta de **assessment somente leitura** de um ambiente Zabbix. Ela se conecta à API (JSON-RPC), levanta o que existe no ambiente, compara com boas práticas de observabilidade/SRE e gera relatórios para engenharia e liderança.

A avaliação é organizada em **5 pilares** e 18 domínios:

| Pilar | Domínios avaliados |
|---|---|
| Confiabilidade da plataforma | Versões & ciclo de vida · Alta disponibilidade · Capacidade & desempenho · Retenção & housekeeping |
| Cobertura de monitoramento | Hosts & disponibilidade · Templates & padronização · Coleta (itens & LLD) · Sintético & serviços de negócio |
| Qualidade de alertas | Triggers & severidade · Ruído & flapping · Problemas em aberto |
| Resposta e operação | Notificações & escalonamento · Integrações (ITSM/on-call) · Manutenção & supressão · Tempo de resposta |
| Segurança e governança | Identidade & acesso · Criptografia & segredos · Auditoria |

### Garantia de somente leitura

- Toda chamada passa por um filtro no próprio script que **só permite métodos `*.get`**, além de `apiinfo.version`, `user.login` e `user.logout`. Qualquer outro método é bloqueado **antes** de sair da máquina (`PermissionError`).
- Recomenda-se reforçar isso no lado do Zabbix com uma role restrita (seção 3).
- O script **não altera nada** no Zabbix, nem grava arquivos fora da pasta de saída.

---

## 2. Pré-requisitos

| Item | Detalhe |
|---|---|
| Python | 3.8 ou superior (`python3 --version` / `py --version`) |
| Bibliotecas para a coleta | **Nenhuma** — usa só a biblioteca padrão. Roda em jump server sem internet/pip. |
| Bibliotecas opcionais (PDF/PPTX) | `pip install --user reportlab python-pptx`. Sem elas, PDF e PPTX são **pulados** (o restante é gerado normalmente). |
| Rede | Acesso HTTPS da máquina de execução até o frontend do Zabbix (`/api_jsonrpc.php`). Normalmente via jump server ou VPN. |
| Credencial | API token (recomendado, Zabbix 5.4+) **ou** usuário/senha. |

---

## 3. Preparação da credencial no Zabbix (feita pelo administrador do cliente)

### Role recomendada: `Assessment-ReadOnly` (Zabbix 5.2+)

| Configuração | Valor |
|---|---|
| User type | **Super admin** (necessário para ler usuários, tokens, housekeeping, autenticação e HA) |
| UI elements | Todos **desmarcados** |
| Actions | Todas **desmarcadas** |
| API access | **Enabled** |
| API methods | **Allow list** → `*.get` (+ `user.login` e `user.logout` se for usar usuário/senha) |

- Colocar o usuário em um **grupo com Frontend access = Disabled** (acesso só via API).
- Gerar um **API token** para esse usuário (5.4+), **com data de expiração** curta (ex.: fim do projeto).

> Com role **Admin** ou **User** o assessment roda, mas os coletores restritos (usuários, tokens, housekeeping, autenticação, HA) aparecem como **"parcial"** no apêndice do relatório e os controles dependentes ficam **N/A** (não penalizam o score, mas reduzem a cobertura da análise).

---

## 4. Execução

Pré-requisito: credencial criada (seção 3) e acesso HTTPS ao Zabbix a partir da máquina de execução.
No Windows, troque `python3 zabbix_assessment.py` por `py .\zabbix_assessment.py`.

### Passo 1 — Definir URL e token (só na sessão atual)

**Linux (bash)**
```bash
export ZBX_URL='https://zabbix.interno/'
read -rsp 'API token: ' ZBX_TOKEN && export ZBX_TOKEN
```

**Windows (PowerShell 5.1 ou 7+)**
```powershell
$env:ZBX_URL = 'https://zabbix.interno/'
$env:ZBX_TOKEN = [pscredential]::new('t', (Read-Host 'API token' -AsSecureString)).GetNetworkCredential().Password
```

> ⚠️ Nunca digite o token direto no comando: ele fica gravado no histórico do shell. O que é digitado no prompt não é gravado.

Sem token? Use `ZBX_USER='svc_assessment'` no lugar de `ZBX_TOKEN`; o script pede a senha.

### Passo 2 — Testar conexão e permissões

```bash
python3 zabbix_assessment.py --test
```

| Resultado | Significado |
|---|---|
| `OK` | Método acessível. |
| `n/a (requer X.Y+)` | Método não existe nessa versão do Zabbix. Normal. |
| `NEGADO` | Falta permissão. Ajustar a role (seção 3) antes de seguir. |

### Passo 3 — Executar

```bash
python3 zabbix_assessment.py --customer "Cliente X" --env-name "Produção" --days 30
```

Ao final o script exibe o score e a pasta de saída (`zabbix-assessment-AAAAMMDD-HHMM`). Abra o `relatorio.html`.

### Passo 4 — Limpar

```bash
unset ZBX_TOKEN ZBX_USER ZBX_PASSWORD ZBX_URL                                    # Linux
Remove-Item Env:ZBX_* -ErrorAction SilentlyContinue                              # Windows
```

Copie a pasta de saída por canal aprovado e apague-a da máquina de execução.

### Opções frequentes

| Situação | Adicionar ao comando |
|---|---|
| Certificado interno / self-signed | `--ca-bundle ca.pem` (ou `--insecure`) |
| Proxy corporativo bloqueando o acesso | `--no-proxy` |
| Máquina sem `reportlab` / `python-pptx` | `--formats none` |
| Avaliar só alguns host groups | `--groups "Linux*,Windows servers"` |
| Ambiente grande / timeouts | `--timeout 300 --threads 2` |

### Gerar PDF/PPTX em outra máquina

Se a coleta foi feita com `--formats none`, copie o `dados.json` para uma máquina com `pip install --user reportlab python-pptx` e rode:

```bash
python3 zabbix_assessment.py --render-only ./zabbix-assessment-AAAAMMDD-HHMM/dados.json --customer "Cliente X"
```

Não conecta no Zabbix; regera todos os relatórios na pasta do JSON.

---

## 5. Referência de parâmetros

| Parâmetro | Variável de ambiente | Padrão | Descrição |
|---|---|---|---|
| `--url` | `ZBX_URL` | — | URL do frontend ou do `api_jsonrpc.php`. Obrigatório (exceto `--render-only`). |
| `--token` | `ZBX_TOKEN` | — | API token. Prefira a variável de ambiente. |
| `--user` | `ZBX_USER` | — | Usuário; senha via `ZBX_PASSWORD` ou prompt. Usado só se não houver token. |
| `--ca-bundle` | `ZBX_CA_BUNDLE` | — | Arquivo PEM da CA interna. |
| `--insecure` | — | desligado | Não valida o certificado TLS. |
| `--no-proxy` | — | desligado | Ignora `HTTP(S)_PROXY` do ambiente. |
| `--timeout` | — | `180` | Timeout por chamada à API (segundos). |
| `--customer` | — | `Assaí Atacadista` | Nome do cliente exibido nos relatórios. **Sempre informar.** |
| `--env-name` | — | `Produção` | Nome do ambiente exibido nos relatórios. |
| `--groups` | — | todos | Host groups separados por vírgula; aceita curingas (`*`, `?`), sem diferenciar maiúsculas. |
| `--days` | — | `30` | Janela de eventos e notificações (1 a 365). |
| `--max-events-per-day` | — | `20000` | Limite de eventos coletados por dia. |
| `--expected-integrations` | — | vazio | Integrações que o cliente diz ter (ex.: `servicenow,teams`); vira um check por item. |
| `--threads` | — | `4` | Chamadas paralelas à API. Aumente com cautela (carga no frontend/banco). |
| `--out` | — | `zabbix-assessment-AAAAMMDD-HHMM` | Pasta de saída. |
| `--formats` | — | `pdf,pptx` | Saídas extras: `pdf`, `pptx` ou `none`. HTML/CSV/JSON são sempre gerados. |
| `--test` | — | — | Só testa conexão e permissões e sai. |
| `--render-only` | — | — | Caminho de um `dados.json`; regera os relatórios sem conectar no Zabbix. |

---

## 6. Arquivos gerados

Todos na pasta de saída (padrão `./zabbix-assessment-AAAAMMDD-HHMM/`). CSVs usam `;` como separador e UTF-8 com BOM (abrem direto no Excel em pt-BR).

| Arquivo | Público | Conteúdo |
|---|---|---|
| `relatorio.html` | Stakeholders | Relatório completo: score global e por pilar, achados, inventário, apêndice de coleta. |
| `relatorio_executivo.pdf` | Liderança | Resumo executivo (requer `reportlab`). |
| `relatorio_tecnico.pdf` | Engenharia | Detalhamento técnico, A4 paisagem (requer `reportlab`). |
| `apresentacao_stakeholders.pptx` | Reunião de apresentação | 16:9, gráficos nativos editáveis e notas do apresentador (requer `python-pptx`). |
| `achados.csv` | Backlog | Lacunas por pilar, ordenadas por prioridade, com evidência, impacto e recomendação. |
| `cobertura_hosts.csv` | Engenharia | Host × disponibilidade, templates, itens, triggers, tags, TLS, versão do agente, erro de interface. |
| `cobertura_grupos.csv` | Engenharia | Host group × cobertura (monitorados, disponíveis, com template/trigger/tag/TLS). |
| `top_triggers.csv` | Engenharia | Triggers que mais dispararam na janela, com MTTR/MTTA medianos e flag de flapping. |
| `higiene_otimizacao.csv` | Engenharia | Itens não suportados, intervalos agressivos, hosts/templates órfãos, com NVPS antes/depois da ação. |
| `dados.json` | Interno | Dados brutos + checks, scores por domínio/pilar e score global. Base para `--render-only`. |

> ⚠️ **Os arquivos são confidenciais.** Contêm nomes de hosts, host groups, usuários, nomes de macros, erros de coleta e topologia do cliente. Tratar conforme a política de dados do cliente: não enviar por canais não aprovados, não anexar em tickets públicos e apagar do jump server após a cópia.

---

## 7. Como ler o resultado

### Score

- Cada controle (check) tem prioridade **Alta (peso 3)**, **Média (peso 2)** ou **Baixa (peso 1)**.
- Score = soma dos pesos dos controles atendidos ÷ soma dos pesos avaliados × 100. Calculado por domínio, por pilar e global.
- Controles **N/A** (versão não suporta, coletor sem permissão, sem dados suficientes) **não entram** no cálculo.

| Score | Nível de maturidade |
|---|---|
| < 40 | Inicial |
| 40 – 64 | Em desenvolvimento |
| 65 – 84 | Estruturado |
| ≥ 85 | Otimizado |

### Apêndice de coleta (status por coletor)

| Status | Significado | Ação |
|---|---|---|
| `ok` | Coletado normalmente. | — |
| `n/a (requer X.Y+)` | Recurso não existe na versão do cliente. | Nenhuma; é esperado. |
| `parcial: API ...` | A API negou ou retornou erro em parte das chamadas. | Ver permissões da role (seção 3) e rodar `--test`. |
| `parcial: erro ...` | Erro de rede/timeout em parte das chamadas. | Aumentar `--timeout`, reduzir `--threads`, repetir. |

Um coletor com falha **não derruba** o assessment: ele é registrado como parcial e o restante continua.

### Pontos de atenção na interpretação

- **Eventos truncados:** se algum dia atingir `--max-events-per-day`, os números de ruído/MTTR/MTTA são uma amostra. Para ambientes muito ruidosos, aumente o limite ou reduza `--days`.
- **`--groups`:** com filtro, problemas e eventos também ficam restritos aos hosts do escopo; controles globais (usuários, autenticação, housekeeping, HA) continuam refletindo o ambiente inteiro.
- **NVPS estimado:** calculado a partir dos intervalos dos itens (`1/intervalo`); itens trapper, SNMP trap, dependentes e com intervalo via macro/flexível não entram na estimativa. O valor real vem do self-monitoring (`zabbix[wcache,values]`), quando disponível.
- **Ciclo de vida da versão:** a tabela de suporte está embutida no script (constante `SUPPORT`). Revisar quando a Zabbix publicar novas datas/versões.

---

## 8. Troubleshooting

| Mensagem | Causa provável | Solução |
|---|---|---|
| `informe --url ou ZBX_URL` | URL não definida. | Exportar `ZBX_URL` ou passar `--url`. |
| `informe ZBX_TOKEN (recomendado) ou ZBX_USER` | Nenhuma credencial definida. | Exportar `ZBX_TOKEN` (ou `ZBX_USER`). Refazer o Passo 1 na mesma janela do terminal. |
| `Erro TLS: ... Use --ca-bundle <ca.pem> ou --insecure.` | Certificado de CA interna/self-signed. | Pedir o PEM da CA ao cliente e usar `--ca-bundle`; em último caso `--insecure`. |
| `Sem conexão com ...: <motivo>` | VPN, rota, DNS, firewall ou proxy. | Testar a porta: `curl -k <URL>/api_jsonrpc.php` (Linux) ou `Test-NetConnection zabbix.interno -Port 443` (Windows). Se houver `HTTPS_PROXY` no ambiente, usar `--no-proxy`. |
| `Falha de autenticação/API: ...` | Usuário/senha errados, usuário bloqueado, API desabilitada. | Validar credencial com o administrador do cliente. |
| `Credencial recusada pelo Zabbix (...)` | Token inválido/expirado/desabilitado, ou role sem API access. | Gerar novo token; conferir *API access = Enabled* e allow list `*.get` na role. |
| `--groups não encontrou host groups para: ...` | Nenhum host group casou com o padrão. | Conferir nomes no frontend; usar curinga (`"Linux*"`). |
| `--formats inválido: ...` | Valor diferente de `pdf`, `pptx`, `none`. | Corrigir o parâmetro. |
| `... não gerado: módulo 'reportlab' ausente` (ou `pptx`) | Biblioteca opcional não instalada. | `pip install --user reportlab python-pptx` ou usar `--render-only` em outra máquina. |
| `método '...' bloqueado: assessment somente leitura` | Proteção read-only acionada (não deve ocorrer em uso normal). | Reportar ao mantenedor do script com o log completo. |
| Execução muito lenta / timeouts | Ambiente grande, frontend ou banco sob carga. | `--timeout 300`, `--threads 2`, reduzir `--days`, ou limitar por `--groups`. Preferir horário de menor carga. |
| Self-monitoring "não encontrado" no relatório | Host do server sem template *Zabbix server health*, ou itens internos sem dados há mais de 1h. | É um achado legítimo; confirmar com o cliente se o template está vinculado. |

Erros HTTP 429/5xx e falhas de rede transitórias são **repetidos automaticamente** (até 4 tentativas com espera de 1s, 2s e 4s) antes de serem registrados.

---

## 9. Checklist de execução

**Antes**
- [ ] Credencial criada com a role `Assessment-ReadOnly` e token com expiração.
- [ ] Janela de execução combinada com o cliente (preferir horário de menor carga).
- [ ] Python 3.8+ disponível na máquina de execução.
- [ ] `--test` executado sem métodos essenciais `NEGADO`.

**Durante**
- [ ] Rodar com `--customer` e `--env-name` corretos.
- [ ] Acompanhar o log; anotar avisos de timeout/erro.

**Depois**
- [ ] Conferir no `relatorio.html` o apêndice de coleta (coletores `parcial`).
- [ ] Gerar PDF/PPTX (direto ou via `--render-only`).
- [ ] Copiar a pasta de saída por canal aprovado e **apagar do jump server**.
- [ ] Solicitar ao cliente a **revogação do token** e a desativação do usuário de assessment.
- [ ] Limpar variáveis de ambiente da sessão (Passo 4).
