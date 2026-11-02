# Log Analysis & Incident Correlation Lab (Python)

## 📌 Visão Geral

Este projeto automatiza a análise e a correlação de logs de um laboratório de
segurança. O script Python investiga eventos de autenticação, tráfego web,
erros da aplicação e ações do firewall para reconstruir atividades legítimas
e suspeitas.

Os arquivos de log foram fornecidos para o laboratório da Red Team Leaders e
representam dados de teste. A análise é feita localmente: o script apenas lê e
exibe linhas que correspondem aos critérios de cada cenário.

## 📂 Estrutura do Repositório

```text
.
├── logs/
│   ├── access.log       # Requisições ao servidor web
│   ├── app_error.log    # Eventos e exceções da aplicação Java/Tomcat
│   ├── auth.log         # Autenticações SSH, PAM e eventos de usuários
│   └── firewall.log     # Eventos de rede e regras UFW
├── scripts/
│   └── analyze_logs.py  # Análise e correlação automatizadas
└── README.md
```

## ▶️ Requisitos e Execução

- Python 3.10 ou superior.
- Não há dependências externas; o script usa apenas a biblioteca padrão.

Na raiz do repositório, execute:

```bash
python3 scripts/analyze_logs.py
```

Opcionalmente, informe um diretório existente que contenha os logs:

```bash
python3 scripts/analyze_logs.py /caminho/para/logs
```

Sem um diretório informado, o script procura `logs/access.log` e, em seguida,
`access.log` no diretório atual. A análise começa quando encontra `access.log`
ou `auth.log`; os demais arquivos são opcionais e seus cenários exibem apenas
os registros disponíveis. Se nenhum dos dois arquivos obrigatórios estiver
presente no diretório selecionado, o programa exibe uma mensagem de erro e
termina com código de saída `1`.

## 🔎 Cenários de Análise

### Cenário 1: sessão do usuário `admin`

**IP associado:** `192.168.1.4`

O script procura em `auth.log` autenticações aceitas que mencionem o usuário
`admin` ou o IP e lista em `access.log` as requisições desse endereço. Nos
dados do laboratório, há um login SSH aceito às 10:01:15 e requisições web para
`/login`, `/cart/add` e `/logout`.

```text
auth.log: Accepted password for user admin from 192.168.1.4
access.log: 192.168.1.4 ... "POST /login HTTP/1.1" 200 ...
```

### Cenário 2: erro HTTP 500 e exceção da aplicação

O script filtra em `access.log` as requisições com status HTTP `500` e, em
`app_error.log`, exibe cada ocorrência de `NullPointerException` com até oito
linhas seguintes de contexto.

Nos dados fornecidos, às 10:07:30 o IP `192.168.1.1` recebeu um erro 500 ao
acessar `/api/v1/user/123`. A aplicação registra que a rota está depreciada e
uma `NullPointerException` em `ApiService.processUserData`, associada a dados
de usuário ausentes.

```text
access.log: 192.168.1.1 ... "GET /api/v1/user/123 HTTP/1.1" 500 ...
app_error.log: API endpoint /api/v1/user/123 is deprecated.
app_error.log: java.lang.NullPointerException: ... "user" is null
```

### Cenário 3: reconhecimento web e tentativas de força bruta

**IP associado:** `10.0.0.6`

- **Reconhecimento web:** três tentativas de acesso a caminhos administrativos
  (`/wp-login.php`, `/administrator/index.php` e `/old-admin/login.aspx`)
  recebem respostas HTTP 404.
- **Autenticação SSH:** são exibidos os eventos associados ao IP; o script
  conta as linhas `Failed password`. Nos logs do laboratório, são cinco
  tentativas malsucedidas para `admin`.
- **Firewall:** são listadas as ações que mencionam o IP. Os registros incluem
  bloqueio de conexão à porta 23, rejeição de tráfego para a porta 22 e um
  bloqueio posterior.

```text
access.log: 10.0.0.6 ... "GET /wp-login.php HTTP/1.1" 404 ...
auth.log: Failed password for user admin from 10.0.0.6 ...
firewall.log: [UFW REJECT] ... SRC=10.0.0.6 ... DPT=22
```

### Cenário 4: atividade suspeita associada a `10.0.0.5`

O script correlaciona ocorrências do endereço em `access.log`, `firewall.log`
e `auth.log`. Nos dados do laboratório, há uma tentativa de acesso a
`/admin/dashboard` que recebe HTTP 403, uma conexão SSH à porta 22 bloqueada
pelo firewall e uma tentativa SSH com o usuário inexistente `visitor`.

```text
access.log: 10.0.0.5 ... "GET /admin/dashboard HTTP/1.1" 403 ...
firewall.log: [UFW BLOCK] ... SRC=10.0.0.5 ... DPT=22
auth.log: Failed password for invalid user visitor from 10.0.0.5 ...
```

## 📊 Resumo dos Indicadores

| Endereço IP | Evidências observadas | Resultado nos logs |
|---|---|---|
| `192.168.1.4` | Login SSH aceito e requisições web | Acesso autorizado |
| `192.168.1.1` | Requisição a `/api/v1/user/123` | HTTP 500 e exceção na aplicação |
| `10.0.0.6` | Varredura de caminhos web e falhas SSH | 404, cinco senhas incorretas e eventos UFW |
| `10.0.0.5` | Acesso ao painel, tentativa SSH e bloqueio no firewall | HTTP 403, usuário inválido e UFW BLOCK |

## ⚠️ Observações

- Os indicadores e conclusões acima descrevem os registros deste laboratório;
  não representam necessariamente atividade em um ambiente real.
- A ferramenta faz correspondência textual dos endereços e eventos definidos
  no script. Ela não substitui uma investigação manual nem valida a ordem
  temporal entre registros de formatos diferentes.
- As cores da saída usam sequências ANSI; em terminais que não as suportem,
  essas sequências podem aparecer como caracteres.
