# Origami

> *Origami is an adaptive content discovery engine that folds its strategy around the target's behavior, technology and response patterns.*

Evolução do ffuf/dirb: em vez de bruteforce cego, o Origami **calibra antes de atacar**, faz **fingerprint aditivo** (não segmenta o ataque, só dá insumo) e **dobra** a estratégia conforme padrões de tecnologia aparecem — por header, cookie, resposta, pasta ou arquivo. Cada achado vira evidência que repondera os módulos e expande a wordlist em tempo real. Com o tempo, aprende entre alvos.

Uso pretendido:

```bash
origami http://www.exemplo.com.br
```

---

## Decisões travadas

| Decisão | Escolha |
|---|---|
| Linguagem | **Python 3.11+** (`asyncio` + `httpx`), com fronteira limpa engine/cérebro pra reescrever só o engine depois se precisar |
| Detecção | **Híbrida, em ordem:** MVP arranca com **overlay próprio curado** (~10-15 techs à mão) pra não atrasar o motor; **ingestão multi-fonte** (Wappalyzer fork `tunetheweb`, nuclei tech-templates, catálogo de 404-pages do 0xdf, favicon-hash DBs) entra no **v2**. Overlay sempre precede a camada ingerida e recebe o write-back do aprendizado |
| Estratégia ML | **Faseada (algoritmo → memória → modelo treinado)** — v1 só algoritmos (simhash/regras, zero modelo treinado); v2 memória cross-target (k-NN + association mining); v3 modelo treinado **só quando houver dado** (FP-classifier, n-gram, bandit sob budget). Detalhe na §3.8 |
| Shortscan | **Auto-disparo *gated*** (IIS confirmado **E** tilde vaza na calibração) + flags `--shortscan`/`--no-shortscan`; invoca o binário Go já instalado em `~/go/bin/shortscan` |
| Teste/avaliação | **Harness local no MVP** (servidor fake: IIS soft-404, wildcard, 404 custom, rate-limit) + métrica norte **hits/request vs ffuf**. Servers de teste online do usuário pra validação/treino posterior |
| Escopo do MVP | **Núcleo adaptativo enxuto** — calibração por contexto + fingerprint + evidence bus + scheduler com prioridade + classificador de FP + módulos IIS/PHP + ingestão de catálogo + SQLite + saída JSON |

---

## 1. Princípios de design

1. **Calibrar antes de atacar.** Nada de ataque sem confirmar o canal. Baseline mede o comportamento real de 404/403/401/500 e só então o scan começa.
2. **Fingerprint aditivo e por prefixo de path.** A web real é legado + proxy + múltiplos apps no mesmo host. `/api/` pode ser Node e `/portal/` ASP clássico. Fingerprint enriquece, não segmenta, e é mantido **por prefixo**.
3. **Barramento de evidências.** Header, cookie, shortscan, JS, robots, sitemap, favicon, git leak — tudo vira `Evidence{source, evidence, confidence}` e alimenta o motor de decisão.
4. **Interpretabilidade > caixa-preta.** A maior parte da "adaptação" é regra determinística externalizada em YAML (estilo nuclei), não ML. ML entra só onde regra não resolve, e sempre justificável num relatório.
5. **Fronteira limpa engine ↔ cérebro.** Engine = worker pool de request rápido. Cérebro = orquestração + decisão + aprendizado. Trocam mensagens. Se throughput virar gargalo, reescreve só o engine (Go/Rust) sem tocar no cérebro.
6. **Não inventar assinatura — ingerir catálogo mantido.** Fingerprint de tech, páginas 404 e favicon hashes vêm de fontes comunitárias atualizáveis (Wappalyzer fork, nuclei, 0xdf-404, FingerprintHub). O KB do Origami = baseline ingerido **+** overlay próprio. Troca manutenção eterna por `git pull` no upstream, e o overlay é onde o conhecimento acumulado (inclusive cross-target) é escrito.

## 2. Arquitetura

```
                 ┌──────────────────────────── CÉREBRO (brain) ─────────────────────────┐
                 │                                                                       │
  calibração ──▶ │  TargetProfile  ◀── EvidenceBus ◀── Fingerprint                       │
   (baseline)    │       │                  ▲                                            │
                 │       ▼                  │                                            │
                 │  KnowledgeBase(YAML) ─▶ Scheduler(priority queue) ─▶ batch priorizado │
                 │       ▲                                              │                 │
                 │   Memory(SQLite)  ◀───────── feedback ──────────────┤                 │
                 └───────┼──────────────────────────────────────────────┼───────────────┘
                         │                                              ▼
                 ┌───────┴────────────────── ENGINE (request) ──────────────────────────┐
                 │  worker pool (asyncio+httpx) ─▶ ResponseClassifier ─▶ hits/FP         │
                 └───────────────────────────────────────────────────────────────────────┘
```

**Pipeline:** `calibração → TargetProfile` → `cérebro consulta KB + memória e emite batch priorizado` → `engine dispara e classifica` → `hit confirmado atualiza profile + dispara regras de fold` → `corpus atualizado alimenta runs futuros`.

## 3. Componentes

### 3.1 Baseline / Calibração (`core/baseline.py`)
O coração. Constrói um **perfil de não-existência por contexto** (por diretório e por classe de extensão), não um número global — soft-404 varia por pasta e por extensão.
- Dispara probes garantidamente inexistentes com perfis distintos: random puro, random + extensão de cada classe a testar, path profundo, path com caractere especial.
- Compara em múltiplas dimensões: status, content-length, word/line count, content-type, redirect target e **simhash do corpo normalizado** (remove CSRF token, nonce, timestamp — coisas dinâmicas que quebram comparação por length pura).
- Detecta **wildcard routing** e **case-sensitivity** do path (case-insensitive já é sinal forte de Windows/IIS).

**Prior art (não reinventar):** a calibração incorpora a lógica de autocalibração do **ffuf `-ac/-acc`** (cluster de respostas de wildcard), do **feroxbuster** e do **gobuster**. O Origami estende isso pra **perfil por contexto** (por diretório + classe de extensão) em vez de um filtro global — que é justamente a fraqueza dessas ferramentas.

### 3.2 Fingerprint (`core/fingerprint.py`)
Aditivo, com peso de confiança, **por prefixo de path**. Os sinais **não são escritos à mão** — vêm da ingestão de catálogos (Wappalyzer/nuclei/WhatWeb; ver §3.9). Sinais:
- **Headers:** `Server`, `X-Powered-By`, ordering/casing, versão HTTP.
- **Cookies:** `ASP.NET_SessionId`, `.AspNetCore`, `JSESSIONID`, `PHPSESSID`, `laravel_session`, `ci_session`, `connect.sid`.
- **Error pages forçados:** força 400/403/404/500 e fingerprinta o corpo. Base: o **catálogo de páginas 404 default do 0xdf** (<https://0xdf.gitlab.io/cheatsheets/404>) — mapeia corpo de erro default → stack (nginx, Apache, IIS, Flask, Django, FastAPI, Gin/Fiber, PHP-FPM, Laravel, Symfony, Express, Next.js, Tomcat, Spring Boot, Jetty, Rails, Sinatra, ASP.NET, Blazor). É um *catálogo de fingerprint por página de erro*, não um guia de soft-404.
- **Favicon hash (mmh3):** um dos sinais mais fortes e subutilizados — mapeia produto inteiro. Base: FingerprintHub e DBs de favicon hash.
- **Comportamento de extensão:** pede `/x.asp` vs `/x.php` e vê qual é *handled* vs servido como estático.
- **Descoberta passiva:** robots.txt, sitemap.xml.
- (futuro) JARM/TLS na camada de transporte.

### 3.3 Evidence Bus + TargetProfile (`core/evidence.py`)
Tudo vira evidência tipada e o profile é o estado persistente do alvo (também é a fonte do aprendizado cross-target). **No MVP o "bus" é simples:** uma lista com score + uma função reducer que repondera `tech_scores` — sem pub/sub nem fila de mensagens.

```python
@dataclass
class Evidence:
    source: str        # "header" | "cookie" | "shortscan" | "js" | "favicon" | ...
    evidence: str      # "header_server_iis"
    confidence: float  # 0.0–1.0
    path_prefix: str = "/"

@dataclass
class TargetProfile:
    host: str
    tech_scores: dict[str, float]          # {"asp.net": 0.85, "iis": 0.9}
    baseline: dict[str, ContextBaseline]   # por prefixo+classe de extensão
    case_sensitive: bool
    wildcard: bool
    enabled_extensions: set[str]
    findings: list[Finding]
    evidence: list[Evidence]
    fingerprint_vector: list[float]        # pro k-NN cross-target (v2)
```

### 3.4 Knowledge Base (`brain/rules.yaml`)
Regras externalizadas, extensíveis sem mexer em código. `tech → sinais → extensões/wordlists/paths/folds`.

```yaml
- tech: iis
  signals:
    - {type: header, match: "Server: Microsoft-IIS", weight: 50}
    - {type: cookie, match: "ASP.NET_SessionId", weight: 80}
    - {type: case_insensitive_path, weight: 30}
  on_confirm:
    extensions: [.aspx, .asmx, .ashx, .asp, .dll, .config, .svc, .asax, .ascx]
    wordlist: iis.txt
    priority_paths: [web.config, trace.axd, elmah.axd, /bin/, App_Data/, /_vti_bin/, WebResource.axd, ScriptResource.axd]
    folds: [shortscan]            # gated: só dispara se tilde vazar

- tech: php
  signals:
    - {type: header, match: "X-Powered-By: PHP", weight: 60}
    - {type: cookie, match: "PHPSESSID", weight: 80}
  on_confirm:
    extensions: [.php, .php3, .php5, .phtml, .inc, .bak, .old]
    wordlist: php.txt
    priority_paths: [.env, composer.json, vendor/, info.php, phpinfo.php]
```

### 3.5 Scheduler (`core/scheduler.py`)
Fila de prioridade. Combina evidências e emite batches:
```
ASP.NET + ADMIN~1 + api/v1  →
  P1: /admin/, /admin/login.aspx, /admin/users.aspx     (derivado de evidência forte)
  P2: /administrator/, /adminportal/                     (variações)
  P3: wordlist genérica                                  (fallback)
```
Candidato derivado de shortscan/JS tem prioridade máxima (prob. de hit muito maior que palpite de wordlist).

### 3.6 Response Classifier (`core/response_classifier.py`)
Decide hit real vs soft-404. v1 = threshold calibrado de distância simhash ao baseline do contexto + status + word count + content-type + timing. v3 = modelo leve (logistic regression / gradient boosting) sobre essas features. Aprende a reconhecer: 404 fake, login, redirect, blocked, forbidden, directory listing, API error.

### 3.7 Módulos de fold (`modules/`)
Disparados por evidência/calibração. Cada um **emite seeds de alta confiança**, não compete com o brute.
- **tech/iis, tech/php, tech/apache, tech/tomcat, tech/laravel, …** — pacote de extensões/paths seguros de discovery por stack.
- **discovery/shortname.py** — ver §4.
- **discovery/js_parser.py** — extrai endpoints/rotas/versões de JS e joga no queue.
- **discovery/backups.py** — `.git/`, `.svn/`, `.DS_Store`, `.swp`, `~`, `.bak`, `.old`; folda agressivo gerando variações dos nomes já descobertos.
- **discovery/api_discovery.py** — Swagger/OpenAPI, introspection GraphQL, `Accept: application/json`, métodos variados; extrapolação de nome (`getUserById` → `getOrderById`).
- **discovery/robots.py, sitemap.py.**
- **Path mutation / recursive context:** achou `/admin/login.aspx` → testa `default.aspx`, `web.config`, `bin/`, `login_old.aspx` e recursa em `/admin/`.
- **WAF-adapt (v2):** 429/403-com-assinatura/captcha → desacelera, jitter, rotaciona UA/header.

### 3.8 Memory / aprendizado (`brain/memory.py` + `memory.sqlite`)

> *O diferencial não é treinar um modelo — é **memória + recuperação + estatística**.* Por isso a separação honesta abaixo: algoritmos baratos e interpretáveis entram cedo; modelo treinado só quando já houver dado rotulado pra justificá-lo.

**Algoritmos que entram (cedo, interpretáveis):**
- **simhash/cluster** pra soft-404 (já no v1, alimenta o classifier).
- **constraint-filter** pro shortname Regime 1 (já no v1; ver §4).
- **k-NN sobre o fingerprint** (v2) — corpus `(fingerprint do alvo → paths que existiam)`; "os N alvos mais parecidos tinham esses paths, prioriza". É RAG pra fuzzing, **o "melhora a cada run"**, e é algorítmico, não treinado.
- **association mining (FP-growth, `mlxtend`)** (v2) — "quando existe `/backup/`, existe `.git/` com prob X".
- **n-gram/Markov** pra reconstruir nome truncado do shortscan Regime 2 (v2/v3).

**Modelo treinado (adiado até ter dado):**
- **FP-classifier (logistic/GBM)** sobre as features do §3.6 — só depois que v1/v2 já rotularam hits/soft-404.
- **contextual bandit (Thompson sampling)** — **só importa sob budget apertado** (WAF/rate-limit); sem isso testa-se tudo e ranking é irrelevante. Otimiza **hits por request**.
- **LLM / rede neural no loop quente: não** — latência, custo, paths alucinados.

**Host personality / replay:** perfil local reutilizável; roda de novo com conhecimento acumulado.

### 3.9 Knowledge Base: ingestão + overlay (`brain/ingest/`, `brain/rules.yaml`, `brain/overlay.yaml`)
O KB tem **duas camadas**:
- **Camada ingerida (upstream):** adapters em `brain/ingest/` convertem `wappalyzer technologies/*.json` (fork `tunetheweb`), nuclei tech-templates e o catálogo 0xdf-404 → `brain/rules.yaml` + tabelas de favicon hash. Atualizável via `origami update` (= `git pull` no upstream). Sem manutenção manual de assinatura.
- **Camada overlay (nossa):** `brain/overlay.yaml` — regras curadas + o que o aprendizado cross-target descobre (expansões de shortname confirmadas, associações `/backup/`↔`.git/`, etc.). É a **referência própria/versionada** e **precede a camada ingerida em conflito**.
- **Licenciamento:** anotar a licença de cada fonte (Wappalyzer fork, SecLists MIT, nuclei) e respeitar os termos na ingestão.

### 3.10 Segurança operacional — rate-limit / WAF (`core/engine.py`)
Cidadão de 1ª classe **já no MVP**: cap de concorrência configurável, jitter e **backoff adaptativo** ao detectar 429 / 403-com-assinatura / captcha / connection reset; rotação leve de UA/header. No MVP fica só o backoff + cap; o bandit que **otimiza** budget vem depois (§3.8). Objetivo: não tomar block e manter o scan dentro do que o alvo aguenta.

### 3.11 Escopo e recursão (`core/scanner.py`)
Cap de profundidade de recursão, restrição a mesmo host/scheme, lista de exclusão de paths e teto de requests por run. Evita explosão combinatória e mantém o scan dentro do escopo autorizado.

## 4. Módulo Shortscan (8.3 / tilde) — o melhor fold do IIS

O tilde **colapsa o espaço de busca de impossível pra tratável**: entrega prefixo de até 6 chars + extensão truncada em 3, mais `~N` em colisão.

**Gate de calibração:** só liga se IIS confirmado **E** o tilde vazar (probe `~1*` lendo delta 404 vs 400). `fsutil 8dot3name` desabilitado ou patch de mitigação → não gasta request.

**Dois regimes:**
- **Regime 1 — está na wordlist (determinístico, ganho gigante, zero ML):** o short name vira *filtro de constraint*. `ADMINI~1.ASP` → testa só entradas `^admini` da família `asp`. 100k entradas → ~20 candidatos. Brute cego vira brute confirmado.
- **Regime 2 — não está em wordlist (entra inteligência leve):** nome > 6 chars não-comum → **gerador n-gram/Markov** condicionado no prefixo + contexto (tech, extensão, pasta, idioma do alvo). Ex.: idioma pt-BR aumenta peso de `cliente.aspx` e reduz `customer.aspx`.

**Loop bidirecional (o origami dobrando):** confirmar `ADMINI~1.ASP → administration.aspx` é um dado rotulado `(truncado → nome completo real)`. Acumulado entre alvos, aprende a distribuição de expansão e melhora o gerador do Regime 2 a cada scan.

**Tabela truncado → família de extensão** (lookup fixo na KB):
`ASP → {.asp,.aspx}` · `ASA → {.asax,.asa}` · `ASM → {.asmx}` · `ASH → {.ashx}` · `ASC → {.ascx}` · `CON → {.config}` · `CS → {.cs}`

**Cuidados:** `~N` (N>1) ⇒ múltiplos arquivos com mesmo prefixo+ext, gerar várias expansões; short name de diretório (`UPLOAD~1`) abre recursão; o 8.3 raramente é requestável direto em IIS moderno — o valor está na reversão.

**Integração:** invoca `~/go/bin/shortscan` (binário Go já instalado), parseia a saída, transforma cada hit em `Evidence{source:"shortscan", confidence:0.95}` consumida com prioridade máxima. Flags `--shortscan` (força) / `--no-shortscan` (desliga).

## 5. Stack tecnológico

| Camada | Tecnologia |
|---|---|
| Linguagem | Python 3.11+ |
| Engine HTTP | `asyncio` + `httpx` (worker pool com concorrência limitada) |
| Parsing HTML/JS | `selectolax` (rápido) ou `beautifulsoup4` (já em uso no protótipo) |
| Knowledge base | `PyYAML` |
| Similaridade de resposta | simhash/LSH (`simhash` ou impl. própria) |
| Favicon hash | `mmh3` |
| Persistência | `sqlite3` (stdlib) |
| Cross-target (v2) | `scikit-learn` (k-NN) ou `faiss`/`annoy`; `mlxtend` (FP-growth) |
| Bandit (v3) | Thompson sampling próprio (~30 linhas, sem lib) |
| Saída | JSON + HTML; CLI com `rich` |
| Catálogos (ingestão) | dados do `tunetheweb/wappalyzer`, nuclei tech-templates, 0xdf-404, FingerprintHub; wordlists SecLists/Assetnote |
| Teste/benchmark | servidor fake local + harness de métrica `hits/request` e `FP-rate` vs ffuf `-ac` |
| Externo | `shortscan` (Go, `~/go/bin/shortscan`) |

**Por que não Go/Rust agora:** o diferencial do Origami é o *cérebro* (k-NN, association, bandit, n-gram), trivial em Python; throughput bruto não é o gargalo no MVP. A fronteira limpa permite portar só o engine depois.

## 6. Estrutura de diretórios

```
origami/
  cli.py                      # entrypoint: origami <url>
  core/
    scanner.py                # orquestra o pipeline
    engine.py                 # worker pool asyncio+httpx
    baseline.py               # calibração por contexto
    fingerprint.py            # fingerprint aditivo por prefixo
    evidence.py               # Evidence + TargetProfile + EvidenceBus
    scheduler.py              # priority queue
    response_classifier.py    # hit vs soft-404
    queue.py
  modules/
    tech/        iis.py apache.py nginx.py tomcat.py laravel.py wordpress.py
    discovery/   robots.py sitemap.py js_parser.py backups.py api_discovery.py shortname.py
  wordlists/     base.txt iis.txt aspnet.txt php.txt java.txt api.txt   # + SecLists/Assetnote
  brain/
    rules.yaml                # KB — camada ingerida (upstream)
    overlay.yaml              # KB — camada própria/curada + write-back do aprendizado
    ingest/                   # adapters: wappalyzer/, nuclei/, zerodf404/, favicon/
    memory.py                 # corpus, k-NN, association, n-gram (v2+)
    memory.sqlite
    model.py
  output/        json_report.py html_report.py
  tests/
    fakeserver/               # IIS soft-404, wildcard, 404 custom, rate-limit
    benchmark/                # cenários + métrica hits/request vs ffuf
  banner.py
```

**Redesenho do zero — o protótipo NÃO é reaproveitado.** O código de Fev/2024 (`origami.py`, `teste*.py`, `modules/*`) é `requests` síncrono, sem baseline, sem evidence bus, sem fingerprint real — reescrever é mais limpo que adaptar. Ele foi movido pra `legacy/` apenas como referência histórica e será apagado quando o MVP estiver de pé. Nenhuma linha migra; no máximo *ideias* sobrevivem em componentes novos e completamente reescritos (ex.: a extração de nomes de links vira `discovery/js_parser.py` async).

## 7. Roadmap

**MVP (núcleo adaptativo enxuto)** — escopo confirmado:
1. CLI `origami <url>`.
2. Baseline por contexto (soft-404 multidimensional + wildcard + case-sensitivity).
3. Fingerprint inicial (headers, cookies, error pages, favicon mmh3, robots/sitemap).
4. Evidence bus (lista + reducer) + TargetProfile.
5. **Overlay curado** (`brain/overlay.yaml`, ~10-15 techs à mão) + módulos **IIS** e **PHP**. *(Ingestão multi-fonte fica pro v2.)*
6. Scheduler com prioridade + expansão de extensão em tempo real.
7. Engine async + **backoff/rate-limit** + Response Classifier (threshold simhash) pra filtrar FP.
8. Escopo/recursão controlados + saída JSON.
9. **Harness de teste local** (servidor fake) pra desenvolver baseline/classifier sem bater em alvo real.
10. **Fold shortscan (IIS 8.3)** — gated pela vuln-check do próprio shortscan, expansão Regime 1 (constraint-filter) + seeds de autocomplete. ✅ implementado.

> **Status (atual):** MVP fechado e além. Prontos e verificados (fake server 404/soft-404/wildcard + alvo real):
> calibração por contexto; fingerprint+fold (headers/cookies/error-page + **favicon mmh3**); engine async+backoff; classificador soft-404 com **filtros `-mc/-fc/-ms/-fs`** (404/400 fora por padrão); recursão com escopo; **shortscan (IIS 8.3)**; **js_parser**; **backups** (vcs + name-folding); **robots/sitemap**; **memória SQLite + priming cross-target + `--history`**; saída JSON.
> UX: dashboard `rich` ao vivo com **findings em stream permanente** (nunca perde), status bar fixa (fase, req/s, hits, duração), **`==> directory`** estilo dirb, cor por origem + **tags semânticas** (disclosure/config/auth/admin/api), start/duração, wordlist em uso, **pular dir `n` / sair `q`**, fallback sem rich, `-v/-vv`, `-F`.
> Robustez (validado em alvo real com WAF): **auto-upgrade de redirect canônico** (http→https); **detecção de WAF** (F5/Cloudflare/Imperva/Akamai/… por corpo+headers+cookies) que não vira finding e aparece no fingerprint; **verificação de hit-surpresa com irmão aleatório** + assinaturas soft-404 aprendidas (multi-modal); normalização de UUID/nonce; **filtros = só exibição** (recursão preservada). **JS→JS** (segue webpack chunks + source maps, pula libs vendor, pega `data-main`). **Vocabulary folding** — nomes+extensões das referências + host/subdomínio/path viram wordlist+extensões. **Shortscan completo**: detecção (gate OR-acumulado), expand (constraint-filter + 8.3 cru + prefixo como dir/arquivo) e **completador n-gram (Regime 2)** pra prefixos truncados. **Parâmetros** colhidos como intel. **Recursão em diretórios-pai** de hits profundos. Saída: **HTML report** + `--out` (params.txt/urls.txt/findings.json). `--scope host|site`. Pacote instalável (`pip install -e .` → `origami`), 30 testes.

**v2 — ingestão + aprendizado mais forte:** ingestão multi-fonte (Wappalyzer/nuclei/0xdf-404/favicon DBs → KB); k-NN sobre fingerprint-vector (hoje o priming é por tech compartilhada) + association mining; `api_discovery` (Swagger/GraphQL); gerador n-gram pro Regime 2 do shortscan; resume mid-scan; saída HTML; benchmark `hits/request` vs ffuf.

**v3 — modelo treinado (quando houver dado):** FP-classifier treinado + gerador n-gram pro Regime 2 do shortscan + contextual bandit (hits/budget, só sob WAF/rate-limit). Treino usa o corpus do v1/v2 + servers de teste online.

## 8. Teste e avaliação

- **Harness local (`tests/fakeserver/`):** servidor que emula IIS soft-404, wildcard routing, 404 custom, case-insensitive paths e rate-limit. Permite desenvolver baseline/classifier de forma determinística, sem bater em alvo real.
- **Benchmark (`tests/benchmark/`):** conjunto de cenários medindo **hits/request** e **FP-rate** do Origami vs **ffuf `-ac`**. É a prova de que adaptativo > cego — sem isso, "é melhor" é só alegação.
- **Servers online do usuário:** validação realista e fonte de corpus rotulado pro treino posterior (a fase em que o modelo treinado do §3.8 passa a valer a pena).
