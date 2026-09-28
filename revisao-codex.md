# Origami — revisão e plano de correções

Data: 28/09/2026 · Terceira passagem: revisão crítica do plano · Versão: `1.12.2` · Commit: `16295d88f71dd16b0a7fa49498a4ff11030d896a`

## Diagnóstico

A prioridade é tornar a execução e seus resultados mais confiáveis: proteger credenciais, delimitar o tráfego, preservar corretamente os checkpoints e entregar relatórios que indiquem falhas e cobertura incompleta. A base já tem componentes separados, testes de regressão, saída HTML com escape e restrição de esquemas nos links, persistência SQLite com WAL e gravação de checkpoint por substituição atômica. Esses pontos devem ser preservados.

Os problemas mais relevantes estão nas fronteiras entre componentes: cabeçalhos globais usados para origens diferentes, nomes de arquivos que colidem, informações perdidas entre execução e serialização, mensagens humanas misturadas ao JSONL e erros de gravação que não chegam ao código de saída.

**Conclusão de produto:** o Origami tem uma CLI rica e mecanismos adaptativos, mas ainda precisa de uma camada consistente de projeto, execução, evidência e revisão para ser um aplicativo confiável de trabalho. A capacidade de apresentar muitos resultados já existe; faltam garantias de que esses resultados não se perdem, de que sua procedência é recuperável e de que “confiança” corresponde a algo que o operador consegue interpretar. Uma interface nova ou um modelo de IA devem consumir essa base, depois de estabilizada.

**Objetivos, por valor prático** — a ordem de implementação está na seção “Sequência de execução revisada”:

1. Preservar evidências diante de erro de configuração, disco, cancelamento e falha de exportação — R04/R06/R15.
2. Impedir transporte de credenciais ou requisições fora da política aprovada — R01/R02/R03/R08.
3. Distinguir execução completa, parcial e falha em todos os formatos — R05/R07/R16.
4. Isolar projetos e permitir exclusão efetiva da memória — R09/R17.
5. Oferecer revisão explicável de evidências, com métricas de utilidade e sem tratar heurística como probabilidade — seção de evolução do produto.

Este documento é um plano para execução posterior. A implementação não foi alterada. O escopo da revisão foi qualidade de software, proteção do operador, limites de execução, integridade das evidências e documentação. Não houve varredura externa nem validação de exploração. Os módulos ofensivos não receberam propostas para ampliar sua capacidade.

### Correções feitas nesta revisão do plano

O texto anterior acumulou evidências úteis, mas ficou amplo demais como roteiro de execução. Os 20 IDs são **áreas de trabalho**, com sobreposições, e não 20 defeitos independentes nem 20 PRs obrigatórios.

- **Prioridade corrigida:** R10 passa a P1 porque inclui perda de arquivo já demonstrada. R19 passa a P3: plano SQL sem índice não comprova problema de desempenho. Em R17, esclarecer a exclusão é imediato; reconstruir a procedência de dados derivados é evolução de esquema.
- **Dependência corrigida:** definir identidade, estado e formato mínimo antes de migrar persistência; isso evita duas migrações para o mesmo resultado.
- **Compatibilidade corrigida:** conservar o fluxo atual de findings do JSONL. Eventos de encerramento/aviso não entram silenciosamente no mesmo formato.
- **Escopo reduzido:** corrigir CLI, transporte, persistência e entrega primeiro. Sistema completo de eventos, interface gráfica, LLM e refatoração ampla ficam como evolução condicionada a benefício demonstrado.
- **Retomada corrigida:** mudanças de orçamento ou apresentação não devem ser rejeitadas junto com mudanças de alvo, identidade ou escopo.
- **Promessas ajustadas:** resultado produzido em RAM não é necessariamente recuperável após disco cheio ou término abrupto. Os critérios abaixo distinguem gravação confirmada, tentativa de recuperação e limitação inevitável.

Nesta passagem foram revistos o documento, o contrato atual da CLI, checkpoints, esquema SQLite e CI. O commit continua igual. Os resultados de testes apresentados adiante pertencem às passagens anteriores; não houve nova execução dessas suítes. Os scripts das checagens adicionais não foram versionados: antes de corrigir cada defeito, transformar seu cenário em regressão verificável no repositório.

## Método e limites

Foram examinados CLI, cliente HTTP, escopo, tipos e orquestração do scanner, checkpoints, memória SQLite, relatórios, documentação, empacotamento e CI. A análise dos módulos de descoberta foi direcionada às fronteiras de transporte e persistência; não constitui auditoria exaustiva de todos os detectores.

As evidências estão classificadas como:

- **Verificado localmente:** comportamento observado em função pura, arquivo temporário, ferramenta estática ou teste existente.
- **Constatado no código:** fluxo visível na implementação, sem demonstração dinâmica do impacto.
- **Melhoria proposta:** endurecimento ou mudança de contrato que ainda precisa de desenho e testes.

As prioridades são de engenharia, não notas CVSS: **P1** antes de confiar em execuções e entregas sensíveis; **P2** próxima rodada de robustez; **P3** manutenção. Não foi atribuída P0 sem evidência de incidente ou impacto crítico imediato.

Arquivos locais previamente não rastreados foram preservados e não foram usados como evidência da implementação atual.

## Validações executadas

Ambiente: Python `3.11.15`, Ruff `0.16.2`, Mypy `2.3.0`, usando `.venv` existente.

| Verificação | Resultado |
|---|---|
| `.venv/bin/ruff check origami/ --output-format concise` | Passou |
| `.venv/bin/mypy origami/ --no-incremental` | Falhou: 1 erro em 65 arquivos examinados |
| `.venv/bin/python -m pip check` | Sem requisitos quebrados; não é auditoria de vulnerabilidades |
| Primeiro grupo de testes, 27 casos | 26 passaram; 1 erro por restrição do ambiente |
| Segundo grupo de testes, 21 casos | 21 passaram |
| Checagens adicionais com dados sintéticos e arquivos temporários | Confirmaram problemas de serialização, nomes, validação e saída descritos abaixo |

Comandos dos grupos selecionados:

```bash
PYTHONPATH=.:tests .venv/bin/python -m unittest \
  test_engine.TestResume \
  test_engine.TestEngineBackoff \
  test_engine.TestLiveProgress \
  test_memory.TestMemoryHygiene -v

PYTHONPATH=.:tests .venv/bin/python -m unittest \
  test_scanner.TestOutputRobustness \
  test_scanner.TestEndpointGraph \
  test_scanner.TestScanDiff \
  test_scanner.TestHeaderParse \
  test_scanner.TestJsonlStream -v
```

O caso `test_slow_trickle_body_does_not_hang_forever` parou em `asyncio.start_server`, com `PermissionError: operation not permitted` ao tentar abrir `127.0.0.1`. Isso não comprova defeito no timeout. O teste permanece pendente em ambiente que permita socket local. Não foi executada a suíte inteira nem foram executados benchmarks; portanto, não há conclusão de aprovação global ou medição de desempenho.

### Evidências adicionais da segunda passagem

Foram feitos **15 cenários adicionais de checagem**, com funções locais, bancos/arquivos temporários e substituição do scanner/transporte por doubles de teste. Não foram acrescentados testes ao repositório. Os números abaixo descrevem essas checagens, não uma nova execução da suíte inteira.

| Cenário | Observação local | Referência |
|---|---|---|
| CLI com resultado concluído e destino JSON inválido | Retornou `0`; chamou remoção do checkpoint antes da exportação | R06/R15 |
| CLI com `completed=False` e duas requisições contabilizadas | Retornou `0` | R07 |
| JSONL existente + arquivo de proxies inexistente | Conteúdo anterior truncado; handle permaneceu aberto ao sair de `run` | R10/R15 |
| Lista com dois alvos e erro sintético no primeiro | Apenas um alvo chegou ao scanner simulado | R15 |
| Construção de dois clientes, com falha no segundo | Primeiro cliente não recebeu `aclose`; lista do motor ficou vazia | R15 |
| Exclusão de host com termo no agregado | Histórico do host removido, termo continuou em `word_stats` | R17 |
| Round-trip de checkpoint | `cache_layer` e `Finding.repro` perderam seus valores | R04/R13 |
| Esquema SQLite de achados | Ausência de `note`, `tags` e `repro` | R13 |
| Emissão seguida de enriquecimento sintético | Dois registros da mesma URL sem tipo de evento ou ID estável | R16 |
| Contrato usado pelo benchmark adaptativo | `ScanOptions(wordlist_path=...)` lançou `TypeError` | R20 |
| Erro SQLite durante `record_run` | Transação permaneceu aberta; gravação posterior confirmou run sem findings | R15 |
| Planos SQL do histórico | `SCAN findings` e `SCAN runs` | R19 |
| Atualização de catálogo com uma entrada simulada | Substituiu catálogo anterior; completude não faz parte do retorno | R18 |
| Motor com retry e prazo já expirado | Duas tentativas para um incremento lógico; retornou `200` apesar do prazo | R08 |
| Corpo de exatamente cinco bytes com limite de cinco | Retido integralmente, mas `truncated=True` | R13 |

Limites dessas evidências: o cenário de clientes comprova ausência de limpeza em doubles, não quantifica sockets vazados. O cenário SQL demonstra contaminação de transação se o mesmo objeto for reutilizado depois do erro; a CLI atual normalmente aborta esse caminho antes de reutilizá-lo. O cenário de atualização confirma substituição, enquanto o risco de catálogo parcial também depende do tratamento de shards no código. O teste de prazo exerceu o motor diretamente; não mediu o excesso de uma execução completa.

## Backlog priorizado

| ID | Prioridade | Trabalho | Evidência | Esforço estimado |
|---|---|---|---|---|
| R01 | P1 | Vincular credenciais à origem e redigir segredos | Código | Médio |
| R02 | P1 | Tornar identidade de host e escopo conservadores | Código | Médio |
| R03 | P1 | Separar políticas TLS do transporte principal e replay | Código | Pequeno/médio |
| R04 | P1 | Corrigir identidade, validação e concorrência dos checkpoints | Local + código | Médio |
| R05 | P1 | Preservar stdout como JSONL válido | Local + código | Pequeno |
| R06 | P1 | Propagar falhas de saída e evitar sobrescrita entre alvos | Local + código | Médio |
| R07 | P1 | Registrar execução incompleta e falhas por etapa | Local + código | Médio |
| R08 | P1 | Fazer limites de requisições e tempo corresponderem ao contrato | Local + código | Médio/grande |
| R09 | P1 | Proteger arquivos de evidências e memória | Local + código | Médio |
| R10 | P1 | Validar entradas da CLI antes de iniciar recursos | Local + código | Pequeno/médio |
| R11 | P2 | Corrigir Mypy e tipar contratos de infraestrutura | Local | Pequeno inicialmente |
| R12 | P2 | Comparar apenas execuções compatíveis no diff | Local + código | Médio |
| R13 | P2 | Preservar notas e contexto nos relatórios | Local + código | Pequeno/médio |
| R14 | P3 | Tornar manutenção, empacotamento e documentação verificáveis | Código + proposta | Incremental |
| R15 | P1 | Garantir finalização, recuperação e transações atômicas | Local + código | Médio/grande |
| R16 | P2 | Versionar eventos e separar dados de apresentação | Local + código | Médio |
| R17 | P1/P2 | Esclarecer exclusão agora; implementar procedência dos derivados depois | Local + código | Médio |
| R18 | P2 | Atualizar catálogo com integridade e rollback | Local + código | Médio |
| R19 | P3 | Medir escala antes de decidir otimizações | Plano SQL + código | A medir |
| R20 | P2 | Corrigir a evidência de avaliação e as promessas de inteligência | Local + código | Médio |

Esforço pequeno significa alteração localizada; médio atravessa alguns componentes; grande exige rever o contrato compartilhado. São estimativas de escopo, sem compromisso de prazo.

**Como usar o backlog:** as evidências e critérios de cada R servem de referência. A sequência revisada seleciona o recorte de cada item por entrega; ela não exige implementar toda a visão de produto descrita em cada R. R04 cuida do formato/identidade de checkpoint; R06, da exportação; R07, do estado; R15, da ordem de finalização e fechamento. Resolver a mesma falha em vários desses contratos não deve gerar implementações duplicadas.

### R01 — Credenciais por origem e redação consistente

**Evidência:** `origami/core/httpclient.py:245` cria clientes com todos os `cfg.headers` como defaults. `origami/modules/discovery/js_parser.py:348` permite leitura de scripts de outras origens consideradas do mesmo site usando o mesmo `engine.fetch`. A ausência de redirects automáticos não resolve uma chamada direta a outra origem. `origami/cli.py:296` mascara valores apenas quando ultrapassam 20 caracteres; valores curtos de cabeçalhos sensíveis aparecem integralmente.

**Impacto:** uma sessão fornecida para o alvo pode acompanhar requisições a um CDN ou subdomínio distinto. O risco é especialmente importante para `Authorization`, `Cookie` informado manualmente e chaves em cabeçalhos personalizados. Não foi realizado envio de credenciais para demonstrar o impacto.

**Plano:**

- Vincular credenciais à origem aprovada, composta por esquema, hostname normalizado e porta efetiva.
- Remover credenciais em acessos a outras origens por padrão; compartilhamento deve ser configuração explícita e específica.
- Aplicar a mesma regra aos clientes auxiliares e replay. Diferenciar cookies geridos pelo cookie jar de um `Cookie` fornecido como header global.
- Centralizar redação por nome de campo e contexto, incluindo URLs com credenciais, proxies, mensagens de exceção e notas. Não decidir sigilo pelo comprimento do valor.

**Aceite:** testes com transportes simulados demonstram que nenhuma credencial acompanha uma origem não autorizada; logs não contêm valores sintéticos sensíveis, inclusive os curtos. Nenhum teste precisa enviar tráfego externo.

### R02 — Identidade de host não deve ampliar autorização

**Evidência:** `origami/core/scope.py:39` e `origami/core/scope.py:60` usam divisão textual por `:`. Isso não representa corretamente IPv6. `same_host` ignora porta e `www`; `reg_domain` depende de uma lista parcial de sufixos. `origami/brain/memory.py:109` repete parte da normalização. Ler um recurso do mesmo domínio registrável também é uma operação de rede e deve estar representado no escopo.

**Impacto:** decisões de escopo e identificação de serviços podem confluir onde deveriam permanecer distintas. Equivalência útil para memória não é, por si só, autorização para enviar uma requisição.

**Plano:**

- Separar identidade exata de origem, identidade de host e agrupamento de domínio para análise.
- Usar parsing de URL e endereço IP apropriado, com tratamento explícito de IPv6, porta, caixa e ponto final.
- Fazer o padrão de autorização aceitar apenas as origens explicitamente permitidas, incluindo recursos auxiliares.
- Se mantido o agrupamento por sufixo público, documentar sua limitação e usar uma fonte versionada local; falha na classificação deve restringir acesso.
- Aplicar a decisão de escopo no transporte, além dos filtros de candidatos, sem transformar a equivalência `www`/apex em autorização implícita.

**Aceite:** matriz de testes de normalização e de negação de acesso cobre IPv4/IPv6, portas, subdomínios, sufixos compartilhados e hosts desconhecidos. Usar apenas dados sintéticos e transporte simulado.

### R03 — TLS: separar exceções e evitar redução implícita

**Evidência:** `origami/cli.py:418` desativa `verify_tls` também quando somente `--replay-proxy` está configurado. Assim, um proxy destinado à etapa final altera a verificação das conexões principais. `origami/core/httpclient.py:113` tem `verify_tls=False` como default de biblioteca; a CLI normalmente o sobrescreve. O motor também reduz automaticamente a política TLS após certos erros.

**Plano:** estabelecer verificação de certificado como default da biblioteca; separar configuração TLS do cliente principal e do replay; permitir CA de proxy explicitamente; tornar a redução de segurança TLS uma opção explícita e registrá-la de forma estruturada na execução.

**Aceite:** testes de construção de clientes mostram que configurar apenas replay não altera a política principal. Exceções inseguras são específicas, visíveis e nunca ativadas silenciosamente.

### R04 — Checkpoint: identidade, validação e fidelidade

**Evidência:** `origami/core/resume.py:23` descarta esquema e substitui caracteres por `_`. A checagem local confirmou que HTTP e HTTPS com o mesmo host/caminho recebem o mesmo arquivo. A estratégia também admite colisões entre caminhos distintos. `load`, na linha 115, trata erro de JSON, mas não valida o tipo raiz nem os campos: `[]` provocou `AttributeError`; `{"version": 1}` provocou `KeyError`.

O temporário de `save` usa nome fixo `.tmp`; substituição atômica não impede concorrência entre escritores. `resume_scan`, em `origami/core/scanner/__init__.py:789`, confia no profile carregado. O checkpoint não vincula configuração/identidade lógica da execução e não preserva `harvested_paths`; também omite campos do profile, como `cache_layer` e `bucket_refs`.

**Aprofundamento:** a perda de `cache_layer` foi confirmada em round-trip, assim como a perda de `Finding.repro`, ausente em `_finding_to_dict`. A retomada retorna diretamente de `_scan_loop`; as verificações finais e o replay que aparecem depois dessa chamada em `scan` não passam pelo mesmo caminho. Isso é divergência de ciclo de vida constatada no código. A correção deve unificar a finalização e explicitar quais etapas foram ou não executadas, sem ampliar atividades automaticamente ao retomar.

**Plano:**

- Separar chave de alvo/configuração de `run_id`: a primeira localiza checkpoints compatíveis; o segundo identifica uma execução específica. A canonização não deve colapsar componentes semanticamente distintos. Havendo mais de um checkpoint compatível, listar as opções e exigir seleção explícita, sem escolher por nome de arquivo colidente.
- Validar esquema, tipos, campos obrigatórios, limites de tamanho e compatibilidade antes de reconstruir objetos.
- Confirmar que o alvo do checkpoint corresponde ao alvo solicitado.
- Registrar configuração relevante e rótulo da identidade, sem salvar segredos. Rejeitar mudança de alvo/projeto ou ampliação de escopo; permitir alterações documentadas de apresentação e orçamento. Alteração de identidade não reutiliza automaticamente conclusões dependentes da sessão anterior. As regras completas estão na seção de compatibilidade.
- Preservar os dados necessários aos relatórios após retomada, começando por `harvested_paths`.
- Usar temporário exclusivo e controle de escritor único, com diagnóstico de estado incompatível/corrompido. Não iniciar nova execução silenciosamente quando o operador pediu retomada e há arquivo inválido.

**Aceite:** round-trip preserva os campos contratados; URLs distintas não colidem; entradas inválidas geram erro controlado; dois escritores não compartilham temporário; retomada incompatível é recusada antes de rede, enquanto as mudanças permitidas seguem a matriz documentada.

### R05 — Contrato de stdout para JSONL

**Evidência:** `origami/cli.py:256` direciona parte dos logs ao stderr no modo `--jsonl -`, mas `_write_outputs`, na linha 175, continua usando `print` no stdout. Uma chamada local com `jsonl='-'` e saída JSON produziu uma linha `[+] JSON written...` no stdout. O tratamento de `KeyboardInterrupt`, na linha 819, também imprime ali.

**Plano:** passar um destino de diagnóstico consistente a todos os caminhos da CLI; reservar stdout exclusivamente aos registros quando solicitado; definir tratamento de pipe fechado e interrupção sem mensagens humanas nesse fluxo.

**Aceite:** um teste da CLI com scanner simulado combina JSONL com cada formato de arquivo e verifica que todas as linhas do stdout são JSON válido. Repetir para interrupção e falha de gravação. Os testes atuais do formato de `finding_record` não cobrem essas combinações.

### R06 — Falha de gravação precisa chegar ao chamador

**Evidência:** `_write_outputs` usa um único `try` para todos os formatos, captura `OSError` e retorna `None`. A checagem local mostrou que uma saída JSON inválida impede a gravação de HTML em caminho válido. `run` não recebe um resultado de gravação para ajustar seu código de saída. `_slug`, em `origami/cli.py:164`, também colide entre `/a/b` e `/a_b`, confirmado localmente; em uma lista, os artefatos podem se sobrepor.

**Confirmação adicional:** a própria `cli.run`, com scanner substituído por um resultado sintético, retornou `0` diante de falha de gravação. A remoção do checkpoint ocorreu antes da tentativa de exportação. Com `--no-learn` e sem JSONL, a falha de exportação pode deixar a execução sem um resultado durável recuperável; o checkpoint anterior também não era necessariamente um snapshot final completo. Corrigir a ordem de finalização em R15, não apenas o `except` de saída.

**Plano:**

- Retornar resultado por artefato, com caminho, sucesso e erro; tentar as saídas independentes mesmo se uma falhar.
- Definir e documentar códigos de saída para sucesso, execução parcial, erro de entrada, interrupção e falha de persistência.
- Usar nomes inequívocos por alvo/execução, reaproveitando a identidade de R04.
- Gravar arquivos por substituição atômica e emitir um manifesto ao concluir o conjunto. O manifesto deve indicar falhas parciais.
- Validar o destino antes de iniciar uma execução longa e ainda tratar erro tardio de disco/permissão.

**Aceite:** falha em um formato não bloqueia outros; retorno não indica sucesso completo se uma saída solicitada falhou; destinos antigos íntegros não são truncados numa gravação interrompida; alvos distintos geram diretórios distintos.

### R07 — Resultado incompleto deve ser visível e estruturado

**Evidência:** `ScanResult` possui `completed`, `error` e `pushbacks`, mas `origami/output/json_report.py:29` não os exporta. A ausência foi confirmada com resultado sintético. `origami/core/scanner/util.py:104` registra exceções de etapas apenas no observador; o encerramento em `origami/core/scanner/__init__.py:1089` marca conclusão sem consolidar essas falhas. Isso deve ser tratado como lacuna de contrato, não como comprovação de que toda execução termina incorretamente.

**Aprofundamento:** `cli.run` também retornou `0` para resultado sintético incompleto. O comando `n`, em `origami/core/scanner/folds.py:94`, interrompe o prefixo sem `hit_cap`; o chamador o adiciona a `scanned`. Pular voluntariamente é uma função válida, mas “pulado pelo operador” precisa ser distinto de “avaliado integralmente” na cobertura. Não alterar essa escolha do usuário; registrá-la.

**Plano:** introduzir `schema_version`, `run_id`, versão da ferramenta, timestamps UTC, estado final, motivo de parada, avisos e resultado por etapa. Separar “orquestração terminou” de “todas as etapas solicitadas concluíram”. Refletir o mesmo estado em JSON, HTML, manifesto e memória. No JSONL atual, manter apenas findings e levar diagnóstico a stderr/manifesto; um eventual formato de eventos será separado e opt-in.

**Aceite:** limites atingidos, cancelamento, etapa com erro e execução completa geram estados distinguíveis. Nenhuma saída parcial deve parecer uma verificação integral. Mensagens estruturadas passam pela redação de R01.

### R08 — Limites precisam restringir tentativas reais e duração total

**Evidência:** `origami/core/httpclient.py:356` incrementa `total_requests` uma vez por chamada lógica, antes do loop de retries. Uma chamada pode realizar até `max_retries + 1` tentativas. `_over_budget`, em `origami/core/scanner/util.py:190`, consulta esse contador e o relógio nos chamadores; o próprio `fetch` não aplica o deadline global antes de cada retry. `_stream_probe` tem seu timeout próprio. O replay final em `origami/core/scanner/__init__.py:759` usa cliente diretamente e não integra o contador principal.

**Impacto:** “max requests” pode ser interpretado como limite de tráfego real, mas o contador representa outra unidade. O prazo global pode ser excedido por operações já iniciadas, esperas e retries. Na checagem direta do motor, um fluxo simulado `503 → 200` produziu duas tentativas para `total_requests=1`, mesmo com deadline já vencido. A dimensão do excesso numa execução completa não foi medida nesta revisão.

**Plano:**

- Definir separadamente operações lógicas e tentativas HTTP efetivas; documentar qual orçamento limita cada uma.
- Reservar orçamento no ponto central de envio, incluindo retries, com segurança para concorrência.
- Aplicar o tempo restante às esperas e operações de transporte; cancelar de forma controlada quando esgotado.
- Declarar como clientes auxiliares e replay entram nos limites ou em orçamento separado explícito.
- Registrar parada por orçamento como execução parcial conforme R07.

**Aceite:** relógio e transporte simulados comprovam que o teto de tentativas não é ultrapassado, nenhuma nova tentativa começa após o prazo e o encerramento libera recursos. Cobrir concorrência e retry sem acionar módulos ofensivos.

### R09 — Evidências e memória precisam de proteção em disco

**Evidência:** `origami/output/artifacts.py:30`, `origami/core/resume.py:93` e `origami/brain/memory.py:172` criam arquivos/diretórios sem política explícita de privacidade. Em diretório temporário com `umask 022`, `findings.json` e o banco SQLite foram criados com modo `0644`. Isso permite leitura por outros usuários se os diretórios ancestrais também permitirem acesso. O banco persiste URLs completas; o relatório inclui notas e evidências.

**Plano:** criar diretórios privados e arquivos privados desde a abertura, com equivalente por plataforma; incluir temporários e arquivos auxiliares SQLite na avaliação. Centralizar redação de URLs/query strings e segredos exportados. Separar entrega sanitizada de eventual evidência restrita, quando essa retenção for explicitamente desejada. Definir retenção e isolamento da memória por projeto/engajamento para evitar reutilização involuntária de dados entre contextos.

**Aceite:** modo POSIX `0700`/`0600` onde aplicável, teste com umask permissiva, nenhuma janela inicial de arquivo legível por terceiros e exportações sem sentinelas sensíveis. Não alterar recursivamente permissões de diretórios arbitrários indicados pelo usuário.

### R10 — Validar argumentos antes de abrir arquivos e clientes

**Evidência:** `_parse_duration`, em `origami/cli.py:108`, aceitou `-1s` e `nan`; `_normalize_url`, na linha 121, aceitou `ftp://example.test/file`. Opções numéricas de concorrência, timeout, taxa e profundidade usam `int`/`float` sem validação de domínio na etapa final da CLI. Concorrência zero é incompatível com a condição de aquisição do motor e pode impedir progresso.

**Aprofundamento:** `run` abre o arquivo JSONL em modo `w` antes de ler `--proxy-file`, e só instala o `finally` depois dessa leitura. Com um JSONL temporário existente e um arquivo de proxies ausente, o conteúdo anterior foi apagado antes do diagnóstico e o handle permaneceu aberto. Este caso exige prevenção de perda de dados, além de mensagens melhores.

**Plano:** validar finitude e intervalos; aceitar apenas HTTP/HTTPS; tratar porta inválida, hostname ausente e política para userinfo; normalizar cabeçalhos de forma insensível à caixa. Abrir JSONL, banco e clientes somente após validar toda a configuração. Usar uma política explícita de UTF-8 para arquivos de entrada e saída e mensagens úteis para falhas de decodificação.

**Aceite:** parâmetros inválidos terminam com diagnóstico curto e código de erro de entrada, sem conexão, arquivo truncado ou banco criado. Cobrir zero, negativos, `NaN`, infinito e cabeçalhos equivalentes por caixa. Não classificar toda opção zero como inválida: algumas usam zero como “desativado”.

### R11 — Corrigir o erro de Mypy e fortalecer contratos

**Evidência verificada:**

```text
origami/core/scanner/__init__.py:240: error:
Argument 3 to "fetch" of "Engine" has incompatible type "**dict[str, int]";
expected "str" [arg-type]
Found 1 error in 1 file (checked 65 source files)
```

`_root_cap` é um dicionário expandido numa assinatura que mistura parâmetros explícitos e `**kw`. O erro foi constatado com a versão local de Mypy; não foi consultado o estado remoto do CI. A configuração em `.github/workflows/tests.yml` executa Mypy como gate, portanto o problema precisa ser resolvido no ambiente de desenvolvimento/CI suportado.

**Plano:** tornar o override de limite de corpo um parâmetro explícito e tipado, ou representar corretamente a estrutura de kwargs; evitar supressão genérica. Tipar gradualmente contratos de checkpoint, escrita de artefatos, eventos, observador e callback `finding_sink`. O Mypy atual informa que corpos sem anotação não são verificados por padrão.

**Aceite:** o comando acima passa; nenhuma nova supressão ampla; ativação de verificação de funções sem anotação ocorre por escopo, após tratar o volume real de erros.

### R12 — Diff não deve confundir ausência de observação com desaparecimento

**Evidência:** `origami/output/diff.py:20` reduz a chave ao path; query e origem não compõem a identidade. `compute` marca como `gone` qualquer entrada anterior ausente da lista atual. Em verificação pura, baseline com um path e lista atual vazia produziu um desaparecimento. `origami/brain/memory.py:306` escolhe último run por host normalizado, que ignora porta e `www`; não exige o mesmo base path, configuração ou identidade. A CLI também pode pedir diff de resultado interrompido.

**Impacto:** comparação de execuções com cobertura diferente pode produzir conclusão indevida. A checagem local confirmou o comportamento do comparador, não o desaparecimento real de um recurso.

**Plano:** persistir identidade de origem, configuração, contexto de autenticação por rótulo e estado/cobertura da execução. Aceitar baseline compatível. Para recurso não observado, emitir “não reavaliado” ou “ausente nesta execução”; só usar “desaparecido” quando houver evidência apropriada. Definir identidade de recurso sem colapsar silenciosamente consultas/origens distintas.

**Aceite:** mudança de porta, base path, identidade, filtros ou execução parcial não gera desaparecimento definitivo. Uma diferença de tamanho isolada permanece mudança observada, sem conclusão automática de segurança.

### R13 — HTML precisa preservar a explicação do achado

**Evidência:** `origami/output/html_report.py:82` monta as linhas sem `Finding.note`. Uma nota sintética apareceu no objeto/JSON, mas não no HTML renderizado. A página tampouco mostra o estado parcial descrito em R07. O timestamp representa a renderização, sem distinguir início/fim da execução e sem timezone explícito.

**Aprofundamento do contrato de evidência:**

- O SQLite persiste um subconjunto do achado: não guarda notas, tags ou metadados de reprodução. Não basta “reexportar do histórico” sem evoluir esse esquema.
- `Finding.repro` é um texto de comando, não um envelope estruturado de evidência; a retomada o perde. Preservar metadados sanitizados da observação e a referência a evidências evita depender de texto livre.
- `Probe.truncated` não é um campo de `Finding`; a informação de corpo parcial não acompanha todos os formatos. Além disso, o transporte marca `truncated=True` quando o corpo atinge exatamente o limite, mesmo se chegou integralmente: cinco bytes recebidos com limite de cinco reproduziram isso. Distinguir “atingiu limite” de “truncamento comprovado” ou comprovar a existência de bytes adicionais de forma limitada.
- URL, nota e outros textos entram em strings de markup Rich em `origami/output/ui.py:291` e `:610`; falta uma política uniforme de texto literal e caracteres de controle. É uma constatação estática de robustez de renderização, sem demonstração de exploração.

**Plano:** mostrar notas sanitizadas em detalhe expansível, origem da observação, limitação e estado da execução. Usar timestamps da execução com timezone. Acrescentar rótulo acessível ao filtro, navegação por teclado para ordenação e tabela utilizável em telas estreitas. Preservar escape HTML e restrição de esquemas nos links.

**Aceite:** notas e tags sobrevivem a persistência, retomada e exportação; conteúdo sintético com caracteres especiais permanece texto no HTML e terminal; filtros e ordenação são utilizáveis pelo teclado; renderização vazia e parcial é clara; corpo completo no limite não recebe conclusão falsa de truncamento. Fazer inspeção visual do HTML final quando esta etapa for implementada.

### R14 — Manutenção, dependências e documentação

**Constatações:** a orquestração tem 1.096 linhas e `folds.py` tem 2.237. `httpclient.py` importa `anyio` diretamente, mas o pacote não é declarado diretamente no `pyproject.toml`; hoje chega transitivamente. O CI testa Python 3.11/3.12 no Linux, enquanto o pacote declara Python `>=3.11` e sistema operacional independente. A instalação editável do CI não verifica sozinha o conteúdo de um wheel instalado. README e `origami.md` repetem informações extensas.

**Plano de manutenção:**

- Depois das correções de contrato, extrair responsabilidades de ciclo de vida, persistência e exportação da orquestração, em mudanças pequenas que preservem comportamento.
- Declarar dependências importadas diretamente e manter um ambiente de validação reproduzível; verificar recursos opcionais presentes e ausentes.
- Adicionar validação de construção e instalação limpa do wheel, incluindo `py.typed`, regras YAML e recursos empacotados.
- Definir plataformas e versões de Python efetivamente suportadas e ajustar a matriz ou as promessas do pacote.
- Separar testes puramente em memória de integração com socket local. Documentar a necessidade de permissão de bind; `CONTRIBUTING.md` chama toda a suíte de “in-process”, mas o teste bloqueado depende de um servidor TCP local.
- Consolidar especificação de flags/formatos e reduzir duplicação entre documentação e implementação. Não manter quantidade fixa de testes sem atualização automatizada.
- Rever afirmações absolutas como “safe by design” em README/SECURITY: um identificador adicional numa requisição não comprova isolamento no servidor. Descrever precondições e risco residual, sem prometer ausência de impacto.
- Distinguir indício, comportamento observado e falha de segurança confirmada no vocabulário dos relatórios; autorização e impacto dependem de contexto que um status HTTP sozinho não fornece.

**Aceite:** instalação do artefato publicado funciona fora do checkout; dependências diretas estão explícitas; a documentação corresponde aos contratos de escopo, limites, TLS, persistência e conclusão; refatorações de infraestrutura têm testes de equivalência e diffs revisáveis.

### R15 — Ciclo de vida, recuperação e transações

**Evidências:**

- `origami/cli.py:445` apaga o checkpoint antes de `_write_outputs`. Erro em `resume_mod.clear` também ocorre antes da exportação e não é tratado nesse ponto.
- A criação de JSONL e banco ocorre antes do `try/finally` de `run`. Configuração inválida nessa janela não passa pelo fechamento normal.
- Um erro não tratado do scanner no primeiro alvo abortou a lista de dois alvos na checagem com doubles. O tratamento de erro por formato não cobre erro de checkpoint, banco ou inicialização do transporte.
- `Engine.__aenter__` monta a lista de clientes por compreensão; se a criação de um cliente posterior falha, os anteriores não são recuperados para fechamento. Isso foi confirmado com um cliente falso que registra `aclose`.
- `Memory.record_run` executa várias escritas e só faz `commit` ao final, sem rollback local. Uma falha sintética na inserção de findings deixou a transação aberta; a operação seguinte de estatísticas confirmou o registro incompleto. WAL e busy timeout não substituem atomicidade da operação de negócio.
- `_scan_loop` grava checkpoints em pontos do loop, sem tratamento de `CancelledError` que persista o estado corrente. A mensagem geral de Ctrl-C promete retomada, mas a perda depende da última gravação e pode incluir o prefixo corrente. Interrupção antes do primeiro checkpoint pode não ter estado retomável. Essa parte é constatação estática, não teste de interrupção real.

**Plano:**

1. Validar toda a configuração antes de adquirir recursos; usar contextos de vida aninhados/stack de fechamento para arquivos, banco, clientes e tarefas.
2. Definir ponto de persistência do resultado final antes de excluir checkpoints. Exportação deve poder ser repetida a partir desse resultado, sem repetir tráfego. Respeitar a política de retenção: `--no-learn` continua sem ler/escrever o banco de memória; resultado final deve usar o destino de saída/recuperação documentado, sem ativar aprendizado nem guardar corpos adicionais silenciosamente.
3. Separar erro global de configuração de falha recuperável por alvo. Produzir resultado `failed` para o alvo e seguir a política explícita da lista; nunca transformar erro em resultado vazio “bem-sucedido”.
4. Fazer cada operação de memória ter transação com commit ou rollback próprio; não deixar transação pendente após exceção.
5. Encerrar tarefas pendentes com cancelamento aguardado. Salvar o progresso possível numa interrupção cooperativa e informar o que não foi persistido. Para término abrupto, definir a janela máxima de perda e usar persistência incremental se necessário.
6. Preservar os dados de recuperação se a exportação falhar. Não apagar saídas antigas antes de validar o destino e a política de sobrescrita.

**Aceite:** testes de falha na abertura do segundo recurso, cancelamento, erro de banco, falha de exportação e falha ao remover checkpoint deixam os recursos fechados e preservam a última gravação íntegra confirmada. Se não foi possível persistir o estado corrente, o app informa a perda potencial e não anuncia recuperação completa. Uma operação SQL que falha não pode ser confirmada por outra operação posterior. Substituição atômica evita arquivo parcialmente substituído, mas não comprova durabilidade diante de perda de energia; qualquer garantia adicional precisa definir sincronização e ser testada na plataforma suportada.

### R16 — Eventos consistentes e dados separados da apresentação

**Evidência:** `_report`, em `origami/core/scanner/_common.py`, emite a observação, e `_scan_body` pode emitir o mesmo objeto enriquecido depois. Na checagem com enriquecimento simulado apareceram dois registros da mesma URL sem `event_type`, `finding_id` ou revisão. `finding_record` não informa `run_id`; a CLI tampouco passa o `host` opcional. O mesmo URL em contextos diferentes não basta para identificar uma observação.

Além disso, `_dedupe_and_collapse` substitui grupos por um representante e uma contagem; os membros não ficam disponíveis no resultado final. O JSONL emitido anteriormente pode conservar mais linhas do que JSON/HTML/memória. O limite de apresentação acaba alterando os dados persistidos. Aqui o problema é integridade de evidência e consistência entre formatos; esta revisão não avalia como melhorar a detecção ou os critérios de agrupamento.

**Plano:**

- Primeiro definir ID de observação, revisão e semântica do enriquecimento no resultado persistido. Isso pode usar um snapshot versionado; não exige implantar armazenamento integral de eventos para corrigir a CLI.
- Conservar o JSONL atual como findings. Se necessário, oferecer um formato de eventos separado, com `run_id`, `observation_id`, sequência, tipo, revisão e timestamp UTC, distinguindo criação, enriquecimento, aviso e encerramento.
- Guardar observações e associação dos membros de grupos; aplicar agrupamento como visão de apresentação reversível.
- Separar observação coletada, item exibido e item revisado pelo humano. Filtro visual não deve eliminar silenciosamente o histórico já coletado; retenção e privacidade continuam explícitas.
- Definir comportamento de `BrokenPipeError`/falha do sink. Não permitir que `_guard` transforme perda de saída em mero aviso de etapa e continue indefinidamente.

**Aceite mínimo:** o snapshot final preserva observações e enriquecimentos sem duplicar sua identidade; os exportadores concordam sobre esse conjunto; membros de grupos podem ser inspecionados; perder a saída essencial interrompe de forma controlada ou persiste por um caminho alternativo previamente configurado. **Aceite adicional, somente se houver formato de eventos:** reconstruir a visão a partir dele equivale ao snapshot. Os consumidores do JSONL anterior continuam recebendo apenas o tipo de registro esperado.

### R17 — “Esquecer” deve incluir dados derivados

**Evidência:** `origami/brain/memory.py:405` remove as tabelas relacionadas ao host, mas preserva `word_stats`. Essa tabela é agregada por tecnologia e palavra, sem host ou run de origem. Na checagem, o histórico do host desapareceu, mas `private_project_term` continuou recuperável no agregado. `forget(None)` remove também essa tabela; o problema descrito é a exclusão seletiva.

**Impacto:** uma intenção de apagar dados de um cliente não remove necessariamente os termos derivados de sua execução. A estrutura atual não permite atribuir e retirar com precisão a contribuição de um host.

**Plano:** isolar a memória por projeto como padrão; registrar procedência dos dados derivados ou reconstruí-los a partir de contribuições que possam ser excluídas. Definir separadamente exclusão de evidências, checkpoints, relatórios e contribuições aprendidas. Até existir exclusão seletiva completa, a CLI precisa descrever exatamente o alcance de `--forget HOST`.

**Divisão de entrega:** esclarecer o comportamento e permitir usar um banco separado com a opção já existente `--db` são medidas imediatas; uma configuração formal de projeto e contribuições atribuíveis vêm depois. O agregado legado não contém informação suficiente para subtrair corretamente um host. Não inventar essa procedência nem limpar dados de outros projetos silenciosamente: manter o legado isolado e explicar as alternativas de preservá-lo ou apagá-lo integralmente por decisão explícita do usuário.

**Aceite:** após exclusão de um projeto de teste, sentinelas exclusivas dele não aparecem em tabelas, exportações ou derivados mantidos pelo aplicativo. Explicar a política para backups/WAL. Não prometer apagamento forense de SSD ou de cópias externas fora do controle do app.

### R18 — Atualização de catálogo não deve destruir a versão saudável

**Evidência:** `origami/brain/ingest/wappalyzer.py:77` agrega shards e converte falhas de cada shard em `{}`. `update_kb`, na linha 101, aceita qualquer conjunto convertido não vazio e substitui diretamente o arquivo anterior. Logo, falha parcial pode ser apresentada como atualização concluída com catálogo reduzido. Se todos os resultados forem vazios, o código preserva o arquivo anterior: esse controle já existe e deve ser mantido.

A checagem com catálogo simulado confirmou a substituição do conteúdo anterior; não simulou uma indisponibilidade real do fornecedor. `RULES_PATH`, em `origami/brain/kb.py:16`, está dentro do pacote instalado, que pode ser somente leitura. A escrita não é atômica e o arquivo não tem manifesto de procedência/versão.

**Plano:** tratar o catálogo como artefato versionado: registrar origem, instante, completude, formato e checksum; validar antes de ativar; escrever em área de dados do usuário; trocar atomicamente e conservar última versão válida para rollback. Falha parcial deve ser resultado explícito, sem substituir silenciosamente a versão saudável. Catálogo local inválido deve produzir diagnóstico e permitir uma política documentada para usar a versão embarcada.

**Aceite:** interrupção de escrita, shard ausente, JSON de tipo inesperado, arquivo sem permissão e catálogo inválido não corrompem a versão ativa. Atualização não modifica o diretório do pacote. Este item protege distribuição e integridade de dados; não propõe aumentar o catálogo de técnicas.

### R19 — Escala e retenção de dados locais

**Evidência:** o esquema em `origami/brain/memory.py` só declara explicitamente índice adicional para `corpus(path)`. `EXPLAIN QUERY PLAN` indicou `SCAN findings` para busca por `run_id` e `SCAN runs` para último run por host. Consultas de memória usam `fetchall`; relatórios materializam suas linhas em memória. O grafo limita arestas, mas preserva findings e usa layout recursivo. Isso identifica pontos de crescimento, não comprova lentidão em produção ou esgotamento de memória.

**Plano:**

- Medir consultas de histórico e exportação com conjuntos sintéticos de tamanhos crescentes, sem gerar tráfego de teste externo.
- Definir retenção, arquivamento, paginação e índices derivados das consultas reais — por exemplo, analisar índices para run/host/tempo e findings por run.
- Definir limites explícitos de nós e profundidade do renderizador; exportar o conjunto completo separadamente quando a visualização for reduzida.
- Evitar que renderização ou exportação custosa bloqueie controles de cancelamento. Medir antes de introduzir threads ou processos.
- Reutilizar a migração versionada definida no lote de persistência. As otimizações de escala não devem criar uma segunda estratégia de migração. `CREATE TABLE IF NOT EXISTS` não é uma estratégia de evolução de schema.

**Aceite:** publicar ambiente, volume de dados, latência das consultas, tempo de exportação e pico de memória; não impor promessas universais sem medição. A interface permanece utilizável e explica qualquer redução da visualização.

### R20 — Avaliação e significado da “inteligência”

**Evidências:**

- `tests/benchmark/bench_adaptive.py` constrói `ScanOptions` com `wordlist_path`, enquanto o modelo atual declara `wordlist_paths`. A chamada ao construtor foi verificada isoladamente e lançou `TypeError`; o benchmark completo não foi executado.
- O cenário do benchmark foi construído para que os recursos relevantes estejam acessíveis por pistas que a estratégia adaptativa consome. Ele demonstra um cenário escolhido, não superioridade geral ou precisão em ambientes reais.
- `origami/core/response_classifier.py:312` descreve `_confidence` como heurística. Exibir `0.90` não demonstra 90% de chance de vulnerabilidade nem severidade.
- A memória aprende a partir de observações da própria ferramenta; não há no esquema examinado um processo de revisão humana com rótulos, procedência e conjuntos de avaliação independentes.

**Plano:** revisar as alegações de qualidade antes de usá-las como argumento de produto. Distinguir teste de compatibilidade da API, demonstração de cenário e avaliação representativa. Para a futura assistência de análise, construir avaliação offline de relatórios e evidências previamente disponibilizados, com respostas revisadas por pessoas, ambiguidades e casos sem conclusão. Manter dados de avaliação separados de dados usados para ajustar o componente de análise.

**Aceite:** documentação explica o que foi medido e o que não foi; score heurístico tem nome e explicação adequados; sugestões de triagem são avaliadas por correção factual, referências à evidência, abstenção e tempo de revisão humana. Não usar quantidade de achados, aprovação pela própria IA ou um cenário selecionado como prova de precisão.

## O que falta para ser um app robusto, bom e inteligente

### 1. Um projeto como unidade de trabalho

Hoje a CLI recebe opções, processa alvos e compartilha um banco global por padrão. Para trabalho recorrente, o usuário precisa abrir um projeto e entender seu estado sem reconstruir o comando anterior.

**Proposta de produto:** projeto com nome, limites autorizados, referências a credenciais, política de transporte, retenção, configurações versionadas e execuções anteriores. Não guardar credenciais em texto no arquivo do projeto. A configuração deve ter precedência documentada entre defaults, projeto e flags, com uma visão sanitizada do resultado efetivo.

**Fluxo desejado:** abrir projeto → conferir configuração efetiva → acompanhar execução → revisar evidências → exportar entrega → comparar execução compatível.

**Pronto quando:** o mesmo projeto pode ser retomado em outro momento com suas decisões e avisos intactos, e o operador sabe qual configuração gerou cada artefato. Migrar dados globais antigos exige escolha explícita do projeto de destino.

### 2. Uma execução durável e explicável

O estado deve ser persistido e ter significado único em CLI, interface e relatório. Para evitar ambiguidade, separar ciclo de vida de cobertura:

| Estado proposto | Significado |
|---|---|
| Preparada | Configuração validada; ainda sem atividade de rede |
| Em execução | Trabalho em andamento dentro da configuração registrada |
| Encerrando | Cancelamento solicitado; recursos e evidências sendo finalizados |
| Concluída | Orquestração encerrada; a cobertura é indicada em campo próprio |
| Falhou | Erro impediu a execução solicitada |
| Cancelada | Encerramento solicitado pelo operador |

O campo de cobertura usa `complete`, `partial` ou `unknown`, com motivos. Uma execução cancelada pode ter evidências parciais úteis; uma execução concluída pode ter etapas puladas. “Complete” significa apenas que o trabalho solicitado e registrado foi concluído, sem afirmar cobertura de toda a aplicação. A interface deve mostrar combinações como “Concluída — cobertura parcial”.

Exportação tem estado próprio: sucesso de execução e sucesso de entrega são coisas distintas. O app deve permitir **reexportar sem repetir rede**. Relatório precisa indicar o que foi executado, pulado, limitado ou indisponível, sem inferir cobertura sobre superfícies não observadas.

**Pronto quando:** interrupção não deixa o usuário sem saber onde parou; abrir uma execução antiga mostra estado, avisos e evidências; executar novamente é uma decisão explícita.

### 3. Evidência preservada, apresentação reversível

Uma observação deve ter identidade estável, run de origem, instante, método/origem sanitizados, status, metadados da resposta, indicação de truncamento, regra/versão responsável pela interpretação, notas e referências à evidência. Acesso ao conteúdo bruto sensível depende de política de retenção; hashes e resumos não substituem conteúdo quando ele é necessário para sustentar a conclusão.

Agrupar, ocultar ou marcar como ruído são decisões de apresentação/revisão registradas separadamente. O usuário precisa conseguir abrir os membros de um grupo, recuperar um item oculto e exportar somente os itens revisados. Não remover observações silenciosamente porque uma análise posterior discordou delas.

**Pronto quando:** cada afirmação da entrega aponta para evidência recuperável; o item sobrevive a reinício, retomada e exportação sem perder notas/contexto; esconder um item na interface não o apaga da execução.

### 4. Inteligência voltada à análise, com explicação e abstenção

O projeto já possui heurísticas, memória, associação, n-gramas e bandit. Isso não resolve sozinho a pergunta do usuário: “por que devo acreditar neste resultado?”. A camada de análise deve começar por regras explicáveis e pelas evidências existentes.

| Capacidade proposta | Benefício ao operador | Limite necessário |
|---|---|---|
| Explicação por observação | Mostra qual evidência sustenta a interpretação | Cada afirmação aponta para evidência identificável |
| Separação entre fato e hipótese | Evita levar indícios ao relatório como conclusões | Campo explícito de incerteza/limitação |
| Agrupamento reversível de evidências | Reduz trabalho repetitivo de leitura | Conserva os membros e a justificativa do agrupamento |
| Comparação de execuções compatíveis | Destaca mudanças efetivamente observadas | Ausência de cobertura não vira desaparecimento |
| Memória de revisão por projeto | Recupera decisões e notas do operador | Não mistura clientes nem usa rótulos de outro contexto silenciosamente |
| Resumo de execução | Ajuda a preparar a entrega | Descreve também falhas, limites e pendências |

**LLM é opcional:** pode explicar e resumir evidências sanitizadas, sem ter autoridade para mudar escopo, enviar requisições, executar comandos ou promover hipótese a achado confirmado. Conteúdo de páginas, comentários e arquivos analisados é dado não confiável, nunca instrução para o assistente. O componente deve funcionar com acesso apenas de leitura aos artefatos selecionados, sem segredos por padrão, com opt-in para envio a serviço externo e com operação básica disponível sem IA.

Uma saída útil contém: afirmação, referências, limites e grau de certeza descrito em linguagem clara. Se faltam evidências, a resposta correta é “inconclusivo”. A sugestão da IA não deve se transformar automaticamente em rótulo de treinamento nem apagar o resultado original.

**Pronto quando:** em conjunto offline revisado por humanos, as explicações são factualmente sustentadas, reconhecem casos inconclusivos e economizam tempo de análise. Não é necessário adicionar um modelo para começar: procedência e explicações determinísticas já têm valor.

### 5. Uma interface centrada nas decisões do usuário

O terminal atual é útil para acompanhamento. Uma futura interface local deve começar pelo fluxo de revisão, apoiada no mesmo serviço de aplicação da CLI, sem reescrever toda a ferramenta.

**Hipótese de navegação a validar posteriormente, com quatro áreas:**

1. **Projeto:** configuração efetiva sanitizada, limites, retenção e credenciais apenas por referência.
2. **Execuções:** estado, duração, métricas com unidade clara, avisos, motivo da parada e exportação.
3. **Revisão:** observações, grupos expansíveis, evidências, filtros, notas, tags humanas e comparação compatível.
4. **Entrega:** seleção de itens revisados, visualização do conteúdo sanitizado, formatos e histórico de exportações.

Não há decisão necessária agora entre aplicação desktop e serviço web local. Primeiro estabilizar serviço de aplicação e contratos. Se houver servidor local, restringir bind a loopback por padrão, proteger ações contra requisições de outras origens e tratar relatórios/conteúdo importado como não confiável.

**Pronto quando:** o usuário consegue entender uma execução antiga, corrigir uma anotação e gerar uma entrega sem consultar logs dispersos ou editar banco. Controles de teclado, labels, foco e estados vazios/erro fazem parte do aceite.

### 6. Diagnóstico previsível e suporte

Adicionar diagnóstico local de versão, diretórios, permissões, dependências opcionais, formato de configuração e integridade do banco. O diagnóstico padrão deve ser offline; qualquer checagem que conecte a proxy/host deve ser separada e explícita.

Um pacote de suporte pode conter versões, stack traces sanitizados, eventos de erro, configuração sem segredos e IDs de execução. Não deve carregar corpos de resposta, cookies, tokens ou informações de cliente sem seleção consciente. Faltas de dependência precisam aparecer antes do início da execução e também no resultado estruturado.

**Pronto quando:** é possível explicar por que uma execução falhou sem pedir ao usuário todo o diretório de evidências nem expor credenciais.

### 7. Medidas de qualidade que realmente ajudam

| Dimensão | Medida proposta | Como validar |
|---|---|---|
| Integridade | Preservação dos campos de evidência | Round-trip entre memória, checkpoint, eventos e exportação |
| Recuperação | Janela de perda e tempo para encerrar | Falhas/cancelamentos controlados com I/O simulado |
| Contratos | Coerência de estado e códigos de saída | Matriz de entrada, erro, parcial, cancelado e sucesso |
| Privacidade | Ausência de credenciais nas saídas permitidas | Sentinelas sintéticas e inspeção de todos os formatos |
| Escopo | Nenhum envio fora da política de origem | Transporte simulado que registra todas as decisões |
| Usabilidade | Tempo para entender e entregar uma execução | Tarefas de revisão com usuários e artefatos fixos |
| Análise assistida | Correção factual e qualidade das referências | Corpus offline separado, revisão humana e casos ambíguos |
| Escala local | Latência, memória e tempo de exportação | Bases sintéticas e ambiente de medição declarado |

Estabelecer uma linha de base antes de definir metas numéricas. Garantias de integridade, privacidade e escopo devem ter casos obrigatórios de aprovação; médias boas não compensam uma regressão nesses contratos. Alterações no componente de análise precisam ser comparadas com a versão anterior, mantendo registros e método de avaliação.

### Arquitetura sugerida, sem reescrita geral

Evoluir por extrações pequenas a partir da estrutura atual:

| Camada | Responsabilidade | Ponto de partida |
|---|---|---|
| Configuração e política | Projeto, origem, limites, credenciais por referência | `cli.py`, `scope.py`, `credentials.py` |
| Serviço de execução | Ciclo de vida, cancelamento, etapas e estado final | Orquestração em `core/scanner` |
| Transporte | Política central de envio, métricas e fechamento | `core/httpclient.py` |
| Persistência | Runs, observações, eventos, revisão, migrações e retenção | `brain/memory.py`, `core/resume.py` |
| Análise de artefatos | Explicações e resumos sobre evidências existentes | Novo componente com interface apenas de leitura |
| Apresentação | CLI, UI local e exportadores como consumidores | `output/`, `cli.py` |

SQLite pode continuar como armazenamento local; não há evidência nesta revisão que justifique introduzir microserviços ou infraestrutura distribuída. Preservar os módulos existentes e migrar os contratos de infraestrutura antes de ampliar a interface.

## Contratos de compatibilidade e migração

Estas regras devem orientar os patches antes de mudar formatos ou defaults. São decisões propostas para a implementação futura; nenhuma foi aplicada nesta revisão.

| Superfície | Regra da primeira entrega |
|---|---|
| JSONL atual | Preservar registros de findings. Avisos e finalização ficam em stderr/manifesto; formato de eventos completo só como opção separada |
| JSON/HTML | Acrescentar estado, avisos e versão sem remover campos existentes; mudanças de significado exigem nova versão e documentação |
| Códigos de saída | `0` reservado a sucesso completo das saídas solicitadas; preservar `2` para erro de entrada/execução já usado e `130` para Ctrl-C; propor código distinto para execução parcial/falha de exportação e testar consumidores antes de publicar |
| Banco legado | Preservar em backup consistente, reconhecer versão e migrar de forma transacional; valores históricos ausentes ficam desconhecidos, nunca inventados |
| Checkpoint legado | Validar alvo e esquema antes de migrar uma cópia. Se informação obrigatória faltar, recusar a retomada com diagnóstico e conservar o arquivo |
| `--no-learn` | Continuar sem acesso ao banco de memória. Política de saída/checkpoint deve ser descrita separadamente; não transformar persistência de relatório em aprendizado |
| TLS e escopo | Documentar defaults mais restritivos e caminhos explícitos de configuração. Não aplicar fallback para rede direta, nem ampliar a origem autorizada por conveniência |
| Arquivos existentes | Nenhuma validação ou inicialização pode truncá-los. Sobrescrita deliberada só após validação, com política definida; JSONL de retomada precisa separar runs ou validar o arquivo antes de anexar |

**Código de saída não substitui o manifesto:** se vários alvos terminarem com estados diferentes, guardar o resultado de cada um e calcular um agregado determinístico. Erro de configuração global impede toda a execução. Cancelamento solicitado encerra a lista. Falha recuperável de um alvo só permite continuar se armazenamento, política e recursos compartilhados permanecerem íntegros. Não capturar toda exceção como se fosse recuperável.

### Matriz de retomada

| Mudança | Tratamento proposto |
|---|---|
| Alvo/origem/projeto diferente | Recusar reutilização do estado |
| Ampliação de escopo ou troca de identidade | Não retomar automaticamente; exigir nova execução/contexto compatível |
| Alteração de credencial mantendo o rótulo | O rótulo não prova equivalência. Exigir referência/versionamento explícito da identidade; registrar a troca e não reutilizar conclusões dependentes da sessão sem política definida |
| Aumento de orçamento | Permitir explicitamente, mantendo contadores anteriores; documentar se o limite de tempo se refere à invocação atual ou ao total |
| Redução do orçamento abaixo do consumido | Encerrar como parcial, sem novos envios |
| Mudança de apresentação/destino de exportação | Permitir sem repetir rede; preservar dados de origem e registrar o novo destino |
| Mudança de configuração que altera o trabalho pendente | Recusar por padrão; permitir apenas exceções documentadas e testadas |
| Mais de um checkpoint compatível | Mostrar candidatos e exigir seleção explícita |

**Rollback:** validar e fazer backup consistente do SQLite, incluindo o estado do WAL, antes de migrar. Falha durante a migração deve reverter a transação. Restaurar um backup antigo depois de novas gravações perde dados posteriores; por isso, preservar ambos e não prometer downgrade automático. Uma versão antiga do programa deve recusar escrita em schema mais novo, sem tentar repará-lo ou apagá-lo. Artefatos externos exportados também não são revertidos por rollback do banco.

## Sequência de execução revisada

### Lote 1 — Correções localizadas que evitam perda e erro silencioso

**Dependência:** nenhuma mudança de arquitetura ou de banco.

- [ ] R11: corrigir apenas o erro de tipo confirmado e manter o gate; tipagem abrangente fica para manutenção posterior.
- [ ] R10/R15: validar entradas antes de abrir JSONL/banco/clientes; fechar recursos adquiridos parcialmente; preservar saídas existentes em erro de configuração.
- [ ] R05/R06: manter stdout válido, retornar falhas de cada saída e produzir código de saída coerente.
- [ ] R06/R15: não remover checkpoint antes de confirmar persistência/entrega; nesta etapa conservar a recuperação disponível, sem alegar que o checkpoint contém todo o estado final.
- [ ] R15: rollback local de transações com falha e fechamento de clientes/tarefas, sem refatorar os módulos de análise.
- [ ] R17: corrigir ajuda/diagnóstico de exclusão seletiva e documentar isolamento com `--db`, sem apagar agregados legados silenciosamente.

**Aceite:** configuração inválida não toca no conteúdo anterior; falha de saída é visível no retorno; clientes falsos são fechados em falhas intermediárias; transação abortada não pode ser confirmada pela operação seguinte. Regressões correspondentes falham antes e passam depois do patch.

**Entrega:** correção incremental publicável. Não declarar ainda que toda a retomada é fiel ou que a exclusão seletiva remove todos os derivados.

### Lote 2 — Credenciais, origem, transporte e privacidade

**Dependência:** validação e tratamento de recursos do lote 1.

- [ ] R01/R02: adotar uma representação comum de origem; separar autorização de agrupamento de domínio e de chave histórica.
- [ ] R01/R03: vincular credenciais à origem, centralizar redação e separar política TLS principal/replay.
- [ ] R08: definir tentativas reais versus operações lógicas e aplicar o orçamento/deadline no ponto de envio. Clientes auxiliares devem obedecer a mesma política ou ter exceção explícita registrada.
- [ ] R09: criar arquivos privados desde a abertura; não depender apenas de chmod posterior ou mudar permissões de diretórios arbitrários.
- [ ] R18: validar completude e formato do catálogo antes da ativação, com escrita atômica em área de dados e preservação da última versão válida.

**Aceite:** transporte simulado registra zero envio fora da política; sentinelas de credenciais não aparecem em destinos/saídas não autorizados; retry respeita teto e deadline; atualização parcial não troca o catálogo ativo. Compatibilidade de TLS/proxy é documentada, sem fallback direto silencioso.

**Entrega:** camada de I/O com contratos defensivos verificáveis. Não depende de interface gráfica nem de sistema completo de projetos.

### Lote 3 — Definir o resultado e então migrar persistência/retomada

**Dependência:** contratos de origem e I/O dos lotes 1–2. A definição abaixo precede a alteração de schema.

- [ ] R04/R07/R13/R16: especificar o resultado mínimo: versão, run, alvo/configuração, ciclo de vida, cobertura, motivos, avisos, observações com IDs, notas/tags e metadados de evidência sanitizados.
- [ ] Implementar esse contrato como snapshot persistido. Um histórico integral de eventos não é requisito.
- [ ] R04/R06: distinguir chave de alvo, ID de run e nomes de artefatos; aplicar matriz de retomada e bloqueio de escritor concorrente.
- [ ] R04/R13/R15: preservar campos necessários na retomada e unificar sua finalização com a execução nova; persistir o resultado final antes de limpar recuperação.
- [ ] R07/R15: registrar paradas, prefixos pulados, falhas e cancelamento; exportação tem resultado próprio.
- [ ] R09/R17: introduzir namespace de projeto na persistência e procedência dos novos derivados, com tratamento explícito do agregado legado.
- [ ] Aplicar migração/rollback conforme a seção anterior; testar banco e checkpoint antigos com fixtures sanitizadas.

**Aceite:** round-trip mantém os campos contratados; reabrir snapshot não requer rede; ambiguidade de checkpoint é diagnosticada; perda durante cancelamento não excede a garantia documentada; migração que falha deixa a versão anterior íntegra. Dados legados ausentes são marcados como desconhecidos.

**Entrega:** resultado durável e recuperável. Reexportação offline pode começar aqui, sem aguardar uma interface nova.

### Lote 4 — Exportação fiel e comparação conservadora

**Dependência:** snapshot e estado do lote 3.

- [ ] R12: comparar somente baselines compatíveis; ausência de observação não vira desaparecimento confirmado.
- [ ] R13: apresentar notas, limitações, estado e timestamps; tratar texto externo como literal; corrigir a indicação de corpo no limite.
- [ ] R16: manter membros de agrupamentos no snapshot e produzir visões reversíveis; esclarecer enriquecimentos sem quebrar JSONL existente.
- [ ] R06/R07: exportar formatos independentes com manifesto por artefato e poder repetir exportação a partir do snapshot.
- [ ] Preservar formatos anteriores conforme contrato; testar consumidores com arquivos fixos, sem rede.

**Aceite:** JSON, HTML e histórico concordam sobre os dados de origem e suas limitações; filtro visual não apaga observação persistida; falha em um formato não impede outros; entrega parcial não aparece como sucesso completo.

**Entrega:** pacote de evidências confiável para revisão e entrega manual.

### Lote 5 — Fluxo mínimo de projeto e revisão pela CLI

**Dependência:** lotes 3–4. Pode reaproveitar as opções existentes antes de introduzir novos comandos.

- [ ] Configuração de projeto versionada, com referências a credenciais e precedência explícita: defaults → projeto → flags.
- [ ] Visão sanitizada das opções efetivas, catálogo de execuções e abertura de snapshot sem rede.
- [ ] Notas/status de revisão humana separados das observações originais; exclusão do projeto cobre dados derivados atribuíveis.
- [ ] Diagnóstico offline de ambiente e integridade de dados, com saída sanitizada.
- [ ] Explicações determinísticas das observações, limitadas à evidência que realmente foi preservada.

**Aceite:** abrir projeto → inspecionar execução anterior → anotar → exportar pode ser feito sem conexão e sem editar SQLite manualmente. A exclusão descreve e verifica seu alcance, incluindo a exceção dos dados legados não atribuíveis.

**Entrega:** primeira versão de produto útil ao trabalho recorrente. Interface gráfica e IA não fazem parte deste aceite.

### Lote 6 — Qualificação da versão e documentação

**Dependência:** validar o recorte efetivamente entregue; este lote não pode adiar testes de regressão dos lotes anteriores.

- [ ] R14: instalação limpa do wheel, recursos empacotados, dependências diretas, versões/plataformas suportadas e migrações.
- [ ] Reexecutar Ruff/Mypy e testes de infraestrutura afetados; executar o teste de socket pendente em ambiente adequado.
- [ ] Registrar separadamente os módulos e cenários que não foram validados; não apresentar o gate de infraestrutura como aprovação de todos os detectores.
- [ ] R20: corrigir a documentação das alegações e marcar o benchmark identificado como incompatível/inválido como evidência até sua manutenção específica; avaliação do componente de análise continua offline.
- [ ] Changelog com mudanças de códigos de saída, defaults, persistência e compatibilidade; procedimento de recuperação documentado.

**Aceite:** instalar fora do checkout, importar recursos, ler dados migrados e reexportar fixtures funciona no ambiente suportado; limitações conhecidas aparecem no release. Não adiar a documentação de breaking changes para depois da publicação.

### Evolução posterior, fora do escopo mínimo

- **R19 — Escala:** medir histórico, relatórios e memória em volumes representativos. Só então selecionar índices, paginação ou processamento em segundo plano. `SCAN` em plano SQL é um candidato a investigação, não um blocker isolado.
- **R14 — Refatoração ampla:** extrair componentes apenas onde as mudanças anteriores revelarem acoplamento que dificulta testes/manutenção. Contagem de linhas sozinha não justifica reescrita.
- **Formato integral de eventos:** adotar apenas se consumidores precisarem de replay incremental além dos snapshots. Não é condição para relatórios confiáveis.
- **Interface local:** validar o fluxo de quatro áreas com artefatos offline e usuários antes de escolher desktop/web ou framework.
- **LLM:** experimento separado para explicação/resumo de evidências sanitizadas, com conjunto de avaliação independente e comparação com explicações determinísticas. Prosseguir somente com benefício mensurado e política de dados definida.

## Matriz mínima de aceite

Cada linha deve virar regressão no lote indicado. São critérios propostos, não testes já implementados.

| ID | Lote | Cenário | Resultado exigido |
|---|---|---|---|
| A01 | 1 | JSONL existente + configuração inválida | Conteúdo anterior intacto; nenhum cliente/recurso residual |
| A02 | 1 | Um destino de saída falha | Outras saídas independentes tentadas; retorno de erro e diagnóstico por artefato |
| A03 | 1 | Segundo cliente falha ao abrir | Primeiro cliente fechado; erro propagado; sem iniciar execução |
| A04 | 1 | Falha no meio de uma transação | Rollback da operação; próxima escrita não confirma registro parcial |
| A05 | 1/4 | JSONL stdout combinado com arquivos e avisos | Todas as linhas de stdout mantêm o contrato de findings |
| A06 | 2 | Outra origem e credencial sintética | Sem envio de credencial/solicitação fora da política |
| A07 | 2 | Retry, prazo expirado e concorrência | Teto de tentativas respeitado; nenhuma nova tentativa após prazo |
| A08 | 2 | Umask permissiva e catálogo parcial | Evidência privada desde criação; catálogo íntegro anterior preservado |
| A09 | 3 | Checkpoint corrompido, ambíguo ou de outro alvo | Recusa controlada antes de rede; arquivo anterior preservado |
| A10 | 3 | Retomada com orçamento maior ou formato diferente | Permitida conforme matriz; contadores e contexto preservados |
| A11 | 3 | Cancelamento/erro de persistência | Estado e limite da recuperação explícitos; última gravação íntegra conservada |
| A12 | 3 | Migração falha e versão antiga abre schema novo | Rollback da migração; versão incompatível recusa escrita |
| A13 | 4 | Snapshot com notas, grupos e limitações | Exportadores preservam conteúdo e mostram estado coerente |
| A14 | 4 | Execução parcial ou baseline incompatível | Não afirma desaparecimento ou conclusão global |
| A15 | 5 | Exclusão de projeto com derivados atribuíveis | Sentinelas removidas do escopo gerido; legado explicado separadamente |
| A16 | 5/6 | Abrir/anotar/reexportar execução persistida | Nenhuma chamada de rede; resultado compatível após instalação limpa |

Para cada patch: registrar teste que falha no estado anterior, alteração, resultado posterior e limitação remanescente. Dados de teste devem ser sintéticos ou sanitizados. A revisão não exige recriar tráfego de exploração para validar esses contratos de infraestrutura.

## Critério de encerramento

**Correções imediatas concluídas:** lotes 1–2 entregues com seus critérios de infraestrutura, limitações documentadas e compatibilidade revisada. Isso permite publicar correções sem esperar por todo o roadmap.

**Base confiável de execução/entrega concluída:** lotes 3–4 entregues, com snapshot versionado, retomada compatível, exportação recuperável, estado/cobertura explícitos e migrações verificadas.

**Primeiro app de trabalho recorrente concluído:** lote 5 entregue e qualificado pelo lote 6. GUI, LLM, otimizações sem medição e refatoração geral não bloqueiam esse marco.

Os IDs do backlog não significam implementação concluída. Os testes reportados nas passagens anteriores não provam as garantias ainda propostas, nem precisão dos detectores ou impacto de segurança em sistemas externos.
