# Execução das correções defensivas

Base: `16295d8`; plano: `13c2707`. Commits locais por etapa, sem push.

## Etapa 1 — Entradas, recursos e transações

Implementado:

- Validação antecipada de números, URLs HTTP(S), cabeçalhos e arquivo de proxies.
- Cabeçalhos repetidos são tratados sem distinção de caixa; erros de sintaxe não imprimem seu valor.
- Arquivos e memória ficam sob `ExitStack`, inclusive em falhas de inicialização.
- Fechamento de clientes parcialmente construídos e tentativa de fechar todo o pool.
- Rollback das operações de escrita do SQLite ao ocorrer exceção.
- Correção da anotação que bloqueava Mypy; interrupção escreve diagnóstico em stderr.

Validação: 17 testes de infraestrutura passaram; Ruff passou; Mypy passou em 65 arquivos; `git diff --check` passou. As regressões novas falharam antes das correções. Não houve varredura externa.

## Etapa 2 — Saídas e arquivos privados

Implementado:

- Substituição atômica UTF-8 para relatórios e checkpoints, usando temporários exclusivos privados.
- Banco, sidecars SQLite, diretórios novos e arquivos de credenciais com permissões privadas; diretórios ancestrais existentes não sofrem chmod.
- JSONL usa arquivo novo: um caminho existente é recusado em vez de truncado. Stdout continua reservado aos findings nesse modo.
- Cada formato de saída é tentado independentemente. Bundles incluem `manifest.json` com arquivos gravados e erros; arquivo antigo não listado como gravado não pertence à exportação atual.
- Saída incompleta/execução parcial retorna código 3; falha de exportação preserva o checkpoint. Falhas no sink não são suprimidas por `_guard`.
- Nomes de artefatos por alvo incluem digest de URL para evitar colisões.
- JSON inclui versão de formato, estado, conclusão, erros, contadores e dados de relatório; HTML inclui notas escapadas, estado e rótulo do filtro.
- Cobertura é explicitamente desconhecida quando a orquestração terminou: o indicador `completed` ainda não comprova cobertura de todas as etapas.

Validação: 38 testes de infraestrutura passaram; Ruff e Mypy passaram; `git diff --check` passou. Permissões foram verificadas sob umask permissiva. Nenhuma alteração no formato dos registros do JSONL.

Limitação: preservar o último checkpoint não equivale a salvar todo o estado em RAM. Não foi alterada a lógica de retomada nem implementada migração do schema do banco.

## Etapa 3 — Credenciais e transporte

- Cabeçalhos configurados ficam vinculados à origem exata do alvo: esquema, host e porta efetiva. IPv6 e portas distintas não compartilham identidade.
- Hooks removem cabeçalhos configurados e credenciais reconhecidas antes de requisições fora dessa origem, inclusive redirecionamentos. Clientes auxiliares direcionados ao alvo também recebem essa proteção.
- Valores de cabeçalhos e senhas de proxies não aparecem no preâmbulo de configuração; mensagens de replay usam rótulos sem credenciais.
- TLS é verificado por padrão na biblioteca. O parâmetro de replay isoladamente não desativa a verificação; falhas de handshake não provocam downgrade automático.
- A opção explícita de TLS legado continua disponível. O comportamento existente de desativar verificação com proxy principal permanece documentado.
- Ajuda e aviso de `--forget` esclarecem que estatísticas compartilhadas antigas permanecem; não foi simulada uma exclusão completa por host.

Validação: 45 testes de infraestrutura passaram; Ruff passou; Mypy passou em 67 arquivos; `git diff --check` passou. Transporte simulado em memória; nenhum teste contra alvo externo. A suíte completa de módulos ofensivos não foi executada.

Limitações: a proteção de cabeçalhos não é uma política completa de escopo de rede. Não há sanitização universal dos corpos de evidências ou de toda mensagem de erro. Chamadores da biblioteca que enviam cabeçalhos precisam definir `credential_origin` explicitamente.

## Etapa 4 — Revisão offline de evidências

- Novo comando independente `--review-report FILE`, sem tráfego, scanner, execução de comandos de reprodução ou acesso ao banco.
- Resumo JSON com SHA-256 dos bytes originais, estado, status HTTP, notas ausentes, corpos vazios e registros repetidos. Não imprime URLs, notas ou comandos da origem.
- Leitura limitada a 32 MiB; recusa arquivos especiais, JSON ambíguo, formatos futuros e inconsistências nos campos usados pelo resumo.
- Relatórios antigos continuam com estado desconhecido; nenhum achado é promovido automaticamente a vulnerabilidade confirmada.
- Fonte preservada sem alterações. Códigos de saída documentados: 0 para estado finished, 3 para parcial/falha/legado, 2 para entrada inválida.

Validação: 55 testes locais passaram, incluindo leitura sem scanner/banco/stdin, preservação do arquivo, diagnóstico sem segredos, limites e rejeição de FIFO sem bloqueio. Ruff e Mypy passaram. Sem tráfego externo.

Limitação: resumo descritivo; não valida todos os campos do relatório nem substitui revisão humana, corpus rotulado, reexportação ou gerenciamento de projetos.

## Etapa 5 — Preservação e recuperação do histórico

Reproduzido antes da correção: `prune_fingerprinted` apagava achados históricos; uma falha em `forget` deixava transação parcial aberta. Dois testes falharam por esses defeitos. Outros dois demonstraram ausência da capacidade de snapshot integral.

Corrigido: limpeza atua apenas no corpus derivado; exclusão por host ou total é transacional; snapshots completos são persistidos junto com o registro da execução. Falha no snapshot desfaz a execução inteira. Migração aditiva cria tabela sem fabricar dados para execuções antigas. Novo `--export-run ID --db DB --json NOVO` recupera o snapshot sem scanner e com conexão somente leitura. IDs aparecem no histórico.

Validação: 44 testes locais passaram, incluindo oito regressões novas; Ruff e Mypy passaram (69 arquivos). Limites: snapshots aumentam o banco; registram o instante da persistência e dependem de memória habilitada; não recuperam campos antigos perdidos nem substituem um journal contra término abrupto. Exclusão lógica não promete sanitização do armazenamento.

## Etapa 6 — Comparação sem falsas conclusões

Cinco regressões falharam antes da correção: perda da identidade de consultas, ausência tratada como remoção, mudança de status tratada como novo acesso, observações conflitantes sobrescritas e baseline de outra porta. Corrigidos o armazenamento da visão de comparação, seleção por URL-base exata e apresentação do diff. Nenhuma requisição adicional foi introduzida.

Validação: 51 testes locais passaram; Ruff e Mypy passaram. O diff agora usa `new`, `unobserved`, `changed` e `ambiguous`. Equivalência de autenticação, filtros e cobertura permanece desconhecida; não é uma confirmação de correção ou de mudança de autorização.

## Etapa 7 — Confirmação de exportação consistente

A exportação anterior podia substituir arquivos e falhar ao gravar o manifesto, deixando o marcador antigo de sucesso. A regressão de preservação do conjunto anterior falhou antes da correção. Agora um manifesto incompleto é persistido antes de qualquer substituição; a confirmação final lista apenas arquivos gravados, com SHA-256 e tamanho. Falha na invalidação inicial preserva os artefatos anteriores; falha final mantém o estado incompleto.

Validação consolidada: 73 testes locais passaram; Ruff passou; Mypy passou em 69 arquivos. Inclui falhas injetadas nas gravações inicial/final e comparação dos hashes com os bytes reais. O ajuste de tipos da etapa 6 está em commit adicional. Não foi executada a suíte de exploração nem tráfego externo.

Limites: hashes não são assinatura; exportações concorrentes no mesmo diretório não são suportadas; arquivos antigos não listados podem permanecer; a durabilidade da entrada de diretório após falha elétrica não está garantida.

## Etapa 8 — Evidência literal no terminal

Cinco regressões falharam antes da correção: notas com markup inválido derrubavam tanto o relatório Rich quanto o streaming; logs, texto simples e diff transmitiam controles de terminal. A apresentação agora escapa markup e torna caracteres de controle/formatação visíveis, mantendo o JSON original. Progresso, badges, diretórios e cabeçalhos usam a mesma proteção. O encerramento da UI deixa de afirmar conclusão do scan sem receber seu estado.

Validação: 80 testes locais passaram, incluindo sete regressões de apresentação; Ruff e Mypy passaram (70 arquivos). Limite: proteção de renderização não é remoção de segredos; a CLI ainda possui mensagens fora dos observers que exigem revisão própria.

## Etapa 9 — Manutenção sem efeitos inesperados

Seis regressões falharam antes da correção: histórico criava banco ausente, migrava banco legado, exclusão deixava conexão aberta ao falhar, exclusão criava banco ausente, banco corrompido escapava como traceback e combinação de histórico/exclusão era silenciosamente aceita. Corrigido com leitura somente leitura, checagem de existência, context managers, rejeição de modos conflitantes e erros locais de manutenção com código 2. Histórico também escapa controles de terminal.

Validação consolidada: 86 testes locais passaram; Ruff e Mypy passaram (70 arquivos). O teste legado compara os bytes do banco antes/depois. Nenhum teste de rede ou exploração foi executado. As mudanças não corrigem a identidade compartilhada legada dos dados de aprendizado nem representam isolamento completo por projeto.

## Etapa 10 — Colisões de caminhos de saída

Regressões demonstraram ausência de rejeição antes de abrir recursos para caminhos conflitantes. Agora são enumerados os destinos efetivos (incluindo grafo, bundle e nomes de múltiplos alvos) e comparados com entradas, banco/sidecars, checkpoints, credenciais e catálogos. A validação resolve symlinks, compara inodes existentes e detecta conflitos arquivo/diretório. Layouts independentes não criam arquivos durante a checagem.

Validação: 12 testes específicos passaram; suíte anterior com oito desses testes totalizou 94 testes aprovados; Ruff e Mypy passaram (71 arquivos). Limite: é uma verificação prévia, não uma proteção contra mudanças concorrentes no filesystem. A lógica de checkpoints/retomada não foi ampliada.

## Etapa 11 — Exclusão de escritores concorrentes de bundles

Duas regressões falharam antes da correção: uma reserva existente era ignorada e um segundo escritor podia entrar durante a exportação. A pasta agora tem uma reserva atômica `.origami-export.lock`, obtida antes de alterar o manifesto e liberada por `finally`. Reservas alheias nunca são removidas. Teste de interrupção verifica liberação e possibilidade de nova exportação. Também foram tratados caminho irresolúvel e modo sem saída em arquivo na validação anterior.

Validação consolidada: 103 testes locais passaram; Ruff e Mypy passaram (71 arquivos). Sem rede. Limite: término não capturável pode deixar reserva obsoleta; após confirmar que não há escritor ativo, remover apenas a pasta vazia de reserva ou escolher outro destino. Não há recuperação automática dessa reserva nem garantia contra alteração hostil concorrente no filesystem.

## Etapa 12 — Observações preservadas e interpretação de repetição

O log fornecido levou a seis regressões: perda de URLs no agrupamento do JSON/snapshot, mutação das notas originais, retenção antiga desconhecida e afirmações incorretas sobre igualdade de corpos/confiança. As seis falharam antes da correção. Novos snapshots de eventos aceitos em `reported_observations` preservam esses dados sem alimentar descoberta; `findings` mantém a visão existente. Rótulos passam a explicar a base heurística do agrupamento e do score.

Validação: 109 testes locais de infraestrutura, incluindo as seis regressões, e 13 testes adicionais de compatibilidade de dedup/apresentação passaram; Ruff e Mypy passaram (71 arquivos). Não houve tráfego para o domínio do log nem alteração da geração ou seleção de requisições.

Limites: retenção no processo atual, depois dos filtros/dedup de emissão; não representa todos os responses, corpos HTTP brutos ou recuperação de eventos anteriores à retomada. Captura no instante de emissão, sem sobrescrever a nota com enriquecimento posterior. Aumenta memória e tamanho dos relatórios. O score permanece heurístico, agora identificado como tal.

## Etapa 13 — Prévia de negações e detalhes de observações

Duas regressões falharam antes da correção: tamanhos distintos reiniciavam a enxurrada de negações na UI e o HTML só continha a representante agrupada. A prévia Rich/plain agora mostra até quatro negações inferidas por status 401/403, com total oculto; entradas de contrato declarado mantêm visibilidade. Avisos de agrupamento deixam de repetir por tamanho. Uma seção expansível do HTML conserva URLs e notas de emissão escapadas, e a legenda do score aparece na CLI/relatório.

Validação: 125 testes consolidados passaram; mais dois testes específicos de terminal plain/avisos passaram depois. Ruff e Mypy passaram. Limites: mudanças exclusivamente de diagnóstico/apresentação; não aceleram requisições nem confirmam os recursos do domínio fornecido. Log de cada request em `-vv` continua separado. Eventos representam somente emissões aceitas deste processo.

## Etapa 14 — Respostas comparadas e correlações passivas (`1.14.5`)

O log de `1.14.4` mostrou redirects com variação de caixa na query, repetição
do HTML de entrada e quatro respostas de 337B. Sem seus corpos/Location, esse
log sozinho não comprova equivalência. O novo comparador usa SHA-256 do corpo
decodificado capturado, status, tipo de conteúdo e hash de cabeçalhos semânticos
(`Allow`, `WWW-Authenticate`, `Content-Disposition`, `Content-Encoding`,
`Set-Cookie`). O simhash de calibração permanece separado: ele remove atributos
HTML e não é suficiente para silenciar resultados com metadados completos.

O terminal Rich/plain agrupa a partir da segunda assinatura equivalente. Em
redirects, compara também rota de origem e destino; somente o destino ecoado
no corpo e uma query copiada exatamente da requisição são normalizados. Corpos
truncados, contratos declarados, reproduções explícitas e alertas de conteúdo
continuam visíveis. Metadados são preservados em JSON/JSONL/checkpoints.
URLs aceitas, inclusive slash twins com metadados completos, permanecem nos
eventos retidos. A apresentação final recupera essas linhas após o agrupamento
interno legado, preservando enriquecimentos posteriores sem alterar esse
algoritmo de descoberta.

JSON/HTML ganham correlações de resposta com membros/referências dos eventos e
correlações de fingerprint por tecnologia/prefixo. Sinais repetidos são
deduplicados na contagem de sinais distintos; score sem evidências é marcado
como procedência indisponível. Tipos de sinal distintos não provam independência
estatística. A referência consultada foi o OWASP WSTG v4.2, INFO-08, que recomenda
usar marcadores de várias fontes para avaliar fingerprints.

Validação: 17 regressões novas (também executadas via unittest); suíte abrangente
com 500 testes aprovados, quatro skips e nove testes já problemáticos no estado
anterior explicitamente excluídos (cinco fixtures de memória incompatíveis e
quatro dependências de operações bloqueadas pelo sandbox). Ruff passou; Mypy
passou em 74 arquivos; compileall e versão da CLI passaram. Não foi acessado o
domínio do log. Transporte nos testes novos foi simulado em memória.

Limites: comparação conservadora mantém variações de tokens/corpo visíveis;
metadados não substituem corpos HTTP brutos. A retenção continua limitada aos
eventos aceitos deste processo. As correlações são leitura de evidências e não
acionam novas sondagens, prioridades ou cadeias de exploração.

## Etapa 15 — Canais, procedência offline e Set-Cookie (`1.14.6`)

O relatório agora distingue tipos de sinal de canais de aquisição: `header` e
`cookie` compartilham cabeçalhos da resposta; `body` e `error_page` compartilham
o corpo. Os campos anteriores continuam disponíveis, e novos campos descrevem
canais e marcadores normalizados. Rotação do valor de um mesmo nome de cookie
não aumenta a contagem normalizada. Evidências brutas, pesos e decisões do
scanner não foram alterados; diversidade de canais não prova independência.

`reference_provenance` relaciona somente as arestas existentes com observações
aceitas por URL HTTP exata, sem fragmento. Query/case/porta/origem não são
colapsadas. Referências relativas sem contexto ficam não resolvidas; queries
já perdidas pelos coletores legados não são reconstruídas. Exemplos de caminhos
são limitados a quatro hops/200 exemplos e 4.000 arestas processadas; limites e
índices são explícitos, e o conjunto bruto de arestas continua no relatório.
Referenciado, observado e explorável permanecem conceitos distintos.

A captura de `Set-Cookie` é um hook de resposta antes da leitura do corpo,
incluindo saltos de redirect, respostas descartadas/filtradas e falhas de leitura
do corpo. Avisos mostram nomes e presença de atributos selecionados, sem valores.
Rotação de valores incrementa a contagem por URL/metadados; mudanças dos atributos
selecionados produzem novas assinaturas. O terminal limita o preview a 20
assinaturas distintas, informa o limite e mantém todas as observações por URL
em JSON/HTML. Campos não interpretados são contados sem ecoar conteúdo. Não há
mudança no cookie jar, novas requisições ou alteração na classificação.

Referências: OWASP WSTG v4.2 INFO-08 (múltiplos marcadores) e RFC 6265
(campos separados de Set-Cookie, observação versus aceitação pelo agente).
Limites: telemetria somente deste processo, sem valores/Domain/Path/expiração,
sem `document.cookie`, sem retrospectiva dos checkpoints e sem emissão como
finding JSONL. Evidências antigas de fingerprint permanecem inalteradas.

Validação: 16 regressões novas em transporte simulado/análise offline; 33 testes
focados aprovados incluindo as 17 regressões da etapa anterior. Não foi acessado
o domínio fornecido. A suíte abrangente passou em 516 testes, com quatro skips
e os mesmos nove testes preexistentes incompatíveis/bloqueados explicitamente
excluídos, documentados na etapa 14. Ruff, Mypy (76 arquivos), compileall e versão
da CLI passaram. O comando instalado informa `origami 1.14.6`.

## Etapa 16 — Consistência dos relatórios e snapshots (`1.14.7`)

Quatro regressões foram reproduzidas antes das correções: a tabela principal do
HTML não recuperava respostas distintas após colapso legado; imprimia todas as
repetições com metadados iguais; scores exportados compartilhavam o dicionário
do perfil; e o aviso de cookie compartilhava o registro agregado mutável.
Agora o HTML usa a mesma recuperação/comparação conservadora do terminal, sem
mudar os dados do scanner. Detalhes dos membros permanecem no relatório, e notas,
tags e reproduções posteriores são preservadas. Scores e notificações são cópias
destacadas; futuras agregações não reescrevem o snapshot entregue ao callback.

O JavaScript de filtro/sort ficava acoplado a todos os `tbody tr`, ocultando
evidências ao buscar um finding. Os seletores foram isolados em `findings-table`.
Uma regressão executa o JavaScript real em Node com DOM simulado, sem navegador
ou rede, verificando filtro, ordenação nos dois sentidos e isolamento da evidência.

`cookie_summary` descreve respostas/campos capturados, nomes por origem HTTP e
variantes dos atributos selecionados, com índices dos registros originais.
Múltiplos campos do mesmo nome em uma resposta não duplicam a contagem de
respostas com esse nome. Sem Domain/Path, essas entradas não são identidades
de cookies do navegador. Unknown/variação de atributos não viram vereditos de
segurança. O JSON ganha contagens da apresentação conservadora, preservando
o significado legado de `presentation_row_count` e as coleções brutas.

As cinco falhas de memória excluídas anteriormente foram reproduzidas como
`AttributeError` por fixtures sem `profile`. Os testes agora usam `ScanResult`
real, com o mesmo perfil/findings/número de requisições, sem mudar as asserções
ou algoritmos de descoberta/aprendizado. Toda a suíte de memória passou.

Validação: 14 regressões novas aprovadas; suíte abrangente com 535 testes
aprovados, quatro skips e quatro exclusões explícitas por dependências do
sandbox: o teste de slow-trickle com socket local e três testes CLI cuja
configuração padrão exige operações indisponíveis neste ambiente. Os cinco
testes de memória antes excluídos agora passam. Ruff (código e regressões novas),
Mypy (77 arquivos), compileall, unittest das regressões novas e versão instalada
da CLI foram verificados. O teste de DOM não é QA visual em navegador.
Não houve tráfego ao domínio fornecido nem novas sondagens/automação ofensiva.

## Etapa 17 — Inteligência passiva de rotas do cliente (`1.15.0`)

O experimento `--verify-bundle` foi removido para manter o trabalho focado na
descoberta útil ao pentester. O parser de HTML/JavaScript agora correlaciona método,
rota e origem para `fetch`, Axios, instâncias Axios com `baseURL`, clientes HTTP
comuns e XHR. Concatenações estáticas limitadas são resolvidas sem executar código.

Interpolação em segmento de caminho não é mais apagada para formar uma URL falsa:
`/users/${id}/reset` permanece `/users/{id}/reset` como inteligência passiva. Rotas
100% estáticas continuam alimentando a descoberta. Templates, inclusive parâmetros
de query, são exportados em JSON, HTML e `client_routes.json`, com procedência do
HTML/JS. Métodos mutáveis descobertos nunca são reproduzidos automaticamente.

O estado também entra no checkpoint para não desaparecer após retomada. Regressões
cobrem métodos, parâmetros, constantes encadeadas, `baseURL`, escopo same-site,
rejeição de esquemas inseguros, deduplicação e ausência do caminho colapsado falso.
Não houve tráfego ao domínio fornecido.

## Etapa 18 — Superfície de entrada por rota (`1.15.1`)

A inteligência passiva agora cobre `axios(config)`, `axios.request(config)`,
`.request()` de instâncias, `$.ajax()` e atalhos GET/POST do jQuery. Objetos inline
são analisados de forma limitada, sem execução: por rota, o relatório preserva
nomes de parâmetros de query, campos de corpo e headers, mas descarta seus valores.
Chamadas duplicadas unem os campos observados em vez de perder a ocorrência anterior.

Os nomes de path/query/body passam também para a superfície de parâmetros e para
`params.txt`. A caixa original é preservada porque chaves de API podem diferenciar
`userId` de `userid`. URLs relativas continuam relativas ao prefixo da aplicação;
somente o padrão explícito de base runtime mantém a interpretação root-relative.
Rotas estáticas continuam recebendo apenas o probe GET normal de descoberta;
métodos mutáveis identificados no cliente não são reproduzidos.

Validação: 20 regressões específicas de inteligência de rotas; suíte abrangente
com 556 testes aprovados, quatro skips e quatro exclusões pelas limitações já
documentadas do sandbox. Mypy (77 arquivos), compileall, versão da CLI e um
ensaio local de 2,1 MB sem rotas passaram. Não houve tráfego ao alvo.

## Pendências do plano

- Identidade e migração de checkpoints, snapshot final recuperável e procedência completa no banco.
- Estado por etapa, cobertura mensurável e identidade de configuração/autenticação para comparações.
- Isolamento por projeto, exclusão dos dados derivados e revisão de apresentação em todos os canais.
- Anotações de revisão offline, integridade do catálogo, empacotamento e avaliação com corpus rotulado.
- Interface de projeto e assistência inteligente explicável continuam propostas, sem implementação nesta execução.

## Limites de execução

O trabalho implementa proteção do operador, persistência e análise offline. Ampliação de automação ofensiva, técnicas de exploração e evolução da retomada desses fluxos permanecem fora deste trabalho. O plano integral não deve ser marcado como concluído com base nestas etapas.
