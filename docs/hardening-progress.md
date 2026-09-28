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

## Pendências do plano

- Identidade e migração de checkpoints, snapshot final recuperável e procedência completa no banco.
- Estado por etapa, cobertura mensurável e identidade de configuração/autenticação para comparações.
- Isolamento por projeto, exclusão dos dados derivados e revisão de apresentação em todos os canais.
- Anotações de revisão offline, integridade do catálogo, empacotamento e avaliação com corpus rotulado.
- Interface de projeto e assistência inteligente explicável continuam propostas, sem implementação nesta execução.

## Limites de execução

O trabalho implementa proteção do operador, persistência e análise offline. Ampliação de automação ofensiva, técnicas de exploração e evolução da retomada desses fluxos permanecem fora deste trabalho. O plano integral não deve ser marcado como concluído com base nestas etapas.
