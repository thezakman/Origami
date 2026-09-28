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

## Pendências do plano

- Identidade e migração de checkpoints, snapshot final recuperável e procedência completa no banco.
- Estado por etapa, cobertura mensurável e revisão das inferências do diff.
- Isolamento por projeto, exclusão dos dados derivados e revisão de apresentação em todos os canais.
- Importação/revisão offline, integridade do catálogo, empacotamento e avaliação com corpus rotulado.
- Interface de projeto e assistência inteligente explicável continuam propostas, sem implementação nesta execução.

## Limites de execução

O trabalho implementa proteção do operador, persistência e análise offline. Ampliação de automação ofensiva, técnicas de exploração e evolução da retomada desses fluxos permanecem fora deste trabalho. O plano integral não deve ser marcado como concluído com base nestas etapas.
