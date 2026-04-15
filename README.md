# NablaTester v2

Ferramenta para analisar um projeto, identificar classes relevantes de bugs e gerar um relatório **PDF** com:
- descrição de cada achado,
- passos de debug por bug,
- plano de debug conjunto ao final.

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Uso com janela gráfica (selecionar pasta + Start)

```bash
nablatester
```

Fluxo:
1. abre uma janela;
2. clica em **Selecionar pasta** para escolher o código de teste;
3. clica em **Start**;
4. acompanha barra de progresso + ETA em tempo real até 100%;
5. ao final recebe `nablatester_report.pdf` na pasta selecionada.

Também é possível forçar GUI por flag:

```bash
nablatester --gui
```

Se o ambiente não suportar GUI, o programa cai automaticamente para modo texto.

### UX/UI (desktop) aprimorada
- Interface em abas (**Execução** e **Runtime**).
- Barra de progresso com percentual e ETA.
- Botão Start com lock de execução (evita duplo clique concorrente).
- Controles avançados de autofix + quality gate estrito.

Na GUI você pode marcar **Ativar correção determinística em cascata** para:
- copiar a base original para uma pasta derivada (`*_nablatester_fixed`);
- editar arquivos em cascata com regras determinísticas;
- emitir stream em tempo real (`cascade_stream.jsonl`);
- gerar relatório PDF final no clone corrigido.

## Uso direto por linha de comando

```bash
nablatester /caminho/do/projeto
```

Opcionalmente:

```bash
nablatester /caminho/do/projeto --output /tmp/meu_relatorio.pdf --no-interactive
```

Relatórios adicionais:

```bash
nablatester /caminho/do/projeto \
  --workers 4 \
  --sarif-output /tmp/nablatester.sarif \
  --json-output /tmp/nablatester.json \
  --no-interactive
```

Modo baseline (ignorar achados conhecidos):

```bash
nablatester /caminho/do/projeto \
  --baseline-in /tmp/nablatester_baseline.json \
  --baseline-out /tmp/nablatester_baseline_nova.json \
  --no-interactive
```

## Correção determinística em cascata (sem LLM)

```bash
nablatester /caminho/do/projeto --autofix --no-interactive
```

Com parâmetros:

```bash
nablatester /caminho/do/projeto \
  --autofix \
  --autofix-target /tmp/projeto_corrigido \
  --stream-report /tmp/cascade_stream.jsonl \
  --max-iterations 10 \
  --strict-gate \
  --gate-cmd "python -m compileall ." \
  --gate-cmd "pytest -q" \
  --no-interactive
```

Observação importante: o modo determinístico reduz bugs das regras cobertas, mas não prova ausência total de bugs (limite teórico e cobertura finita de regras).

## Upgrade SAST determinístico (nível enterprise - base)

Esta versão evolui de detecção por texto para uma base de análise estática determinística:

- **Motor de regras desacoplado** em `src/nablatester/rules/*.json|yaml` (estilo engine + regras externas).
- **Análise semântica Python via AST**:
  - chamadas perigosas por regra (`dangerous_calls`);
  - análise de contaminação source -> sink (`taint_sources`/`taint_sinks`/`sanitizers`);
  - heurística de SQL injection para `execute()` com f-string;
  - análise interprocedural básica (caller -> callee) para fluxo contaminado;
  - controle de escopo para reduzir falso positivo de taint entre funções;
  - uso de variável antes de atribuição em escopo de função;
  - marcadores TODO/FIXME/HACK via tokenização de comentários (evita falso positivo em identificadores).
- **Cobertura semântica inicial para JavaScript/TypeScript** em padrões críticos (`eval`, `child_process.exec/execSync`).
- **Autofix em cascata com invariância sintática**:
  - pré-compila código candidato antes de salvar;
  - rollback automático se a modificação quebrar sintaxe;
  - normalização e ordenação do bloco de imports após injeções automáticas.
- **Cobertura expandida de linguagens**: mais de 35 extensões/fontes suportadas para varredura poliglota inicial.

## Como chegar perto de 100% (detecção) e maximizar correção correta

100% absoluto para qualquer código é inviável na prática (limites teóricos e contextuais), mas o NablaTester pode chegar muito perto em cenários controlados combinando:

1. Regras SAST por linguagem + CFG/DFG/taint com cobertura ampla.
2. Correção em CST/AST com rollback e validação sintática/semântica por arquivo.
3. Execução de testes, lint e type-check após cada lote de fixes.
4. Sandbox de execução para validação comportamental e regressão.
5. Regras por domínio (web, fintech, backend, mobile) + baseline de falso positivo.
6. Quality gate estrito por iteração com rollback transacional (compile/test/lint/type-check).

Meta operacional recomendada: reduzir FNs progressivamente por suíte de regressão e manter taxa de correção automática segura (sem quebrar build) acima de 95% nos padrões suportados.

## Gerar executável único

```bash
pip install pyinstaller
pyinstaller --onefile -n nablatester src/nablatester/cli.py
```

Binário gerado em:
- `dist/nablatester`

Você pode distribuir esse executável e rodar sem ativar ambiente virtual.

## Projetos de teste incluídos

Foram adicionados exemplos reais com múltiplos diretórios/arquivos para validar o scanner:

- `sample_projects/project_alpha/src/main.py`
- `sample_projects/project_alpha/src/broken.py`
- `sample_projects/project_beta/api/handler.py`
- `sample_projects/project_beta/workers/job_runner.py`

Teste rápido:

```bash
nablatester sample_projects/project_alpha --no-interactive
nablatester sample_projects/project_beta --no-interactive
```
