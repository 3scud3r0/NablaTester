# BugSuite Analyzer v2

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
bugsuite
```

Fluxo:
1. abre uma janela;
2. clica em **Selecionar pasta** para escolher o código de teste;
3. clica em **Start**;
4. ao final recebe `bugsuite_report.pdf` na pasta selecionada.

Também é possível forçar GUI por flag:

```bash
bugsuite --gui
```

Se o ambiente não suportar GUI, o programa cai automaticamente para modo texto.

Na GUI você pode marcar **Ativar correção determinística em cascata** para:
- copiar a base original para uma pasta derivada (`*_bugsuite_fixed`);
- editar arquivos em cascata com regras determinísticas;
- emitir stream em tempo real (`cascade_stream.jsonl`);
- gerar relatório PDF final no clone corrigido.

## Uso direto por linha de comando

```bash
bugsuite /caminho/do/projeto
```

Opcionalmente:

```bash
bugsuite /caminho/do/projeto --output /tmp/meu_relatorio.pdf --no-interactive
```

## Correção determinística em cascata (sem LLM)

```bash
bugsuite /caminho/do/projeto --autofix --no-interactive
```

Com parâmetros:

```bash
bugsuite /caminho/do/projeto \
  --autofix \
  --autofix-target /tmp/projeto_corrigido \
  --stream-report /tmp/cascade_stream.jsonl \
  --max-iterations 10 \
  --no-interactive
```

Observação importante: o modo determinístico reduz bugs das regras cobertas, mas não prova ausência total de bugs (limite teórico e cobertura finita de regras).

## Gerar executável único

```bash
pip install pyinstaller
pyinstaller --onefile -n bugsuite src/bugsuite/cli.py
```

Binário gerado em:
- `dist/bugsuite`

Você pode distribuir esse executável e rodar sem ativar ambiente virtual.

## Projetos de teste incluídos

Foram adicionados exemplos reais com múltiplos diretórios/arquivos para validar o scanner:

- `sample_projects/project_alpha/src/main.py`
- `sample_projects/project_alpha/src/broken.py`
- `sample_projects/project_beta/api/handler.py`
- `sample_projects/project_beta/workers/job_runner.py`

Teste rápido:

```bash
bugsuite sample_projects/project_alpha --no-interactive
bugsuite sample_projects/project_beta --no-interactive
```
