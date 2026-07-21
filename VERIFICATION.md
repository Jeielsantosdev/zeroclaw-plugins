# Verificação obrigatória — rodar após TODA alteração, antes de qualquer commit

Este checklist é **obrigatório**, não opcional, para qualquer plugin deste repositório (`x402-quote-check`, `x402-settle`, `lending-health`, e qualquer outro criado depois). Nenhuma alteração é considerada "terminada" sem passar por ele inteiro. Cada item existe para proteger um dos 5 critérios oficiais de julgamento da bounty — a coluna "critério" mostra qual.

**Regra de ouro: se qualquer item falhar, o trabalho não está pronto — corrigir antes de commitar. Nunca commitar código que falhe em um destes passos.**

---

## 1. Build e testes (rodar dentro do diretório do plugin, ex. `plugins/x402-quote-check/`)

| # | Comando | O que prova | Critério |
|---|---|---|---|
| 1.1 | `cargo fmt --check` | Formatação consistente com o resto do repositório (CI rejeita PR com diff de formatação) | Prontidão para merge (15%) |
| 1.2 | `cargo test --locked` | Núcleo puro passa todos os testes, sem rede real, sem toolchain wasm | Qualidade de código (20%) |
| 1.3 | `cargo clippy --locked --all-targets -- -D warnings` | Zero warnings no host — nenhum aviso "silenciado por atalho" | Qualidade de código (20%) |
| 1.4 | `cargo clippy --locked --target wasm32-wasip2 -- -D warnings` | Zero warnings especificamente no alvo real do componente | Qualidade de código (20%) |
| 1.5 | `cargo build --locked --target wasm32-wasip2 --release` | Builda limpo para o alvo que a bounty exige | Prontidão para merge (15%) |

Se `1.1`-`1.5` não passarem todos, **pare aqui** — não faz sentido avaliar segurança de código que nem builda.

## 2. Segurança — checagem manual linha a linha (não pular, mesmo achando "óbvio")

Percorrer `src/lib.rs` e `src/<núcleo>.rs` inteiros, checando cada item abaixo. Fazer isso lendo o código, não só confiando na memória do que foi escrito.

| # | Checagem | Como verificar | Critério |
|---|---|---|---|
| 2.1 | Nenhum `println!`/`eprintln!`/`dbg!` no componente | `grep -rn "println!\|eprintln!\|dbg!" src/` deve vir vazio — todo log passa por `log_record` | Segurança/custódia (25%) |
| 2.2 | Nenhum `.unwrap()`/`.expect(...)`/`panic!`/`unimplemented!`/`todo!` em código de produção | Ler `src/lib.rs` e a parte de `src/<núcleo>.rs` **fora** do módulo `#[cfg(test)] mod tests` — qualquer ocorrência ali é um bug de fail-closed em potencial, não um detalhe de estilo | Segurança/custódia (25%), Qualidade de código (20%) |
| 2.3 | Erro de entrada do modelo sempre vira `ToolResult { success: false, .. }`, nunca `Err(...)` | Reler cada `match`/`?` em `execute()` e confirmar que só uma falha genuinamente irrecuperável do componente usa `Err` | Segurança/custódia (25%) |
| 2.4 | Nenhuma chave privada, segredo ou credencial hardcoded no código | `grep -rniE "private_key|secret_key|priv_key|api_key\s*=" src/` — qualquer acerto precisa vir de `__config`, nunca de uma constante no código | Segurança/custódia (25%) — item de desqualificação instantânea se violado |
| 2.5 | `manifest.toml` declara **só** as permissões realmente usadas | Se `http_client` está declarado, confirmar que `waki::` é usado em `src/`; se `config_read` está declarado, confirmar que `__config` é lido em `src/`. Nenhuma permissão "por garantia" | Prontidão para merge (15%) |
| 2.6 | O tier de custódia declarado no README bate exatamente com o que o código permite | Reler o README e confirmar, campo por campo, que nada no código monta/assina/envia transação além do que o tier declarado autoriza | Segurança/custódia (25%) — o critério mais citado no edital ("is the tier honest?") |
| 2.7 | Todo campo vindo de fonte não confiável (resposta HTTP, argumento do modelo) é validado antes de influenciar qualquer decisão de política | Confirmar que nenhum campo de texto livre (mensagens, descrições, nomes) altera limites, permissões ou fluxo — só campos estruturais validados importam | Segurança/custódia (25%) |
| 2.8 | Testes de prompt injection/fail-closed existem e passam | `cargo test --locked` já rodou em 1.2 — confirmar visualmente que os testes de ataque (mint falsificado, rede falsificada, injeção via texto livre, etc.) realmente existem no arquivo de testes, não só que "os testes passam" (um arquivo de testes vazio também passa) | Segurança/custódia (25%) |

## 3. Antes de considerar pronto para commit

- [ ] Seções 1 e 2 inteiras, sem pular nenhum item.
- [ ] README atualizado se qualquer comportamento, config key, ou tier mudou.
- [ ] Nenhum arquivo de build (`target/`, `*.wasm`) staged no commit (confirmar com `git status` antes de `git add`).
- [ ] Mensagem de commit descreve o que mudou e por quê, não só "fix" ou "update".

## 4. Antes de abrir/atualizar o PR (uma vez por entrega, não a cada commit)

- [ ] `bash tools/ci/validate_components.sh <nome-do-plugin>` — roda o mesmo pipeline que o CI oficial vai rodar (fmt, test, clippy host+wasm, build, empacotamento), a partir de uma árvore git limpa.
- [ ] `python3 tools/build-registry.py --source-plugins plugins --check-metadata registry.json` — valida metadados de registro sem editar `registry.json` manualmente.
- [ ] Checklist geral completo em `../docs/07-checklist.md` (documentação, custódia, entrega) também revisado.
