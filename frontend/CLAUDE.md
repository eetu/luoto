# frontend

SvelteKit (runes) SPA, adapter-static to `dist/`, embedded into `luoto` by rust-embed (the
`cli/build.rs` re-embeds on rebuild). halo-design tokens in `src/lib/styles/halo.css`
(verbatim copy of the family file); halo-interaction shell: env list and the vault
(navigate), an env's egress view or the vault view of every env's credentials (surface,
`app.view`), subject panel (host, request, env, vault or one credential) and status bar.

- `src/lib/api.ts` is the only fetch layer. The API's types are generated from the Rust
  structs into `src/lib/generated/api.ts` (`just types`; never edit it) and re-exported by
  `src/lib/types.ts`, which holds only UI-side types. The e2e fixtures (`e2e/fixtures/*.ts`,
  real responses) `satisfies` their generated type. The token comes from the `#token=`
  fragment into sessionStorage.
- Shared state lives in `src/lib/stores/app.svelte.ts`; panels read it directly.
- Live updates: fetch-based SSE (`followEvents`) so the token can travel in a header.
- One context menu (`menu.svelte.ts` + `ContextMenu.svelte`), one `Modal`.
- Text written by the sandbox (request reasons) is rendered as plain text in an
  "untrusted" block — never as HTML, never pre-filled into commands, never in a browser
  notification (`notify.svelte.ts`). The one field it fills is a variable request's plain
  value, shown beside it as the sandbox's.
- `yarn validate` = typecheck + lint + format. Vendored yarn: `node .yarn/releases/yarn-*.cjs`.
- Glyph: the islet outline is the accent (orange stroke over currentColor waves) instead of the
  family's warm dot, which read as a figure above the islet. Still exactly one accent element.
