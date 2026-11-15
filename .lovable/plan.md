# Stap 10 volledig + rollout 0276 (GO gegeven)

Uitgangspunt (nagekeken): 0275 staat al live op Neon; `db/` en Neon lopen gelijk. `vdf.rs` bestaat (420 regels) maar zit nog niet in de engine. Er is nog geen `noise-tunnel.ts` en geen `audit-dudect.ts`. 0276/0277 staan klaar in `db-pending/`. 0277 krijgt **geen** rollout in deze stap.

## 1. Basismeting (eerst, niets wijzigen)
- Draai de bestaande testsuite, de typecheck en `bun run verify:rls` en leg de uitkomst vast als vertrekpunt.
- Controleer of de wasm-bouw hier het pinbestand exact reproduceert (`build.sh --check`).

## 2. Wesolowski VDF in rout-zk
- Hang `vdf.rs` in `lib.rs` en exporteer `vdf_eval(input, T)` en `vdf_verify(input, T, proof)` via `abi.rs`, binnen de vaste arena (geen allocator, geen memory.grow).
- Voeg Rust-tests toe in `tests/vdf.rs`: een kleine modulus, vectoren voor RSA-2048 en weigeringsgevallen.
- Bouw de module, zet de nieuwe SHA-384 en ABI 7 in `zk-wasm-pin.ts` en maak de functies beschikbaar in `zk-engine.ts` en in de worker- en clientberichten.

## 3. Noise_IKpsk2-tunnel
- Maak `src/lib/crypto-enclave/noise-tunnel.ts`: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` met @noble-bibliotheken die al in het project zitten. Het draait alleen in de worker, met getypeerde berichten en het wissen van buffers in `finally`.
- Voeg tests toe met de officiële Noise-testvectoren, plus weigering bij een verkeerde PSK of statische sleutel, replay en een gewijzigde nonce.

## 4. Dudect-timingaudit
- Maak `scripts/audit-dudect.ts` en het script `test:dudect`: een Welch t-test met afwisselend vaste en willekeurige invoer, minstens 100.000 iteraties per operatie. Gemeten worden scalaire vermenigvuldiging, subtle-vergelijkingen, ratchetstappen, OPAQUE en VDF-verificatie.
- Criterium: |t| < 4.5. Het rapport komt in `docs/`. Een operatie die faalt, wordt gemeld en niet weggemasseerd.

## 5. Rollout 0276 op Neon (EXPAND)
- Controleer opnieuw dat de huidige code stabiel is en dat de PGlite-test voor 0276/0277 groen is.
- Verplaats `0276_tenant_column_expand.sql` naar `db/` en zet `CODE_SCHEMA_LEVEL` op `"0276"`. Werk de schema-snapshot bij.
- Bouw de transactie met `scripts/migration-rollout.ts`, met de SHA-256-controle en de controle op 0275 als voorganger. Voer die uit als één aanroep naar Neon.
- Controleer daarna: de geschiedenisrij en de checksum, dat de nieuwe functies bestaan, en dat elke eigenaarsfunctie het veilige zoekpad `pg_catalog, pg_temp` heeft. De app moet automatisch de functies van 0276 gaan gebruiken.
- 0277 blijft in `db-pending/` tot productie 0276 rapporteert en jij apart GO geeft.

## 6. Validatie en documentatie
- Draai de tests, de typecheck en `verify:rls` opnieuw. De lijst met nog open RLS-bevindingen mag alleen korter worden.
- Werk bij:
  - `docs/HANDOVER.md`: alleen een nieuwe bijlage voor Stap 10.
  - `roadmap.md`
  - `db-pending/README.md`: het verouderde "0275 pending" eruit.
  - `AGENTS.md`: regels voor VDF, Noise en dudect.

## Risico's
- De Rust-compiler hier is 1.95.0, maar zelf gebouwd uit broncode. De bouw vraagt het officiële rustup-pakket (LLVM 22.1.2). Als `--check` het pinbestand niet reproduceert, gebeurt het volgende:
  - Ik lever de code en de tests wel.
  - De nieuwe pin laat ik open.
  - De bouw met de officiële toolchain moet dan in CI of bij jou gebeuren. Er komt geen niet-reproduceerbare pin in de code.
- De dudect-uitkomst is statistisch bewijs voor deze machine, geen formeel bewijs.
