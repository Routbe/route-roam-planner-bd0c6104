# Stap 10 (Level-9) + rollout 0276 — herzien plan

Uitgangspunt (nagekeken): 0275 staat live op Neon; `db/` en Neon lopen gelijk. `vdf.rs` bestaat maar zit niet in de engine. Er is nog geen `noise-tunnel.ts` of `audit-dudect.ts`. 0276/0277 staan in `db-pending/`. Z3-modellen staan in `scripts/formal-rls/`.

## 1. Basismeting (niets wijzigen)
- Tests, typecontrole, `verify:rls` en `build.sh --check` draaien; uitkomst vastleggen als vertrekpunt.

## 2. Rollout 0276 op Neon (EXPAND, GO gegeven)
- 0276 naar `db/`, `CODE_SCHEMA_LEVEL = "0276"`, snapshot bijwerken; PGlite-replay- en rollout-test voor 0276 groen.
- Eén transactie via `scripts/migration-rollout.ts`: SHA-256 gelijk aan het bestand, 0275 als voorganger, definer-guard in dezelfde transactie.
- Teruglezen: geschiedenisrij + checksum, nieuwe functies aanwezig, elke definer op `pg_catalog, pg_temp`.

## 3. Pipeline 0276 -> 0277
- `scripts/tenant-backfill.ts`: vult de nieuwe tenant-kolommen in batches binnen de eigenaarscontext, idempotent, en eindigt met een verificatiequery (0 rijen zonder tenant, 0 afwijkingen tussen oude en nieuwe kolom). Eerst droog op PGlite, daarna pas live na aparte bevestiging.
- `scripts/formal-rls/certify-0277.ts`: zet de policies van 0277 om naar Z3 (bestaand `tenant-model.ts`) en bewijst niet-interferentie (geen rij van tenant A zichtbaar of schrijfbaar voor B) en dat geen huidige schrijver breekt. Uitkomst `unsat` = gecertificeerd, rapport in `docs/`.
- 0277 blijft in `db-pending/` tot productie 0276 meldt, de backfill nul afwijkingen toont, Z3 certificeert én jij apart GO geeft.

## 4. Wesolowski VDF (`wasm/rout-zk/src/vdf.rs`)
- Twee groepen achter één ABI: RSA-2048 en **class groups van imaginaire kwadratische velden** (binaire kwadratische vormen, discriminant afgeleid uit een publieke seed via hash-to-prime, dus geen trusted setup).
- Vaste-breedte bignum (discriminant 2048 bit), compositie/kwadratering via NUCOMP/NUDUPL met reductie; Wesolowski-bewijs met Fiat-Shamir hash-to-prime ℓ. Pietrzak alleen als tweede verificatiepad indien het binnen de arena past; anders expliciet gemeld.
- Geen allocator, geen `memory.grow`; elke tussenliggende kwadrateringsbuffer via `wipe::bytes`/volatile writes na gebruik.
- Rust-tests: kleine discriminant met handmatig narekenbare vectoren, RSA- en class-group-rondes, weigering bij vals bewijs/verkeerde T/niet-gereduceerde vorm. ABI 7 en nieuwe pin alleen bij reproduceerbare bouw.

## 5. Hybride PQ-Noise-tunnel (`src/lib/crypto-enclave/noise-tunnel.ts`)
- Patroon IKpsk2 uitgebreid met KEM-tokens (PQNoise/“hybrid” aanpak): elke DH-stap wordt aangevuld met ML-KEM-1024 encapsulatie; beide geheimen gaan via `MixKey` de chaining key in, zodat de sessie veilig blijft zolang X25519 óf ML-KEM standhoudt — hetzelfde niveau als RVE2 uit Stap 8.
- ChaChaPoly + BLAKE2s, @noble-bibliotheken uit het project, alleen in de crypto-werker, getypeerde berichten, buffers gewist in `finally`.
- Tests: officiële Noise-vectoren voor het klassieke deel; voor het hybride deel bestaan geen officiële vectoren, dus eigen vastgezette vectoren plus weigering bij verkeerde PSK, verkeerde statische sleutel, gewijzigde KEM-ciphertext, replay en gewijzigde nonce.
- Eerlijk: dit is een tunnel op berichtniveau, geen echte TLS; "mTLS" betekent hier wederzijdse authenticatie via statische sleutels.

## 6. Dudect-audit (`scripts/audit-dudect.ts`, `bun run test:dudect`)
- Per operatie ≥ 1.000.000 metingen, 10.000 niet-meegetelde warm-up-runs, `bun --expose-gc` met `gc()` tussen blokken, afwisselend vaste/willekeurige klasse, Welch t-test met grens |t| < 4,5.
- Operaties: X25519-vermenigvuldiging, ML-KEM decapsulatie, subtle-vergelijkingen, ratchetstap, OPAQUE, VDF-verificatie (Wasm), het WebAuthn-PRF-afleidingspad (HKDF na PRF-uitvoer) en AES-256-GCM met foute vs. juiste AAD.
- Rapport in `docs/`; een gefaalde operatie wordt gemeld, niet weggemasseerd. Looptijd kan per operatie minuten zijn; draait buiten de gewone testsuite.

## 7. Validatie en documentatie
- Alles opnieuw draaien; open RLS-bevindingen mogen alleen korter worden.
- Bijwerken: bijlage Stap 10 in `docs/HANDOVER.md`, `roadmap.md`, `db-pending/README.md`, `AGENTS.md` (regels VDF, PQ-Noise, dudect, backfill/Z3-poort).

## Risico's
- Rust hier is niet de officiële build: reproduceert `--check` niet, dan lever ik code en tests maar geen nieuwe pin; bouwen moet dan in CI.
- Class groups zonder allocator is zwaar werk; als de arena (2 MiB) te klein blijkt, meld ik dat en stel een grotere vaste arena voor in plaats van stil te versimpelen.
- Dudect is statistisch bewijs voor deze machine, geen formeel bewijs; JavaScript (PRF/AES via WebCrypto) is niet volledig onder onze controle.
