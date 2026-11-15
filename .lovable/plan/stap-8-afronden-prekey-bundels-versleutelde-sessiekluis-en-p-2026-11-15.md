# Stap 8 afronden: prekey-bundels, versleutelde sessiekluis en publicatie

Neon blijft op 0274. Er komen geen nieuwe SQL-bestanden in `db/` of `db-pending/`. De Wasm-motor blijft byte-exact gelijk (ABI 6, SHA-384 `6f47f561…`), want de sessietoestand (9888 bytes) komt al als bytes in de worker terecht. Er is dus geen nieuwe Wasm-op nodig.

## Twee keuzes die ik vastleg (de opdracht spreekt zichzelf tegen)
1. **Opslagpad bij Scaleway:** de opdracht noemt zowel `users/<uid>/prekey-bundle.json` als `.bin`. Ik kies `users/<uid>/prekey-bundle.json`: het volledige, ondertekende document dat het publieke adres ongewijzigd teruggeeft.
2. **Sleutel van de kluis:** `HKDF-SHA256(ikm = PRF-masterseed || host_device_key-seed, salt = "rout.pqr.vault.v1", info = userId)` geeft een niet-exporteerbare AES-256-GCM-sleutel. Zonder `host_device_key`, bijvoorbeeld bij een gast, gebruik ik alleen de PRF-seed met een aparte info-tag. Een sessie gaat dus nooit open met de sleutel van een andere rol.

## 1. Bundel verplicht controleren in de worker
- `pq_ratchet.init_session` met rol initiator vraagt voortaan het volledige prekey-document plus `rpId` en `handle`, niet langer een losse engine-bundel.
- De worker roept eerst `verifyPrekeyDocument()` aan. Elke fout stopt de sessie zonder dat er een toestand ontstaat: geen of een ongeldige passkey-handtekening, verkeerde context of handle, ouder dan 30 UTC-dagen, of een afgekeurd of ontbrekend MDS3-oordeel.
- Pas daarna haalt de worker de engine-bundel van 1606 bytes uit het document en start `pqrInitiatorInit`.

## 2. Versleutelde sessiekluis (`src/lib/crypto-enclave/pq-session-vault.ts`)
- IndexedDB-database `vault_ratchet_sessions`, record `{ v: 1, iv, ct }`, opgevuld tot een vaste bucket van 12 KiB.
- AAD = `"rout.pqr.session.v1|" userId "|" sessionId`. Een record dat naar een andere sessie of gebruiker is verplaatst, gaat niet open.
- `ratchet_encrypt` en `ratchet_decrypt` schrijven de nieuwe toestand eerst weg en geven pas daarna het resultaat terug. Mislukt het wegschrijven, dan blijft de oude toestand staan en faalt de stap.
- `close_session`: het record wordt overschreven met nullen van dezelfde grootte, daarna verwijderd. Alle eigen buffers worden gewist.

## 3. Worker-ops en client
Nieuwe ops in `protocol.ts`, `enclave-core.ts`, `pq-ratchet.ts` en `client.ts` (`enclave.pqRatchet.*`):
- `pq_ratchet.create_prekey_bundle`: maakt een responder-toestand en een 1646-byte bundel en geeft de passkey-uitdaging terug.
- `pq_ratchet.unlock_vault` / `lock_vault`: kluissleutel afleiden of laten vallen.
- `pq_ratchet.load_session_vault`: herstelt sessies na een herlaadbeurt.

Daarnaast:
- `secure.wipe` in `password-enclave.ts` vergrendelt de kluis, wist het sessiegeheugen en de sleutelbuffers, en beëindigt lopende sessies.
- Na een herlaadbeurt herstelt de client sessies automatisch, zodra de kluis is ontgrendeld.

## 4. Publicatie zonder SQL
- Een serverfunctie voor publicatie (alleen voor ingelogde leden, met hun eigen handle) controleert de passkey-handtekening tegen de geregistreerde passkey in `neon_auth.passkey`. Ze controleert ook het MDS3-oordeel via de bestaande attestatie-lees-functie en het formaat, de leeftijd en de context van het document.
- Daarna schrijft ze naar Scaleway (`putObject`, interne bucket) onder `users/<uid>/prekey-bundle.json`. Ze leest Neon alleen, en dat via bestaande functies.
- Publiek adres: `src/routes/$username_.prekey-bundle[.]json.ts`, opgebouwd zoals het bestaande `zkp-anchor.json`. Het geeft het opgeslagen document terug, of `404 not_available` als er geen is of als opslag niet is ingesteld.

## 5. Tests en controle
Nieuwe tests:
- `prekey-bundle.test.ts`: aanmaken, handtekening en context; verlopen, gewijzigde en niet-ondertekende bundels worden geweigerd.
- `pq-session-vault.test.ts`: met `fake-indexeddb` opslaan, overschrijven, herstellen na een gesimuleerde herlaadbeurt, en wissen plus verwijderen bij sluiten.
- Een integratietest met de 4 verplichte gevallen, plus de hele keten met nagebootste Scaleway-opslag: bundel maken, publiceren, handshake doen, versleutelde berichten uitwisselen.
- Een test dat `secure.wipe` het geheugen en de kluis volledig wist.

Daarna draai ik `bunx vitest run` (alles groen), `tsgo` (0 fouten) en `zk-wasm-pin.test.ts` (Wasm onveranderd).

## 6. Documentatie
- In `roadmap.md` vink ik de deeltaken van Stap 8 af.
- Onderaan `docs/HANDOVER.md` komt een nieuwe bijlage, "Bijlage: Stap 8 — Prekey Bundles en Encrypted Session Vault". De bestaande secties blijven letterlijk staan.
- In `AGENTS.md` komt één regel over de kluissleutel en het opslagpad.

## Wat ik niet kan controleren
In deze omgeving zijn geen Scaleway-sleutels en geen echte passkey of hardware. Publicatie en MDS3 test ik daarom met nagebootste opslag en vaste testgegevens. Een echte test op rout.be blijft daarna nodig.
