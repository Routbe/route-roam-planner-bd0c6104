# Roadmap

## ROUT Card tap (NTAG 424 DNA) — Batch 1
- [x] db/0245_sdm_tap.sql (EXPAND): fleet MetaRead key, batches, cards by uid_hash, tap attempts, tap grants, RPCs for rout_app only
- [x] sdm-verifier.ts: AN10922 diversification, PICCData decrypt, uid index, constant-time compares + NXP vectors
- [x] sdm-tap.server.ts + vault port methods; PGlite tests as rout_app
- [x] /t public tap page (PICCData only, no card id), "Authentic ROUT Card" badge, replaceState clears query
- [x] schema level 0245, snapshot + db types
## ROUT Card tap — later batches
- [x] Card tap step-up: "ROUT Card" method in the step-up dialog (Web NFC on Android, /t fallback for iPhone and other devices), accepted for card_reveal, card_lifecycle and general sensitive actions
- [x] db/0253 card revoke + 0250 audit fix (EXPAND, live on Neon)
- [x] Blocking or replacing the ROUT card revokes the member's physical cards (db/0253)
- [x] Test on real hardware: Android Chrome NFC scan, iPhone tap via /t, desktop + signed-in phone (owner-tested)
- [x] /t asks "Ja, ik bevestig" before a tap completes an open card step-up (an unrelated tap can no longer approve a request from another session)
- [x] Re-test the /t confirm button on iPhone (changed after the owner's hardware test; owner-confirmed 2026-11-13)
- [x] Admin batch screen (/admin/cards): create, station config export, manifest import; member activation (db/0246, live on Neon)

## Developer console
- [x] Billing page: plan without billing account, live limits from the enforced rules, fair use + link to API terms (nl/en/fr/de)

## Auth
- [x] Passkey-only registration enforced server-side (user.create hook + bridge refuses members without a passkey)

## Workspace Studio
- [x] New profile photo does not save in Workspace Studio: Studio uploads as workspace-logo, /api/public/avatar reads via rout_public_avatar (db/0251 live on Neon, public read verified)
- [x] Workspace logos: prune keeps every photo still in use (db/0252 rout_prune_avatar_uploads, live on Neon)
- [x] Workspace conversion: workspaces.avatar_url set from the live design's photo (conversionWorkspaceLogo)
- [ ] Converted workspace logo stored in the Neon fallback still belongs to the retired login (cascade on a hard user delete); copy it into the workspace owner's uploads if hard deletes are ever enabled
- [x] "ROUT OS v2.5 Alle systemen operationeel" overlaps bottom preview buttons on phone; check similar overlaps

- [x] 0247 hardening (live on Neon, verified): constant-time activation-hash compare, SERIALIZABLE + retry for consume/activate, deny-all RLS on vault_enclave (review before apply)
- [x] Station file v2: correct NDEF offsets, encrypted UID+counter, ChangeFileSettings payload
- [x] Key delivery to the personalisation station: HPKE P-256 sealed bundle (0248 live)
- [x] Station registry (0248) + HPKE-wrapped batch key export on /admin/cards, logged via mark_sdm_batch_exported
- [x] db/0249 (drop station-less export marker) moved into db/ after production reported 0248
- [x] db/0250 card tap as step-up factor (EXPAND, live on Neon)

## Beveiligingsmelding agenda's
- [x] Agenda toevoegen/verversen: max 20 per lid per uur (gedeelde teller, faalt dicht), melding in nl/en/fr/de + test

## Admin portal and Studio routing
- [x] Admin portal refuses non-admins in the UI itself (adminAccessDecision + AdminForbidden screen, nl/en/fr/de); server checks unchanged
- [x] /studio/booking lands on the bookings page: /studio accepts page=booking (src/lib/studio-page-param.ts) and Studio opens bookings from that routed value
- [ ] Signed-in click-through of the admin refusal screen and the bookings page: owner verifies on the Vercel deploy (no DATABASE_URL requested for the preview)

## Migratie-synchronisatie (2026-11-13)
- [x] Stap 1a: alleen-lezen analyse van 95/0169/0209/91 (verslag aan eigenaar)
- [x] Stap 1b: archief in db-archive/, erkende vingerafdrukken in scripts/migration-history-allowlist.ts, controle scripts/migration-history-check.ts (Neon: 251 rijen, 0 afwijkingen)
- [x] 0254: rout_pairwise_register op search_path = pg_catalog (live op Neon, gecontroleerd)
- [x] Afdwinging SECURITY DEFINER search_path: krimpende overgangslijst, lint + bewaking in beide runners vanaf 0255, test op snapshot, live controle (scripts/security-definer-check.ts)
- [x] Batch 1 — kaarten, kluis, inloggen: 21 functies (db/0255, live op Neon, 0 afwijkingen)
- [x] Batch 2 — werkruimtes, ouders, agent-sandbox: 36 functies (db/0256, live op Neon, 0 afwijkingen; 79 over)
- [x] Batch 3 — boekingen: 31 functies (db/0257, live op Neon, 48 over)
- [x] pg_temp-beleid: pg_catalog, pg_temp voor elke SECURITY DEFINER-functie (besluit eigenaar)
- [x] Batch 4 — de laatste 48 functies + pg_temp op alle 348 (db/0258, live op Neon, 0 open)
- [x] Rechtencorrectie interne hulpfuncties (db/0259, live op Neon, per functie nagekeken)
- [x] Herbouw uit db/ gelijk aan Neon voor alle functierechten (db/0260, op Neon aantoonbaar zonder effect)
- [x] db/0261 — drie ongebruikte SECURITY DEFINER-functies weg bij rout_app + samenvoegen met de handle van het tweede account herstellen (live op Neon 2026-11-13, per functie nagekeken)
- [x] 17 tabellen/reeksen: onderzoek per tabel klaar (bijlage J); voorstel db-pending/0262 getest
- [x] 0262 — overbodige tabelrechten van rout_app ingetrokken (live op Neon 2026-11-13, nagekeken), bestand in db/, schemaniveau 0262, volledige suite groen
- [x] auth_recovery_requests: besluit eigenaar — aparte SECURITY DEFINER-ingangen, geen policies
- [x] db/0263 (EXPAND) — ingangsfuncties voor herstelaanvragen geschreven en getest (bijlage K)
- [x] db/0263 live op Neon (2026-11-13, checksum gelijk, per functie nagekeken)
- [x] quarantine.server.ts gebruikt alleen nog de rout_recovery_*-functies (test tegen db/ + 0264, bijlage L)
- [x] Deze code op Vercel gezet door de eigenaar (health-probe meldde 0263, 2026-11-13 18:05 UTC)
- [x] 0264 (CONTRACT) in db/ en live op Neon (2026-11-13): rout_app heeft geen tabelrechten meer op auth_recovery_requests, schemaniveau 0264
- [ ] Productie opnieuw deployen zodat de health-probe 0264 meldt — eigenaar (geen haast: 0264 verandert alleen databaserechten)
- [x] Briefing in appendix van docs/HANDOVER.md (bijlage B letterlijk, bijlage C controle)
- [x] QA-testdraaiboek: docs/ROUT-QA-draaiboek.md (kopie in Files)
- [x] /t-schermen en knoppen in nl/en/fr/de (cardTap.* in interface-bundels); zegel "Authentic ROUT Card" blijft bewust Engels
- [ ] QA-draaiboek uitvoeren op het Vercel-deploy — eigenaar, met fysieke kaarten en toestellen

## Boekingssysteem topniveau (plan 2026-11-13)
- [x] Fase A: hoofdpagina/ontdek/about/info op alle formaten
  - [x] 12 formaten + liggend, geen overflow/afsnijding/CLS, contrast AAA, tikdoelen 44px, animaties alleen transform/opacity
  - [x] Per pagina titels/omschrijvingen NL/EN/FR/DE + eigen deelafbeelding
- [ ] Fase B: database (grootboek, agendakoppelingen, routering, locaties, annuleringsbeleid) — Neon pas na GO
  - [ ] B1: booking_events — onveranderlijk grootboek, hash-keten + server-ondertekening, overzicht ↔ grootboek-controle (db/0265, alleen test)
  - [ ] B2: agendakoppelingen Google/Microsoft/CalDAV — sleutels alleen als RVE1-envelop in vault_enclave (alleen test)
  - [ ] B3: publieke kant alleen anonieme tijdvakken/bitmasker (bevestigen + test)
  - [ ] B4: MCP-hulpmiddelen: vrije tijden lezen, reservering voorbereiden; bevestigen alleen na passkey/step-up van een mens
- [ ] Fase C: Google/Microsoft/CalDAV sync — wacht op OAuth-apps van eigenaar + host voor Omni-werker
- [ ] Fase D: gewogen beurtrol, routeringsvragen
- [ ] Fase E: vergaderruimtes, betalingen, annuleringsbeleid
- [ ] Fase F: boekings-, beheer- en hostpagina's, mails NL/EN/FR/DE
- [ ] Fase G: intake-versleuteling, ROUT ID, Wallet, MCP-hulpmiddelen

## Vervolg 2026-11-13 (goedgekeurd plan)
- [x] Stap 0: 0265 greatest/least hersteld, naar db-pending tot GO
- [x] Stap 0: volledige testsuite groen (2805/2805)
- [x] Fase A: 12 formaten + liggend — geen overloop; 9-delige reeks en omgevingsknop op gsm opgelost
- [x] Fase A: taal al juist vanaf de server (geen Engels→Nederlands-wissel meer), lege flits bij laden weg; verspringen (CLS) overal < 0,07
- [x] Fase A: alle knoppen en links op de gemeten openbare pagina's ≥ 44×44 px (AAA), grijze tekst ≥ 7:1 contrast
- [x] Fase A: titel, omschrijving en deelafbeelding 1200×630 per pagina in NL/EN/FR/DE nagekeken (6 hoofdpagina's × 4 talen)
- [x] Fase A: brede meting op alle 47 overige about-, info- en ontdekpagina's (3 formaten): 0 fouten
- [x] Fase A: voor/na-overzichtsbladen per pagina op 11 formaten (Files: fase-a/)
- [x] Testsuite 2854/2854 groen (2 klokafhankelijke/trage tests robuust gemaakt)
- [ ] Fase B: zero-knowledge (client-side E2EE, blinde indexen, grootboek-invarianten) vanaf de eerste migratie
- [ ] Fase G: W3C Verifiable Credentials / selectief-onthullend bewijs voor gastverificatie
- [x] Fase B: herstel 2-van-4 (passkey, ROUT-kaart, server, papier) — cryptokern + werker + tests; kaartgeheim alleen in URL-fragment
- [x] Fase B: db-pending/0266 kaartdeel herstel — getest in testdatabase (wacht op GO)
- [x] Fase B: herstel aangesloten op scherm, opslag en herstel-login — nu als 3-van-4 (kaart tikken, 3 stukken kiezen)
- [ ] Fase B: kaarten (her)personaliseren met #rk1-fragment (fabrieksstation) — fysieke kaarten nodig
- [x] Fase B: versleutelde boekingsinhoud (bkh/bkg, ML-KEM-1024 + X25519, vaste emmers) — kern + tests
- [ ] Fase B: 0265 grootboek aanpassen: vingerafdruk over versleutelde tekst i.p.v. platte velden
- [ ] Fase B: migratie boekingsenveloppen + host-boekingssleutel (zaad onder werkruimtesleutel) + werker-ops
- [ ] Fase B: gastcontact (e-mail) als kluisverwijzing + blinde index voor limieten per gast
- [ ] Fase B+: vaste byte-lengtes (padding) en constante responstijden voor boekings- en bitmasker-API's
- [ ] Fase B+: Omni-werker als blinde doorgeefluik, nooit toegang tot persoonlijke sleutels

## Stap 0 + Fase A (GO 2026-11-13)
- [x] Vier migratie-afwijkingen alleen-lezen vastgelegd (HANDOVER-bijlage)
- [x] db-pending/README en QA-draaiboek op stand 0266 gezet
- [x] Volledige testronde: 1 rood (verouderde telling kaarttap-teksten) hersteld
- [x] /t vaste Engelse tekst vertaald; inzoomen op telefoon toegestaan; taalkeuze metadata = root
- [x] Fase A meetronde (11 formaten: home, discover, about, info, bookings-info): geen overloop/afsnijding, CLS ≤ 0,1; te kleine tikdoelen (footer-credit, kruimelpad SEO-pagina's) hersteld
- [x] Fase A: onthul-animaties: inhoud zichtbaar vóór en zonder de pagina-code; alleen blokken onder de vouw vervagen in
- [x] Fase A: CLS kwam van de lettertypewissel; reserve-lettertypes met dezelfde maten + voorladen → max 0,0007 op 66 metingen
- [x] Fase A: contrast AAA: axe (7:1) + pixelmeting onder de letters; lichtkrant, privélijst, voorbeeldkaart en gekozen tab hersteld; 0 fouten
- [ ] Boekingspagina's meten (geblokkeerd: preview heeft geen database)

## Fase B–G extra veiligheidslagen (eis eigenaar 2026-11-13)
- [ ] Hardwarebinding: apparaatsleutels alleen te openen met een passkey-PRF van een geattesteerde hardware-authenticator (TPM 2.0 / Secure Enclave)
- [ ] Geheugen-wiping: één vooraf toegewezen werkergeheugen voor sleutel- en klare bytes, nulgezet na elke bewerking + test
- [ ] Property-based tests (fast-check) + begrensde modelcontrole voor grootboek, hash-ketens, reserveringssloten en statusovergangen — vereist vóór GO per migratie
- [ ] BBS+ (BLS12-381) blinde credentials + zero-knowledge-bewijs bij aankomst; server bewaart alleen een nullifier per tijdslot
- [x] Besluit eigenaar: herstel 3-van-4 (vervangt 2-van-4 uit bijlage O)
- [x] Fase B: recovery-mpc versie 3 (drempel 3 van 4), werker, server, /t-doorgifte, schermen; modelcontrole 16 deelverzamelingen + fast-check
- [x] GO eigenaar: 0267 (kaarttik "dit is mijn kaart") live op Neon 2026-11-14 12:12 UTC, in db/
- [ ] GO eigenaar: db-pending/0268 (opslag 3-van-4) op Neon — tot dan weigert de app elke nieuwe kluis
- [ ] Na deploy met niveau ≥ 0268: db-pending/0269 (oude 2-van-3/2-van-4-opslag weg, alleen versie 3) — GO eigenaar
- [ ] Doorkliktest 3-van-4 op echte telefoon met een kaart mét #rk1-fragment
- [x] Besluit eigenaar: pseudoniem per host — limieten per host, niet te volgen tussen hosts, mail via kluisverwijzing

## Ronde J (plan 2026-11-14, GO plan)
- [x] Bindende regels F, H en I in src/lib/booking-engine/AGENTS.md
- [x] 0267 + rollback gecorrigeerd: doel 'activation' (db/0246) bleef weg → elke kaartactivatie zou falen; nu behouden + bewaking in het DO-blok + test die activatie na 0267 en na rollback doet
- [x] Testsuite: 3 bestanden faalden op het laden van een font-bestand (`?url`) buiten de projectmap; vitest-config staat de echte node_modules-map toe
- [x] Alleen-lezen controles 0267 op Neon (geen tap-rijen, constraint met activation, functie = db/0245+0258, rechten in orde, 0267 nog niet toegepast)
- [x] 0267 toegepast (één transactie), checksum/rechten/constraint nagekeken, CODE_SCHEMA_LEVEL 0267
- [x] Stap 2: TLA+-model herstel v4 (formal/recovery-v4) + TLC in CI (.github/workflows/tla-recovery-v4.yml): 3 hoofdmodellen groen, 5 mutanten breken, 10 getuigen bereikt
- [ ] Stap 2 nazorg: eerste CI-run op GitHub bekijken zodra de code daar staat
- [x] Stap 3 code: OPAQUE + Argon2id (Wasm, vast geheugen) + Hashcash-PoW aangesloten: plugin in Better Auth, gewone wachtwoorden uit, /secure/password (inloggen), /secure/password/new (aanmelden), /secure/password/set (instellen/verwijderen met passkey-step-up), extra voorzichtig typen, wissen na 30 s weg
- [x] Stap 3 live: 0270 toegepast op Neon (GO eigenaar 2026-11-14 15:55 UTC), bestand in db/, CODE_SCHEMA_LEVEL 0270
- [ ] Stap 3 eerste inlogtest: wacht op deploy van deze code naar Vercel met ROUT_VAULT_KEK gezet (eerste wachtwoord maakt de server-sleutel en OPAQUE-setup)
- [ ] Stap 6: 0268/0269 bij herschrijven voor v4 hernummeren boven 0270 (anders kan de health-probe de EXPAND niet bewijzen)
- [ ] Stap 3 nazorg: /secure/* krijgt bij hosting op Vercel dezelfde headers (nu via src/server.ts); de algemene securityHeaders() worden nergens toegepast (bevinding, niet gewijzigd)
- [x] Stap 4: Veiligheidsschild (3 niveaus) in topbalk, NL/EN/FR/DE (GO eigenaar 2026-11-14, geen migratie)
  - [x] Berekening getSovereigntyHealthScore + tests (besluit A: niveau 3 = kaart + passkey; besluit B: bevroren kaart schort 3 op)
  - [x] Serverfunctie (alleen lezen: passkeys, pake_registered, member_card_factor, kaartstatus)
  - [x] Knop in topbalk (44×44, geen verspringen) + paneel/lade, 3 kleurtokens met contrasttest ≥ 7:1
  - [x] Teksten NL/EN/FR/DE + vertaaltest
  - [x] Opnieuw controleren na passkey/kaart-wijzigingen; geen timers/luisteraars die blijven hangen (geheugentest)
  - [x] AGENTS.md bijwerken; volledige tests + typecheck
  - [ ] Doorkliktest met een echt ingelogd account (wacht op deploy naar Vercel)
- [ ] Stap 5: FIDO MDS3-attestatie (Level 9)
  - [x] MDS3 BLOB ophalen, JWS + x5c naar gepinde GlobalSign R3, CRL, serienummer, cache; attestatie-engine (packed/tpm/apple), status- en certificatiecontrole; niveau 3 = kaart + gecertificeerde sleutel; RVE1 pak; db-pending/0271 + rollback; tests
  - [x] 0271 live op Neon (GO eigenaar 2026-11-14)
  - [ ] Android Key: KeyDescription-niveaus en RootOfTrust parsen (telt nu nooit als geattesteerd)
  - [ ] Eerste echte registratie met een beveiligingssleutel na deploy (vereist ROUT_VAULT_KEK)
- [x] Stap 7: anonieme boekingsmotor — kern 7a–7f af, 0273 live op Neon (GO eigenaar 2026-11-15); open punten hieronder zijn nazorg en 7g (besluiten eigenaar 2026-11-14: pseudoniem per boeking, eigen allocatorvrije Rust-Wasm op zkcrypto bls12_381)
  - [x] 7a: wasm/rout-zk (no_std, geen allocator, geen memory.grow, vaste geïmporteerde memory, volatile wissen, subgroepcontrole G1/G2, `subtle`)
  - [x] 7a: BBS (KeyGen/Sign/Verify/ProofGen/ProofVerify) + Blind BBS (Commit/BlindSign/VerifyBlindSign/BlindProofGen/BlindProofVerify met COMMIT-onthulling); alle 49 officiële fixtures byte-gelijk (cargo test)
  - [x] build.sh + SHA-384-pin + loader voor rout-zk: officiële rustup 1.95.0 (LLVM 22.1.2), 2× uit verse mappen gelijk, pin a4a02c5f…540c, CI-job rout-zk in wasm-reproducible.yml (7f)
  - [ ] Timingmeting (dudect) van de gegenereerde Wasm
  - [x] 7d: forward-secure hostsleutels — HKDF-SHA256-ratchet per epoch (SK_0 uit vers random seed), oude staat in place gewist, ondertekende epoch-links vanaf anker PK_0, credentials (ook blind) gebonden aan sleutel-id + epoch; worker-ops host_key.init / advance_epoch / sign_credential / chain / verify_epoch_credential
  - [x] 7d vervolg: besluit bewaren SK_t (eigenaar 2026-11-14): alleen de actuele staat, als RVE1-envelop (kind 9 hsk) onder de Master KEK in vault_enclave; tabel staat in db/0273
  - [x] 7f: SK_t onder de Host Device Key — hsk (kind 9, holder member_device) in pqc-envelope.ts, verzegeld/geopend alleen in de worker (host_key.init/advance geven sealedState, host_key.restore controleert tegen de publieke keten + high-water mark); 0273 eist holder 2, 1703 bytes
  - [x] 7d vervolg: PK_0 gebonden aan het hostrecord bij init (anon_host_keys, db/0273), handtekening + ondertekenaar opgeslagen; keten publiek leesbaar via anon_host_chain
  - [x] 7f: ankerhandtekening = BBS van een device-seed-sleutel over [sleutel-id, PK_0, boom-id] (host_key.sign_anchor / verify_anchor)
  - [x] Besluit (eigenaar 2026-11-15): PK_0 op het publieke hostprofiel (`/@host/zkp-anchor.json`), ondertekend met de MDS3-geattesteerde hardwaresleutel van de host; epoch = 24 uur, overgang om 00:00 UTC
  - [x] 7b: Pedersen-commitments (homomorf optellen/aftrekken) + Bulletproofs-range-proofs v ∈ [0, 2^64−1] in rout-zk; worker-ops pedersen.commit / bulletproofs.prove_range / bulletproofs.verify_range
  - [x] 7f: a ≤ t ≤ b — slot als RAW-bericht in het credential, bij aankomst COMMIT-onthulling + twee range proofs (generatoren Y_1, Y_0) gebonden aan challenge/venster/C; capaciteitspools (C_rem,i = C_rem,i−1 − C_take,i, bewijs take ≥ 1 en rest ≥ 0) in rout-zk ABI 5 + 0273
  - [ ] Externe audit van de eigen BBS-, Bulletproofs-, Poseidon- en SMT-code (regel 'audited libraries' in booking-engine/AGENTS.md)
  - [x] 7c: Poseidon (referentie x5_255_3, constanten via Grain herberekend en gelijk) + 256-diepe nullifier-SMT met NonExist/Exist, hergebruik geweigerd; ondertekende root (BBS, eigen sleutel uit device-seed) per epoch; worker-ops smt.genesis / smt.insert_nullifier / smt.verify_non_membership / smt.verify_signed_root
  - [ ] 7c vervolg: blijvende bescherming tegen terugdraaien van een oude ondertekende root (nu alleen high-water mark in het werkgeheugen) via externe verankering
  - [x] 7c vervolg: meerdere toestellen van één host — elk toestel eigen keten, boom en rootsleutel (0274, live op Neon)
  - [x] 7a: pseudonyms.ts + worker-op `pseudonym.derive` (HKDF-Expand + HMAC-SHA256, gedeelde vector met Rust)
  - [x] 7f: gast-adapters in de worker (anon_guest.begin/accept/present/discard, anon_host.verify_presentation, capacity.*), geheimen alleen in de worker
  - [x] 7f: eigen anonieme ledger (anon_ledger_events, hash-keten per boom, client-verifier anon-ledger.ts byte-gelijk aan SQL); 0265 ongemoeid
  - [x] 7f: end-to-end test (worker + 0273 op PGlite): twee anonieme gasten, dubbel uitgeven geweigerd, derde plaats onmogelijk, herladen via verzegelde staat
  - [x] Gast-credential bewaren tussen boeking en aankomst: versleuteld in vault_guest_storage (7g)
  - [x] Besluit (eigenaar 2026-11-15): master_seed van de gast uit de WebAuthn-`prf`-extensie (zonder PRF: HKDF over de assertion-handtekening); lopende bewijzen en SK_guest in IndexedDB `vault_guest_storage`, versleuteld onder die lokale sleutel
  - [x] 7e: db-pending/0273 + idempotente rollback (deny_all, definers, 7 audit-acties) + PGlite-test (replay → 0273 → rollback → 0273, schema-vingerafdruk gelijk, fast-check-model + 2×70 interleavings)
  - [x] Volledige suite + typecheck
  - [x] 7f: account purge (rout_anon_booking_purge, alleen als de verwijdering vervallen is) en merge (rout_anon_booking_merge in execute_account_merge); alle anon-FK's ON DELETE RESTRICT; ENCLAVE_MERGE_TABLES
  - [x] 0273 naar db/, CODE_SCHEMA_LEVEL 0273, schema-snapshot uit de replay (geen rijtypes voor vault_enclave), alle tests en dry-run van het uitrolscript groen
  - [x] Besluit (eigenaar 2026-11-15): elk hosttoestel een eigen keten SK_t,dev, geregistreerd als toegestaan toestel onder de Host Root Identity
  - [x] 0273 live op Neon (GO eigenaar 2026-11-15, 07:39 UTC) via scripts/migration-rollout.ts: één transactie, checksum c0d26bd1…b458 in de transactie gecontroleerd, alle vingerafdrukken gelijk aan de replay
  - [ ] Productie meldt 0273 pas na een deploy naar Vercel (health meldt nu 0272)
- [x] Stap 7g: besluiten eigenaar 2026-11-15 gebouwd (GO eigenaar 2026-11-15; goedgekeurd)
  - [x] guest-vault.ts: seed uit WebAuthn PRF (fallback HKDF over de handtekening, alleen als twee assertions byte-gelijk zijn), SK_guest + boekingen als AES-256-GCM in IndexedDB vault_guest_storage (emmers van 4096 bytes), worker-ops guest_vault.unlock/lock, herladen getest
  - [x] guest-passkey.ts: PRF-assertion en gast-passkey aanmaken in de browser (nog geen scherm)
  - [x] /@host/zkp-anchor.json: route + document per toestel (PK_0, links, passkey-assertion, MDS3-oordeel); verifier voor gasten (ES256/EdDSA/RS256); geeft 404 not_available tot 0274 live is
  - [x] Dagelijkse ratchet 00:00 UTC (epoch = UTC-dag): DailyEpochRatchet, inhaalsprong, single-flight, opnieuw versturen; Wasm-geheugen na de stap nul, oude SK in place overschreven, nieuwe envelop in de eigen vault_enclave-rij
  - [x] 0274 + rollback: anon_host_devices, anon_anchor_endorsements, één live keten per toestel (max 16), register/revoke/list/passkey/publiek anker, purge en merge uitgebreid; PGlite 0267→0273→0274→rollback→0274 groen
  - [x] Volledige suite 3124 groen (9 overgeslagen), tsgo 0 fouten, HANDOVER-bijlage
  - [x] 0274 op Neon (GO eigenaar, 2026-11-15 08:35 UTC, migration-rollout.ts in één transactie; 7 vingerafdrukken gelijk aan de replay), naar db/, CODE_SCHEMA_LEVEL 0274, snapshot
  - [ ] Productie meldt 0274 pas na de volgende deploy
  - [ ] Serverfuncties + schermen: host registreert toestel en start de ratchet; gast opent kluis en boekt (nu alleen bouwstenen + tests)
  - [ ] Keten vol na 1024 links (≈ 2,8 jaar dagelijks): oude keten intrekken en een nieuwe op hetzelfde toestel registreren (0274 laat dat toe), nog geen scherm
- [ ] Stap 8: hybride PQ-ratchet + RVE2 (GO eigenaar 2026-11-15; geen SQL)
  - [x] wasm/rout-zk pq_ratchet.rs: ML-KEM-1024 + X25519 root-stap (HKDF, X-Wing-binding), HMAC-keten met volatile wipe, AES-256-GCM + HMAC in RVE2, out-of-order (max 64 per gat, 64 sleutels), atomisch (state alleen bij succes)
  - [x] ABI 6, reproduceerbare build (officiële 1.95.0, 2x gelijk), nieuwe pin; 10 nieuwe Rust-tests (68 totaal)
  - [x] Worker-ops pq_ratchet.init_session / ratchet_encrypt / ratchet_decrypt / close_session + client; secure.wipe wist sessies; worker-test
  - [x] Prekey-bundle (1646 B) ondertekend met MDS3-geattesteerde passkey; worker weigert elke initiator-handshake zonder geldige handtekening, MDS3-pass of binnen 30 UTC-dagen (`bundle_rejected`)
  - [x] Publicatie zonder SQL: serverfunctie `publishMyPrekeyBundle` controleert passkey + MDS3 en schrijft naar Scaleway `users/<uid>/prekey-bundle.json`; publiek op `/@handle/prekey-bundle.json`
  - [x] Sessies bewaren over herladen: versleutelde IndexedDB `vault_ratchet_sessions` (AES-256-GCM, 12 KiB-buckets, schrijven vóór resultaat, nullen + verwijderen bij sluiten); worker-ops create_prekey_bundle / unlock_vault / lock_vault / load_session_vault
  - [x] Tests: prekey-bundle, pq-session-vault, integratie (4 verplichte gevallen + E2E met nagebootste Scaleway); Wasm-pin onveranderd
  - [ ] Echte test op rout.be met hardware-passkey en Scaleway-sleutels
  - [ ] Schermen/transport voor berichten en status-updates
  - [ ] Externe audit + dudect voor de ratchet en de gebruikte RustCrypto-crates
- [ ] Stap 9: RLS non-interference-model (Z3) vergeleken met de snapshot in CI (GO eigenaar 2026-11-15; Neon niet aangeraakt)
  - [x] scripts/formal-rls-verifier.ts: parser voor alle policy-expressies, Z3-bewijs per tabel/commando/fase (1210 verplichtingen, 519 Z3-checks), vault_enclave deny-all, search_path van 415 definers, views, unieke-sleutel-orakels
  - [x] src/test/rls-non-interference.test.ts: bewijs op de snapshot, mutaties worden gevangen, PGlite-aanvallen (cross-tenant, vervalste rijen, injectie op elke rout_app-definer, vault_enclave)
  - [x] db-pending/0275 + rollback: F4/F5 (schrijfbare/eigenaarsviews), F7 (zelf lid/eigenaar worden van elke workspace), F8a (rij planten in vreemde workspace); getest op PGlite
  - [ ] GO eigenaar voor 0275 op Neon
  - [ ] F1 profiles volledig leesbaar (EXPAND/CONTRACT), F2 social_links, F3 workspaces.legacy_user_id, F6 orakels, F8b UPDATE naar vreemde workspace, F9 rout_resolve_account geeft e-mail
  - [ ] neon_auth (Better Auth) buiten het RLS-model: eigen rol voor de auth-adapter
- [x] /secure/*-documenten met COOP/COEP (wachtwoordpagina's)
- [x] Wasm SRI (SHA-384) en reproduceerbare build van de wachtwoordmotor: officiële rustup 1.95.0 (LLVM 22.1.2) vastgezet, pin opnieuw gezet, CI .github/workflows/wasm-reproducible.yml (lokaal 2x uit twee mappen gelijk)
- [ ] Wasm-CI nazorg: eerste run op GitHub bekijken zodra de code daar staat
- [ ] Kluis- en herstelschermen ook naar /secure/*
- [ ] Stap 6: dynamisch herstel v4 (2-van-3 → 3-van-4, TLA+-gevolgd)
  - [x] Shamir GF(2^8) constant-time in de gepinde Wasm-engine (officiële toolchain), herbouw + pin
  - [x] recovery-v4.ts: verse generatiesleutel per ceremonie, beleid 2of3/3of4, commitments, uitsluiting gecompromitteerd deel, commit-laag
  - [x] TLA+: gecompromitteerd deel (CompromiseContained + mutant + getuigen), TLC groen
  - [x] db-pending/0272 + rollback (vault_enclave, deny-all, definers, audit-acties, TTL 10 min)
  - [x] Server-stappen (RecoveryV4Store) + PGlite-scenariotest per modelactie
  - [x] Tests: 3-uit-4, 2-uit-4 faalt, foute hash, rotatie, nul-geheugen, PGlite 0272 + rollback; typecheck
  - [ ] Server-functies + schermen die RecoveryV4Store aanroepen (crypto in de enclave-worker); cron voor recovery_v4_expire_due
  - [x] 0268/0269 naar db-archive/ (eigenaar 2026-11-14)
  - [x] 0272 live op Neon (GO eigenaar 2026-11-14), byte-gelijk met de replay

## Stap 10 (herzien, wacht op Approve)
- [ ] Rollout 0276 op Neon + CODE_SCHEMA_LEVEL 0276
- [ ] Wesolowski VDF: RSA-2048 + class groups (geen trusted setup), allocator-vrij, volatile wipe
- [ ] Hybride PQ-Noise tunnel (ML-KEM-1024 + X25519, IKpsk2-basis)
- [ ] Dudect-audit: 1M iteraties, 10k warm-up, --expose-gc, ook PRF- en AES-GCM-AAD-pad
- [ ] Backfill-/verificatiescript 0276 -> 0277 en Z3-certificering 0277
