# Dossier passif : 90.98.0.0/18 annoncé par AS54113

**Origine du dossier :** bgpmon v3 a levé l'alerte `MORE_SPECIFIC_UNEXPECTED` (sévérité critique) pour la cible `90.98.0.0/15`. Le préfixe `90.98.0.0/18` est annoncé par AS54113 (Fastly, Inc.) à l'intérieur d'un espace attribué historiquement à Orange (AS3215).

**Date de rédaction :** 21/10/2026. La collecte automatique s'est déroulée le 21/10/2026 de 08:01:15 à 08:09:51 UTC. Une exploration manuelle préalable a eu lieu entre 07:20 et 07:50 UTC ; ses résultats sont identiques.

**Méthode :** sources publiques uniquement, consultées en lecture seule, sans aucun scan de l'espace IP. Chaque constat renvoie à un fichier de [`raw/`](raw/) (source, requête, horodatage, SHA-256 : voir [`INDEX.json`](INDEX.json)). Les constats bruts générés automatiquement sont dans [`OBSERVATIONS.md`](OBSERVATIONS.md).

> Ce document distingue (a) les **observations** datées et sourcées, (b) les **hypothèses**, et (c) ce qui **n'a pas pu être vérifié**. Il ne contient aucune conclusion d'attribution.

## Résumé

1. **Registre.** Le RIPE NCC enregistre le **transfert de 90.98.0.0/16 d'Orange S.A. vers Fastly, Inc.**, daté du **03/09/2026** (statistiques officielles des transferts). L'inetnum `90.98.0.0 - 90.98.255.255` est depuis cette date une allocation `ALLOCATED PA` de l'organisation `ORG-FI26-RIPE` (Fastly, Inc.), créée le 03/09/2026 à 07:43:08 UTC.
2. **Liste officielle de Fastly.** La liste publique d'adresses de Fastly contient `90.98.0.0/17` et `90.98.128.0/18`. Aucune archive Wayback Machine jusqu'au 16/08/2026 ne les contenait.
3. **Retrait par Orange.** AS3215 a retiré `90.98.0.0/16` entre le 01/09/2026 13:09 et le 02/09/2026 07:02 UTC, soit environ 24 h avant la date d'enregistrement du transfert.
4. **Apparition du /18.** Il est apparu le **05/10/2026 à 03:03:15 UTC**. Pendant environ 15 h, il a été propagé **exclusivement via AS5511 (Opentransit, Orange)**, puis par les transitaires habituels de Fastly.
5. **AS5511 déclare un transit pour Fastly depuis 2020.** La politique publique d'AS5511 contient `accept AS54113` / `announce ANY` depuis la version de l'objet du 08/07/2020.
6. **Points de vigilance :**
   - aucune ROA ne couvre le /18 (RPKI `unknown`) ;
   - l'objet RADB du /18 a été modifié environ 8 h 45 après la première annonce ;
   - AS174 (Cogent), premier upstream habituel de Fastly, ne transporte pas ce préfixe ;
   - les objets ALTDB `90.98.0.0/15` d'origine AS41128 et AS270118, liés à l'incident d'avril, existent toujours.

## Chronologie

Heures en UTC. La granularité de `routing-history` est de 8 h ; les dates à la seconde viennent de BGPlay.

| Date | Événement | Source (fichier `raw/`) |
|---|---|---|
| 2019-04 → aujourd'hui | AS3215 annonce `90.99.0.0/16` sans interruption notable | `routing_history_full` |
| avant le 24/02/2026 | Aucune annonce de `90.98.0.0/16` ni du /15 visible par plus de 10 peers RIS depuis 2008. Seul `90.99.0.0/16` (AS3215) est routé dans le /15. | `routing_history_full` |
| 24/02 → 10/03/2026 | `90.98.0.0/15` originé par AS41128 (jusqu'à 292 peers). Retrait le 10/03 entre 00:14 et 19:26. | `routing_history_400d`, `bgplay_withdrawal_2` |
| 11/04 → 21/04/2026 | Nouvelle annonce de `90.98.0.0/15` par AS41128 (jusqu'à 332 peers). Annonce de `90.98.0.0/16` par AS41128 à faible visibilité (12 peers) les 21 et 22/04. | `routing_history_400d` |
| 20/04/2026 12:45 | ROA `90.98.0.0/16` AS3215, maxLength 16 (`not_before` de la ROA) | `roa_archive` |
| 19-20/04/2026 | AS3215 annonce `90.98.0.0/16` (granularité 2 jours ; le rapport d'enquête donne le 20/04 à 15:01) | `routing_history_400d` |
| 21/04/2026 01:25 → 17:59 | Retrait de `90.98.0.0/15` (AS41128) par les peers RIS | `bgplay_withdrawal_1` |
| 24/08/2026 | La ROA `90.98.0.0/16` AS3215 est présente dans l'archive du 24/08 et absente de celle du 25/08. La ROA restante, `90.99.0.0/16`, est re-signée le 24/08 à 08:34:28. | `roa_archive` |
| 01/09 13:09 → 02/09/2026 07:02 | Retrait de `90.98.0.0/16` par AS3215 (335 peers au départ, 1 à la fin de la fenêtre) | `bgplay_withdrawal_0` |
| 03/09/2026 07:43:08 | Découpage dans la base RIPE : création de l'inetnum `90.98.0.0 - 90.98.255.255` (`US-FASTLY-20060302`, `ORG-FI26-RIPE`), en même temps que `90.99.0.0 - 90.127.255.255` (`FR-TELECOM-20060302`, `ORG-FT2-RIPE`) | `ripe_inetnum`, `ripe_historical_inetnum` |
| 03/09/2026 | Transfert `RESOURCE_TRANSFER` 90.98.0.0–90.98.255.255, Orange S.A. (FR) → Fastly, Inc. (US). Ensemble d'origine : 90.98.0.0–90.99.255.255. | `ripe_transfers` |
| 03/09 → 05/10/2026 | Aucune route pour `90.98.0.0/16` ni ses plus-spécifiques (visibilité ≥ 10 peers) | `routing_history_400d` |
| 05/10/2026 03:03:15 | Première annonce de `90.98.0.0/18` par AS54113, chemin `215628 12577 33891 1299 5511 54113` | `bgplay_appearance` |
| 05/10/2026 03:03 → ≈ 18:00 | 100 % des annonces RIS du /18 ont AS5511 comme upstream (622 annonces dans l'heure 03:00) | `bgplay_appearance` |
| 05/10/2026 11:49:37 | `last-modified` (et `changed`) des objets RADB `90.98.0.0/18` et `90.98.128.0/18`, origine AS54113, `MAINT-AS54113` | `irr_RADB_exact`, `irr_RADB_more` |
| 05/10 ≈ 18:00 → 06/10/2026 | Bascule vers les transitaires de Fastly (AS12956, AS1299, AS9002, AS2914, AS3356, AS6762…) | `bgplay_appearance` |
| 16/08 → 21/10/2026 | `90.98.0.0/17` et `90.98.128.0/18` apparaissent dans `api.fastly.com/public-ip-list` : absents de l'archive du 16/08, présents le 21/10 | `provider_list`, `provider_list_wayback` |
| 21/10/2026 | `90.98.0.0/18` (AS54113) vu par 162 peers RIS sur 164. RPKI `unknown`. | `routing_status_prefix`, `rpki_validation` |

## (a) Observations

### 1. Routage

| # | Constat | Source | Horodatage |
|---|---|---|---|
| R1 | Seule origine du /18 : AS54113 (186 routes RIS sur 186) | `bgp_state_prefix` | état RIS du 21/10/2026 05:59:55 |
| R2 | Le /15 ne contient aujourd'hui que deux routes : `90.99.0.0/16` (AS3215) et `90.98.0.0/18` (AS54113). Il n'y a pas d'autre plus-spécifique : le /18 est **isolé** dans la table de routage. | `routing_status_covering` | 21/10/2026 |
| R3 | Upstreams actuels d'AS54113 pour le /18 : AS1299 (23), AS3356 (16), AS2914 (16), AS6762 (10), AS9002 (9), AS6939 (7), AS3257 (7), AS34549 (6). Longueur moyenne du chemin : 2,88 sauts. | `bgp_state_prefix` | 21/10/2026 |
| R4 | Six préfixes de référence d'AS54113 (`151.101.0.0/16`, `199.232.0.0/16`, `146.75.0.0/17`, `146.75.128.0/17`, `167.82.0.0/17`, `140.248.0.0/18`) ont pour upstreams principaux AS174, AS2914, AS37662, AS3356, AS1299, AS9002 et AS6939. **98,9 %** des routes du /18 passent par un upstream présent dans la référence. | `bgp_state_reference_*` | 21/10/2026 |
| R5 | **AS174 (Cogent)** ne transporte pas le /18, alors qu'il porte 90 routes de la référence. AS37662 non plus (68 routes de référence). | `bgp_state_*` | 21/10/2026 |
| R6 | À l'apparition, le /18 est propagé uniquement via **AS5511** de 03:03 à environ 18:00. Les transitaires habituels de Fastly n'apparaissent qu'ensuite (voir la chronologie heure par heure dans `OBSERVATIONS.md`). | `bgplay_appearance` | 05-06/10/2026 |
| R7 | La première période de `routing-history` commence le 05/10 à 08:00, et non à 03:03. Ce décalage s'explique par la méthode de RIPEstat (instantanés toutes les 8 h, seuil de 10 peers). | `routing_history_appearance` | — |
| R8 | **Avant l'incident** (avant le 24/02/2026), seul `90.99.0.0/16` (AS3215) était routé dans le /15. `90.98.0.0/16` n'avait aucune annonce visible depuis 2008. Les seules annonces couvrantes visibles remontent à 2004-2008 (`90.0.0.0/8` AS19962, `90.0.0.0/7` AS3352, `0.0.0.0/1` AS1299). | `routing_history_full` | historique depuis 2000 |
| R9 | **Après le retrait du 21/04/2026**, `90.98.0.0/16` et `90.99.0.0/16` sont annoncés par AS3215. Le /16 l'est jusqu'au 02/09/2026, le /16 voisin sans interruption depuis. Upstream d'AS3215 : AS5511 pour 320 peers sur 335. | `routing_history_400d`, `bgplay_withdrawal_0` | 19/04 → 02/09/2026 |
| R10 | AS54113 annonce **1811 préfixes** (fenêtre du 07/10 au 21/10/2026). Le /18 est le seul situé dans 90.98.0.0/15. | `announced_prefixes_asn` | 21/10/2026 |

### 2. RPKI

| # | Constat | Source |
|---|---|---|
| P1 | Validation actuelle de (90.98.0.0/18, AS54113) : **`unknown`**, aucune ROA (validateur Routinator, via RIPEstat) | `rpki_validation` |
| P2 | Les archives quotidiennes du RIPE NCC (15 dates du 20/02 au 20/10/2026, SHA-256 vérifiés) ne contiennent **aucune ROA pour 90.98.0.0/15, ni pour 90.98.0.0/18, ni pour AS54113** dans ce bloc. | `roa_archive` |
| P3 | ROA d'Orange `90.98.0.0/16` AS3215 maxLength 16 : présente du 21/04 au 24/08/2026 (`not_before` 20/04/2026 12:45:26), absente à partir du 25/08/2026 | `roa_archive` |
| P4 | ROA d'Orange `90.99.0.0/16` AS3215 maxLength 24 : présente sans changement à toutes les dates. Seules les dates de re-signature évoluent ; ses attributs (origine, préfixe, maxLength) n'ont **pas changé depuis avril**. | `roa_archive` |

### 3. IRR

| # | Constat | Source |
|---|---|---|
| I1 | RADB : `route 90.98.0.0/18`, origin AS54113, descr « Fastly », mnt-by `MAINT-AS54113`, last-modified 2026-10-05T11:49:37Z. L'attribut `changed` porte la même date (adresse masquée, domaine fastly.com). RADB n'expose pas de date de création. | `irr_RADB_exact` |
| I2 | RADB : `route 90.98.128.0/18`, origine AS54113, même maintainer et même horodatage. **Cette route n'est pas annoncée.** | `irr_RADB_more`, `routing_status_covering` |
| I3 | `MAINT-AS54113` (descr « Fastly, Inc. », admin-c `TECHOPS-FASTLY`, last-modified 2025-10-22) maintient 4952 objets, dont 4946 d'origine AS54113. C'est un maintainer actif et ancien. | `irr_RADB_mnt_MAINT-AS54113`, `irr_RADB_mntner_MAINT-AS54113` |
| I4 | ALTDB : deux objets `route 90.98.0.0/15`, origines **AS41128** et **AS270118**, mnt-by `MAINT-SPRINT`, descr « SprintLink - FR Telco », `changed` déclaré en 2022. Ils sont **toujours présents**. ALTDB n'authentifie pas les objets par rapport au registre. | `irr_ALTDB_covering` |
| I5 | `MAINT-SPRINT` (ALTDB) maintient 25 objets, dont 15 d'origine AS270118 | `irr_ALTDB_mnt_MAINT-SPRINT` |
| I6 | ALTDB : `route 90.99.0.0/16`, origine AS3215, descr « IPv4 Allow », mnt-by `MAINT-AS398775`, `changed` du 10/12/2024. Ce maintainer porte 69 objets aux origines variées (AS26561, AS398770, AS245…). Son objet `mntner` n'est pas retourné par ALTDB. | `irr_ALTDB_more`, `irr_ALTDB_mnt_MAINT-AS398775`, `irr_ALTDB_mntner_MAINT-AS398775` |
| I7 | RIPE : aucun objet `route` pour 90.98.0.0/15 ni ses sous-préfixes | `irr_RIPE_*` |

### 4. Registre RIPE

| # | Constat | Source |
|---|---|---|
| G1 | inetnum `90.98.0.0 - 90.98.255.255`, netname `US-FASTLY-20060302`, statut `ALLOCATED PA`, org `ORG-FI26-RIPE`, mnt-by `FASTLY` et `RIPE-NCC-HM-MNT`, créé le 03/09/2026 07:43:08Z. Une seule version dans l'historique. Aucune assignation plus spécifique. | `ripe_inetnum`, `ripe_historical_inetnum`, `ripe_inetnum_more` |
| G2 | `ORG-FI26-RIPE` : « Fastly, Inc. », LIR, US, créée en 2013 | `ripe_org_ORG-FI26-RIPE` |
| G3 | L'allocation voisine `90.99.0.0 - 90.127.255.255` (`FR-TELECOM-20060302`, `ORG-FT2-RIPE`) a été créée au même instant. C'est la forme habituelle d'un découpage lors d'un transfert. | observation manuelle (whois RIPE), cohérente avec `ripe_transfers` |
| G4 | aut-num **AS5511** (« Opentransit », `ORG-FT2-RIPE`) : `import: from AS54113 action pref=100; accept AS54113`, `export: to AS54113 announce ANY` (et les équivalents IPv6). Ces lignes sont présentes depuis la version 325 de l'objet, valide à partir du 08/07/2020 (absentes de la version 324 du 14/05/2020). | `autnum_AS5511_RIPE`, `ripe_historical_AS5511` |
| G5 | aut-num **AS3215** (RIPE) : aucune mention d'AS54113 | exploration manuelle |
| G6 | aut-num AS54113 dans RADB : « Fastly, Inc. », `MAINT-AS54113`. Dans l'ARIN, l'ASN est enregistré depuis 2011 au nom de Fastly, Inc. | `autnum_AS54113_RADB`, exploration manuelle (whois ARIN) |

### 5. Transferts officiels (RIPE NCC)

Source : [transfers_latest.json](https://ftp.ripe.net/pub/stats/ripencc/transfers/transfers_latest.json), consulté le 21/10/2026. Seul un extrait filtré est conservé (`ripe_transfers`).

| Date | Bloc cédé par Orange S.A. | Bénéficiaire | Routage actuel du bloc |
|---|---|---|---|
| 09/11/2023 | 2.0.0.0/15 | Oracle Svenska AB | non annoncé |
| 30/05/2024 | 2.2.0.0/16 | Oracle Svenska AB | non annoncé |
| 22/07/2024 | 90.72.0.0/16, 90.97.0.0/17 | Bleu SAS | AS2376 (Bleu SAS) |
| 21/02/2025 | 86.232.0.0/16 | Bleu SAS | AS2376 |
| 22/05/2026 | 86.226.0.0/16, 90.96.0.0/16 | NET AND GRID RESEARCH, LLC | plus-spécifiques annoncés par AS6079, AS7029, AS7459, AS13335, AS22773, AS54004, AS215294 |
| **03/09/2026** | **90.98.0.0/16** | **Fastly, Inc.** | **90.98.0.0/18 par AS54113** |
| 14/10/2026 | 92.181.224.0/19 | Orange Espagne SA (groupe) | non annoncé |

(Données : `transferred_blocks_routing`.)

### 6. Cohérence avec Fastly et autres préfixes d'Orange

| # | Constat | Source |
|---|---|---|
| C1 | `https://api.fastly.com/public-ip-list` (21/10/2026) contient `90.98.0.0/17` et `90.98.128.0/18` | `provider_list` |
| C2 | Les 23 versions archivées de cette liste (Wayback Machine, du 27/09/2024 au 16/08/2026) ne contiennent aucune plage 90.98 | `provider_list_wayback` |
| C3 | DNS inverse : `98.90.in-addr.arpa` et `0.98.90.in-addr.arpa` ne sont pas délégués (NXDOMAIN, SOA `pri.authdns.ripe.net`). Aucun PTR sur l'échantillon de 8 adresses, ni d'ailleurs sur 90.99 (Orange). | `dns_reverse` |
| C4 | Dans l'espace RIPE **encore détenu** par Orange (`ORG-FT2-RIPE`, 96 blocs CIDR), 323 routes ont une origine hors des 61 ASN d'Orange. **Aucune n'est d'AS54113 ni d'un CDN.** Il s'agit de filiales du groupe (Orange Espagne AS12479 : 254 routes ; Slovaquie, Roumanie, Moldavie, Belgique, Guinée équatoriale, OBS US) et de clients entreprises ou opérateurs (AS16236 Stellantis, AS21272 Danone, AS9180 Alienor, AS8362 NordNet…). | `holder_scan_ORG-FT2-RIPE` |
| C5 | Dans l'espace **cédé** par Orange, on trouve un CDN, AS13335 (Cloudflare), dans 90.96.0.0/16, cédé en 05/2026 à NET AND GRID RESEARCH. Ce bloc porte aussi des ROA de nombreux opérateurs depuis octobre. Fastly n'apparaît que dans 90.98.0.0/16. | `transferred_blocks_routing`, exploration manuelle des ROA |

### 7. Contexte public

Recherches web du 21/10/2026 :
- Aucune publication d'Orange, de Fastly, de Spamhaus ou de Kentik ne mentionne `90.98.0.0/18` ni le transfert de `90.98.0.0/16`.
- Publications de Spamhaus sur l'incident d'avril (dates non vérifiées ici) : [routes inhabituelles impliquant notamment AS41128](https://x.com/spamhaus/status/2043708364941627683), [changement du chemin vers AS22541 et AS29802](https://x.com/spamhaus/status/2044797263285768504), [retrait après les /16 d'Orange](https://x.com/spamhaus/status/2047238121721372754). La dernière liste `90.98.0.0/15` (AS41128 AS22541 AS29802) comme retirée.
- Des agrégateurs tiers reprennent les plages Fastly 90.98, sans source primaire supplémentaire : [ipinfo.io/AS54113](https://ipinfo.io/AS54113), [networksdb.io](https://networksdb.io/ip-addresses-of/fastly-inc), [cloud-ip-ranges.com](https://cloud-ip-ranges.com/providers/fastly), [cloudipdb.io](https://cloudipdb.io/fastly/).

## (b) Hypothèses, de la plus à la moins plausible

### H1 — Annonce légitime par le nouveau titulaire, après un transfert d'adresses : **la plus plausible**

Fastly est titulaire de 90.98.0.0/16 depuis le transfert du 03/09/2026 et a commencé à en annoncer une partie le 05/10.

- **Ce qui la soutient :**
  - le transfert officiel RIPE NCC (section 5) et l'inetnum Fastly (G1, G2) ;
  - la liste publique de Fastly (C1) et l'objet RADB tenu par le maintainer historique de Fastly (I1, I3) ;
  - les upstreams conformes au profil d'AS54113 (R4) ;
  - la chronologie cohérente : retrait de la ROA, puis de la route par Orange, puis transfert, puis annonce ;
  - le schéma de cessions IPv4 d'Orange depuis 2023 (section 5).
- **Ce qui la confirmerait :**
  - une ROA AS54113 créée par Fastly sous le TAL RIPE ;
  - un objet `route` dans la base RIPE, qui fait autorité ;
  - une confirmation écrite d'Orange ou de Fastly, par exemple via leur NOC ou leur PeeringDB.
- **Ce qui l'infirmerait :** une contestation du transfert par le RIPE NCC, un retrait de la liste publique Fastly, ou un démenti d'Orange ou de Fastly.

### H2 — Annonce légitime, avec une hygiène de routage incomplète au démarrage : **plausible, compatible avec H1**

- **Ce qui la soutient :**
  - aucune ROA (P1, P2) ;
  - aucun objet `route` dans la base RIPE (I7) ;
  - objet RADB modifié environ 8 h 45 après la première annonce (I1 et chronologie) ;
  - AS174 absent (R5), ce qui pourrait relever d'un filtrage IRR ou RPKI de Cogent, sans certitude ;
  - objets ALTDB obsolètes liés à l'incident encore présents (I4).
- **Ce qui la confirmerait :** l'apparition ultérieure d'une ROA et d'AS174 dans les chemins.
- **Ce qui l'infirmerait :** une explication de l'absence d'AS174 sans rapport avec les filtres.

### H3 — Propagation initiale via AS5511 : relation de transit existante (déclarée depuis 2020), plutôt que fuite ou détournement

- **Ce qui la soutient :** la politique publique d'AS5511 envers AS54113 (G4), et l'upstream AS5511 déjà utilisé par Orange pour ce même /16 jusqu'au 02/09 (R9).
- **Point ouvert :** à 03:03, l'objet RADB n'était peut-être pas encore créé (seul `last-modified` est connu). Dans ce cas, le filtre d'AS5511 « accept AS54113 » n'aurait pas reposé sur cet objet. Plusieurs causes possibles : objet préexistant modifié à 11:49, filtre fondé sur un as-set ou sur une liste manuelle. Non vérifiable de l'extérieur.

### H4 — Annonce frauduleuse imitant Fastly (fausse origine AS54113) : **peu plausible**

- **Ce qui la soutiendrait :** l'absence de ROA, qui rend une usurpation d'origine indétectable par la RPKI.
- **Ce qui la contredit :**
  - Fastly est titulaire au registre (G1) et déclare la plage dans sa liste officielle (C1) ;
  - l'objet RADB est maintenu par le maintainer de Fastly (I3) ;
  - les chemins actuels sont typiques de Fastly (R4).
  Une usurpation devrait réunir tous ces éléments à la fois.
- **Ce qui la confirmerait :** un démenti de Fastly, ou des chemins incohérents avec la topologie de Fastly.

### H5 — Lien entre l'incident d'avril et la cession : **hypothèse de contexte, non vérifiable**

`90.98.0.0/16` n'était pas annoncé avant le 24/02/2026 (R8). L'ensemble 90.98.0.0–90.99.255.255 était l'« ensemble d'origine » du transfert. Les hijackers visent souvent de l'espace inutilisé. Il est possible qu'un bloc en cours de préparation à la vente ait été ciblé parce qu'il était dormant ; rien ne permet de l'établir. Aucun élément ne relie Fastly à l'incident.

## (c) Non vérifié

- **Certificate Transparency** : crt.sh a répondu HTTP 502 aux recherches par adresse IP lors de l'exploration manuelle du 21/10/2026. Aucun certificat n'a pu être relié au /18.
- **Contenu servi** : aucun service hébergé n'a été vérifié, volontairement. Cela demanderait des connexions actives vers l'espace IP.
- **Date de création de l'objet RADB** : seule la dernière modification (05/10 11:49) est connue. RADB ne publie pas d'historique.
- **Raison de l'absence d'AS174 et d'AS37662** dans les chemins du /18.
- **`MAINT-AS398775`** (ALTDB, objet 90.99.0.0/16 AS3215) : l'objet `mntner` est introuvable et le lien avec Orange est inconnu.
- **Accord entre Orange et Fastly** (contrat, usage prévu de 90.98.192.0/18, non déclaré par Fastly) : aucune source publique.
- **Couverture RIS** : les routes vues par moins de 10 peers échappent à `routing-history`. Un acteur peu visible a pu annoncer de l'espace sans apparaître dans les périodes listées.
- La recherche par dichotomie de G4 suppose que les lignes relatives à AS54113 n'ont pas disparu puis réapparu entre 2020 et 2026.

## Synthèse demandée

**Éléments en faveur d'une annonce légitime**
- Transfert officiel Orange S.A. → Fastly, Inc. du 03/09/2026 (RIPE NCC) ; inetnum `ALLOCATED PA` au nom de Fastly.
- 90.98.0.0/17 publié dans la liste officielle d'IP de Fastly (ajouté après le 16/08/2026).
- Objet RADB tenu par le maintainer de Fastly (près de 5000 objets AS54113).
- Chemins typiques de Fastly ; transit via AS5511 conforme à une politique déclarée depuis 2020.
- Chronologie cohérente : retrait de la ROA puis de la route par Orange (24/08 → 02/09), découpage du registre (03/09), première annonce (05/10).
- Le /18 est le seul plus-spécifique du bloc. Le schéma observé dans l'espace cédé par Orange (Oracle, Bleu, NET AND GRID, Fastly) est celui de cessions IPv4, pas d'annonces sauvages.

**Éléments inquiétants (hygiène et résidus, plutôt que preuve d'illégitimité)**
- **Aucune ROA pour le /18** : RPKI `unknown`, donc une usurpation de l'origine AS54113 resterait indétectable par les validateurs.
- **Objets ALTDB `90.98.0.0/15` AS41128 et AS270118 (`MAINT-SPRINT`) toujours présents.** Ils pourraient servir à réinjecter une annonce frauduleuse, cette fois sur l'espace de Fastly.
- Objet ALTDB `90.99.0.0/16` AS3215 maintenu par un tiers (`MAINT-AS398775`, « IPv4 Allow ») dont le mntner est introuvable.
- AS174 (Cogent) ne transporte pas le /18, contrairement au reste de l'espace Fastly.
- Objet RADB modifié après la première annonce. Aucun objet `route` dans la base RIPE, qui fait pourtant autorité.

**Ce qui reste à vérifier de votre côté**
- Une confirmation par Orange ou Fastly, par exemple via leurs contacts NOC publics (PeeringDB, `remarks` d'AS5511).
- L'apparition d'une ROA AS54113 pour 90.98.0.0/17 et 90.98.128.0/18 : relancer `bgpmon dossier` dans quelques semaines.
- Un signalement possible des objets ALTDB obsolètes à l'opérateur d'ALTDB.
- Une nouvelle tentative crt.sh.

**Proposition pour `allow_more_specific_from` (non appliquée)**

**Je ne recommande pas d'ajouter 54113 à `allow_more_specific_from` de la cible `90.98.0.0/15`.** La cible porte le rôle « Espace Orange France », alors que la moitié 90.98.0.0/16 n'est plus à Orange. Avec cet ajout, AS54113 serait aussi autorisé à annoncer des plus-spécifiques de **90.99.0.0/16**, qui reste à Orange : ce serait un angle mort. Je propose plutôt de **scinder la cible**, à valider par vous et à appliquer seulement après confirmation de H1 :

```yaml
- label: "90.99.0.0/16"            # reste à Orange
  type: prefix
  resource: "90.99.0.0/16"
  expected_origins: [3215]
  allow_more_specific_from: [3215]
  forbidden_origins: [41128]
  forbidden_path_asns: [41128, 22541, 29802]
  max_prefix_length: 24
  rpki: expect_valid
  irr: watch
  severity: critical
- label: "90.98.0.0/16"            # cédé à Fastly le 03/09/2026
  type: prefix
  resource: "90.98.0.0/16"
  expected_origins: [54113]
  allow_more_specific_from: [54113]
  forbidden_origins: [41128, 270118, 3215]
  forbidden_path_asns: [41128, 22541, 29802]
  max_prefix_length: 24
  rpki: expect_valid               # signalera RPKI_UNKNOWN tant que Fastly n'a pas de ROA
  irr: watch
  severity: high
```

Interdire 3215 sur le /16 cédé est un choix discutable : Orange pourrait encore y fournir un transit via AS5511. Mais une **origine** AS3215 sur de l'espace de Fastly serait anormale.

## Limites

- La visibilité RIS ne représente pas tout Internet. `routing-history` a une granularité de 8 h à 12 jours selon la fenêtre, et ignore les routes vues par moins de 10 peers.
- La validation RPKI est celle de RIPEstat (Routinator). Les archives ne couvrent que le TAL du RIPE NCC, ce qui est pertinent puisque l'espace est géré par le RIPE NCC.
- Données IRR : RADB et ALTDB acceptent des déclarations non vérifiées par le registre, et les dates `changed` sont déclaratives.
- Données personnelles : les adresses e-mail sont masquées, les attributs de contact supprimés. Un nom de famille présent dans la description d'un as-set ALTDB a été masqué après relecture (`--redact`). Les 1514 valeurs `owner` des fichiers BGPlay sont masquées : ce sont les titulaires des ASN vus dans les chemins, dont plusieurs personnes physiques ; seul l'ASN est conservé, et l'analyse n'utilise que lui. Les autres données ne contiennent que des noms d'organisations et des identifiants techniques.
- Rejouer la collecte :

```bash
python -m bgpmon dossier 90.98.0.0/18 54113 --covering 90.98.0.0/15 -o dossier/90.98.0.0-18 \
  --roa-date 2026-02-20 --roa-date 2026-04-15 --roa-date 2026-04-19 --roa-date 2026-04-20 \
  --roa-date 2026-04-21 --roa-date 2026-04-23 --roa-date 2026-06-01 --roa-date 2026-08-15 \
  --roa-date 2026-08-24 --roa-date 2026-08-25 --roa-date 2026-09-01 --roa-date 2026-09-04 \
  --roa-date 2026-10-04 --roa-date 2026-10-06 --roa-date 2026-10-20 \
  --provider-list https://api.fastly.com/public-ip-list --provider-history \
  --holder-org ORG-FT2-RIPE --holder-name "Orange S.A." --redact "<terme relevé à la relecture>"
```

Le terme masqué n'est volontairement pas reproduit ici.
