# Journal des modifications

## Non publié

- Nouvelle sous-commande `bgpmon dossier PREFIX ASN` : collecte passive et horodatée d'un dossier de preuves sur une annonce. Elle couvre le routage RIS actuel et historique, BGPlay, les archives ROA du RIPE NCC, l'IRR, le registre RIPE, les transferts officiels, le DNS inverse et la liste d'IP de l'opérateur. Les e-mails sont masqués et l'option `--redact` permet de masquer des termes repérés à la relecture.
- Client RIPEstat : `get_body()` expose aussi les `messages` des réponses.
- Premier dossier : `dossier/90.98.0.0-18/` (alerte AS54113).

## 3.0.0 — 2026-10-21

Réécriture complète : le script monolithique `bgp_monitor.py` v2.4 devient le package `bgpmon` (`python -m bgpmon`). L'ancien script est conservé, marqué obsolète, dans `legacy/`.

### Corrections des défauts de la v2.4

1. **Plus-spécifiques invisibles** : `routing-status` n'était lu que pour le préfixe exact. Les plus- et moins-spécifiques sont maintenant découverts (RIPEstat `routing-status`, puis `bgp-state` pour chacun) et suivis en temps réel par RIS Live (`moreSpecific` et `lessSpecific`). Nouvelle règle `MORE_SPECIFIC_UNEXPECTED`.
2. **Mélange état courant / historique** : `last_seen.origin` était ajouté aux origines courantes, d'où des faux positifs persistants. L'historique (`first_seen`, `last_seen`) est désormais conservé à part, en simple contexte.
3. **AS path ignoré** : nouvelles règles `PATH_FORBIDDEN_ASN`, `PATH_UPSTREAM_CHANGE` et `PATH_SUSPICIOUS` (boucle, ASN réservé ou privé, AS_SET, dernier saut inédit).
4. **Ni RPKI ni IRR** : validation RPKI des couples (préfixe, origine) observés (`RPKI_INVALID`, `RPKI_UNKNOWN`, `RPKI_STATE_CHANGED`) et diff des objets `route`/`route6`/`aut-num` sur RADB, ALTDB et RIPE (`IRR_OBJECT_*`).
5. **ASN suivis au seul nombre de préfixes** : diff de l'ensemble des préfixes (`ASN_NEW_PREFIX`, `ASN_PREFIX_GONE`) et des voisins (`ASN_NEW_NEIGHBOUR`, `ASN_NEIGHBOUR_GONE`), plus un abonnement RIS Live optionnel sur l'origine.
6. **`webhook_url` inutilisé** : canal webhook générique compatible Discord, Slack et ntfy (format détecté d'après l'URL), avec l'URL lue dans `BGPMON_WEBHOOK_URL`.
7. **Alerte réécrite à chaque cycle** : conditions avec détection de transition (apparition, résolution), déduplication et cooldown configurable par type d'événement, persistés entre deux redémarrages.
8. **Historique en mémoire** : persistance SQLite (conditions, événements, snapshots, upstreams appris, RIB RIS Live, santé des sources).
9. **Fusion de configuration écrasant les cibles** : `{**DEFAULT_CONFIG, **user_cfg}` disparaît. Le fichier de configuration est l'unique source de vérité, validé par un schéma strict (`check-config`). La commande `migrate-config` convertit l'ancien format.
10. **Rapport HTML trompeur** : le titre codé en dur (« Hijack massif 167.32.0.0/16 DÉTECTÉ ») est remplacé par un titre calculé d'après l'état réel. Le bandeau n'apparaît qu'en cas d'alerte, et le rafraîchissement suit la configuration au lieu des 300 s fixes.
11. **Robustesse HTTP et HTML** : session réutilisée, timeout, retries avec backoff exponentiel, respect de `Retry-After`, débit limité, cache court et paramètre `sourceapp=bgpmon` pour RIPEstat. Tout le contenu du rapport est échappé.

### Autres changements

- Un état n'est plus jamais `CLEAN` par défaut : une origine vide, une absence de données ou une source en erreur donnent `INCONNU`. Une erreur de source ne résout aucune condition, et `SOURCE_ERROR` est émis après N échecs consécutifs.
- Nouvelles sous-commandes : `run`, `once` (codes de sortie 2 = alerte, 3 = inconnu, utilisable en CI), `report` (exports CSV et JSON), `events` (filtres), `migrate-config`, `check-config` et `test-alert` (alerte factice pour tester les canaux, dont le webhook).
- Journalisation par le module `logging` (format texte ou JSON). Plus de `print` dispersés ni de `os.system("clear")`. Arrêt propre sur SIGINT et SIGTERM.
- Données IRR : seuls des attributs non personnels sont stockés en clair. ALTDB est interrogé sur `whois.altdb.net` (`rr.altdb.net` ne résout plus).
- Nouveau champ de cible `expect_silent` : une route retirée qui doit le rester est `OK` (« OK-silencieux ») tant qu'elle n'est pas annoncée, et `SILENCE_BROKEN` est levé dès sa réapparition. Il est appliqué aux trois /24 198.x.
- Les cibles de la v2.4 sont migrées dans `config.example.yaml`, avec des attentes explicites et sans nom de personne physique. Les sept sous-préfixes `167.32.x` ne sont plus des cibles séparées : `167.32.0.0/16` les couvre via les plus-spécifiques. Le nom d'une personne présent dans une description de la v2.4 a aussi été retiré de la copie `legacy/`.
- Tests `pytest` sans réseau, `ruff`, `mypy --strict`, GitHub Actions (actions épinglées par SHA), Dockerfile et unité systemd d'exemple.
- Dépendances épinglées : `requests` 2.34.2, `websocket-client` 1.9.2, `PyYAML` 6.0.3.
