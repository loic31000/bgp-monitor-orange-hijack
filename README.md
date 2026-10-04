# BGP Monitor - Orange France Hijack Investigation

<p align="center">
  <img src="https://img.shields.io/badge/Python-3-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Requests-2.32.3-222222?style=for-the-badge&logo=python&logoColor=white" alt="Requests 2.32.3">
  <img src="https://img.shields.io/badge/RIPEstat-API-0072BC?style=for-the-badge" alt="RIPEstat API">
  <img src="https://img.shields.io/badge/BGP-monitoring-6A5ACD?style=for-the-badge" alt="BGP monitoring">
</p>

Outil Python de monitoring passif développé dans le cadre de l'enquête BGP sur des annonces visant des ressources associées à Orange France.

Le script interroge uniquement des API publiques RIPEstat. Il ne réalise pas de scan actif des systèmes surveillés.

## État de l'incident documenté

Le README historique du projet indiquait encore le hijack comme actif. Cette information n'était plus à jour.

Dans le rapport d'enquête associé :

- Orange AS3215 a commencé à annoncer des routes plus spécifiques `90.98.0.0/16` et `90.99.0.0/16` le 20 avril 2026 à 15:01 UTC ;
- la route `90.98.0.0/15` via AS41128 a été retirée du DFZ le 21 avril 2026 à 17:27 UTC.

Rapport associé :

[bgp-hijack-orange-2026](https://github.com/loic31000/bgp-hijack-orange-2026)

## Fonctionnalités du moniteur

Le fichier `bgp_monitor.py` permet de :

- surveiller des préfixes et des ASN déclarés dans `config.json` ;
- interroger l'état de routage d'un préfixe via RIPEstat ;
- récupérer les origines observées et la visibilité RIS ;
- comparer l'origine observée à un ASN légitime ou à un ASN surveillé ;
- interroger le nombre de préfixes annoncés par un ASN ;
- afficher les résultats dans le terminal ;
- conserver un historique court des statuts en mémoire ;
- écrire `bgp_monitor.log` ;
- écrire les détections `HIJACK` dans `bgp_alerts.log` ;
- générer `bgp_report.html` avec rafraîchissement automatique ;
- exécuter une seule vérification avec `--once` ;
- modifier l'intervalle avec `--refresh`.

## Cibles

La configuration par défaut du script inclut notamment :

- `90.98.0.0/15` ;
- `92.183.128.0/18` ;
- `AS41128` ;
- `AS3215` ;
- `AS29802` ;
- plusieurs routes du pool MCI/SAE ;
- `167.32.0.0/16` et plusieurs sous-préfixes ;
- `AS2702`, `AS7857`, `AS215828` et `AS398290`.

Le fichier `config.json` présent dans le dépôt contient actuellement un sous-ensemble plus court de ces cibles. Le script possède aussi sa propre configuration par défaut.

## Installation

```bash
git clone https://github.com/loic31000/bgp-monitor-orange-hijack.git
cd bgp-monitor-orange-hijack
python -m venv .venv
```

Activation de l'environnement virtuel :

Windows PowerShell :

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux/macOS :

```bash
source .venv/bin/activate
```

Puis :

```bash
pip install -r requirements.txt
python bgp_monitor.py
```

Une seule vérification :

```bash
python bgp_monitor.py --once
```

Intervalle personnalisé :

```bash
python bgp_monitor.py --refresh 60
```

## Fichiers

```text
bgp-monitor-orange-hijack/
├── bgp_monitor.py
├── config.json
├── requirements.txt
└── README.md
```

Fichiers générés à l'exécution :

```text
bgp_monitor.log
bgp_alerts.log
bgp_report.html
```

## Méthodologie

Le moniteur consomme les endpoints publics RIPEstat pour observer le routage. Un statut `HIJACK` est produit par la logique du script lorsque l'ASN surveillé est observé comme origine, ou lorsque l'ASN légitime attendu est absent alors qu'une autre origine est présente.

Ce statut est une détection basée sur les règles codées dans l'outil. Il ne constitue pas à lui seul une attribution de l'acteur responsable.

## Licence

Aucun fichier `LICENSE` n'est actuellement présent dans le dépôt.
