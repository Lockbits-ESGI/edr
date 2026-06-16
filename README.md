# MiniEDR

MiniEDR est un projet EDR Python avec une architecture agent/serveur:

- un agent endpoint qui collecte des snapshots systeme et des evenements FIM;
- un serveur FastAPI qui stocke les donnees dans SQLite;
- une API REST pour lire les agents, evenements et statistiques;
- des scripts PyInstaller pour generer des binaires agent/serveur.

## Installation rapide

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edite `.env` cote serveur:

```env
VT_API_KEY=
AUTH_TOKEN=change-me
DATABASE_URL=sqlite:///./miniedr.db
VT_ENABLED=false
GLPI_ENABLED=false
GLPI_WEB_URL=https://glpi.lockbits.pro
GLPI_API_URL=https://glpi.lockbits.pro/api.php/v2.2
GLPI_OAUTH_CLIENT_ID=
GLPI_OAUTH_CLIENT_SECRET=
GLPI_API_USERNAME=
GLPI_API_PASSWORD=
GLPI_APP_TOKEN=
GLPI_USER_TOKEN=
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
LOG_LEVEL=INFO
MAX_EVENTS_PER_PAGE=100
WORKERS=1
```

Pour creer automatiquement un ticket GLPI a chaque evenement accepte par le
serveur, configure `GLPI_ENABLED=true` et les variables OAuth `GLPI_OAUTH_*`,
`GLPI_API_USERNAME` et `GLPI_API_PASSWORD`. Les tickets sont crees via l'API
GLPI v2 exposee par `GLPI_API_URL`.

## Lancer le serveur

```bash
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```

Verification:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/stats
```

Dashboard:

```text
http://IP_DU_SERVEUR:8000/dashboard
```

Documentation OpenAPI:

```text
http://IP_DU_SERVEUR:8000/docs
http://IP_DU_SERVEUR:8000/openapi.json
```

## Lancer un agent

Scan unique:

```bash
MINIEDR_SERVER_URL=http://IP_DU_SERVEUR:8000 \
MINIEDR_AUTH_TOKEN=change-me \
MINIEDR_AGENT_COMPANY=EntrepriseA \
python -m agent.main --mode scan --user alice
```

Monitoring continu:

```bash
MINIEDR_SERVER_URL=http://IP_DU_SERVEUR:8000 \
MINIEDR_AUTH_TOKEN=change-me \
MINIEDR_AGENT_COMPANY=EntrepriseA \
python -m agent.main --mode monitor --user alice
```

`MINIEDR_AGENT_COMPANY` ajoute le tag normalise `company:EntrepriseA` a tous
les evenements envoyes par l'agent. Ce tag est aussi transmis dans le heartbeat
pour rattacher l'agent a sa societe cote serveur.

Le `--user` est transmis au serveur dans chaque evenement et utilise comme
requester GLPI de type `User` lors de la creation des tickets. Il peut aussi
etre renseigne via `MINIEDR_USER` ou `agent.user` dans la configuration agent.

## Compiler les binaires

Agent Linux:

```bash
PYTHON=venv/bin/python ./packaging/build_agent_linux.sh
```

Agent macOS:

```bash
PYTHON=venv/bin/python ./packaging/build_agent_macos.sh
```

Agent Windows, depuis Windows:

```bat
set PYTHON=venv\Scripts\python.exe
packaging\build_agent_windows.bat
```

Serveur Linux:

```bash
PYTHON=venv/bin/python ./packaging/build_server_linux.sh
```

Les binaires sont generes dans `dist/`.

## API utile

```bash
curl http://IP_DU_SERVEUR:8000/api/v1/stats
curl http://IP_DU_SERVEUR:8000/api/v1/agents
curl "http://IP_DU_SERVEUR:8000/api/v1/events?page=1&page_size=20"
curl "http://IP_DU_SERVEUR:8000/api/v1/events?event_type=fim&page=1&page_size=20"
curl http://IP_DU_SERVEUR:8000/api/v1/events/EVENT_ID
curl http://IP_DU_SERVEUR:8000/api/v1/agents/AGENT_ID
```

Filtres disponibles sur `/api/v1/events`:

- `agent_id`
- `event_type`
- `severity`
- `hostname`
- `page`
- `page_size`

Types d'evenements:

- `scan`
- `heartbeat`
- `system_info`
- `fim`

## Structure

```text
agent/          Agent endpoint
server/         Serveur FastAPI, stockage SQLite, API REST
shared/         Schemas et helpers partages
packaging/      Scripts/specs PyInstaller
tests/          Tests unitaires et API
templates/      Template de rapport HTML local
```

## Deploiement

Le guide complet serveur + client + systemd est dans [DEPLOYMENT.md](DEPLOYMENT.md).

## Securite

Ne commit jamais `.env`, `miniedr.db`, `dist/`, `build/`, `venv/` ou les binaires generes. Les secrets doivent rester dans `.env` sur les machines concernees.
