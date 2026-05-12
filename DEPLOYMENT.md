# MiniEDR - Deploiement serveur + agent

Ce workflow part d'un `git clone` propre et compile les binaires sur la machine cible.

## 1. Serveur Linux

```bash
git clone <URL_DU_REPO> edr
cd edr

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
```

Edite `.env` si besoin:

```env
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
DATABASE_URL=sqlite:///./miniedr.db
VT_ENABLED=false
VT_API_KEY=
AUTH_TOKEN=
```

Lancement en mode dev:

```bash
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000
```

Build du binaire serveur:

```bash
PYTHON=venv/bin/python ./packaging/build_server_linux.sh
./dist/linux/miniedr-server
```

Verification:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/stats
```

## 2. Agent Linux/macOS

PyInstaller compile pour l'OS et l'architecture courants. Pour un client Linux, compile sur Linux. Pour Windows, compile sur Windows.

```bash
git clone <URL_DU_REPO> edr
cd edr

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

PYTHON=venv/bin/python ./packaging/build_agent_linux.sh
```

Sur macOS:

```bash
PYTHON=venv/bin/python ./packaging/build_agent_macos.sh
```

Execution contre le serveur:

```bash
MINIEDR_SERVER_URL=http://IP_DU_SERVEUR:8000 ./dist/linux/miniedr-agent --mode scan
MINIEDR_SERVER_URL=http://IP_DU_SERVEUR:8000 ./dist/linux/miniedr-agent --mode monitor
```

Avec authentification:

```bash
# Meme valeur que AUTH_TOKEN cote serveur.
MINIEDR_SERVER_URL=http://IP_DU_SERVEUR:8000 \
MINIEDR_AUTH_TOKEN=change-me \
./dist/linux/miniedr-agent --mode monitor
```

## 3. Agent Windows

Depuis une machine Windows:

```bat
git clone <URL_DU_REPO> edr
cd edr
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
set PYTHON=venv\Scripts\python.exe
packaging\build_agent_windows.bat
```

Execution:

```bat
set MINIEDR_SERVER_URL=http://IP_DU_SERVEUR:8000
dist\windows\miniedr-agent.exe --mode monitor
```

## 4. Avant push GitHub

Ne pousse pas de secrets. `.env` est ignore par git, et les fichiers `.env.example` ne contiennent que des placeholders.

Le fichier `miniedr.db` est encore suivi par git dans ce depot. Pour l'enlever du prochain commit sans supprimer ta copie locale:

```bash
git rm --cached miniedr.db
```
