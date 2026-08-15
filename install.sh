#!/usr/bin/env bash
#
# Installation de DomaineAnalyser (Linux, macOS, WSL).
#
# Idempotent : relancer le script ne casse rien et ne réinstalle que ce qui
# manque. Il ne modifie jamais le Python du système — tout est confiné dans
# le répertoire .venv du projet.
#
# Options :
#   --no-system-tools   n'installe pas le binaire optionnel whois
#   --dev               installe aussi les outils de développement
#   -h, --help          affiche cette aide

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
MIN_PYTHON="3.10"

WITH_SYSTEM_TOOLS=1
EXTRAS="ai"

# --- présentation ------------------------------------------------------------

if [ -t 1 ]; then
    BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
    BOLD=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi

step() { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$1"; }
ok()   { printf '    %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '    %s!%s %s\n' "$YELLOW" "$RESET" "$1"; }
fail() { printf '    %s✗%s %s\n' "$RED" "$RESET" "$1" >&2; }

# Aide écrite explicitement plutôt qu'extraite de l'en-tête par numéros de
# ligne : la moindre ligne ajoutée plus haut décalerait la plage et ferait
# fuiter du code dans la sortie.
usage() {
    cat <<'EOF'
Installation de DomaineAnalyser (Linux, macOS, WSL).

Idempotent : relancer le script ne casse rien et ne réinstalle que ce qui
manque. Il ne modifie jamais le Python du système — tout est confiné dans
le répertoire .venv du projet.

  ./install.sh [--no-system-tools] [--dev]

  --no-system-tools   n'installe pas le binaire optionnel whois
  --dev               installe aussi les outils de développement
  -h, --help          affiche cette aide
EOF
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-system-tools) WITH_SYSTEM_TOOLS=0 ;;
        --dev)             EXTRAS="ai,dev" ;;
        -h|--help)         usage ;;
        *) fail "option inconnue : $1"; exit 64 ;;
    esac
    shift
done

# --- 1. interpréteur Python --------------------------------------------------

step "Vérification de Python"

PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    fail "Python $MIN_PYTHON ou supérieur est requis et n'a pas été trouvé."
    echo
    echo "    Debian/Ubuntu : sudo apt install python3 python3-venv"
    echo "    Fedora/RHEL   : sudo dnf install python3"
    echo "    macOS         : brew install python"
    exit 1
fi
ok "$("$PYTHON" --version) — $(command -v "$PYTHON")"

# --- 2. environnement virtuel ------------------------------------------------

step "Environnement virtuel"

if [ ! -x "$VENV_DIR/bin/python" ]; then
    # Message explicite : sur Debian, python3-venv est un paquet séparé et son
    # absence produit une erreur peu compréhensible.
    if ! "$PYTHON" -m venv "$VENV_DIR" 2>/dev/null; then
        fail "Création de l'environnement virtuel impossible."
        echo "    Sur Debian/Ubuntu : sudo apt install python3-venv"
        exit 1
    fi
    ok "créé dans .venv"
else
    ok "déjà présent, réutilisé"
fi

VENV_PY="$VENV_DIR/bin/python"

# --- 3. dépendances Python ---------------------------------------------------

step "Dépendances Python"

"$VENV_PY" -m pip install --quiet --upgrade pip
ok "pip à jour"

"$VENV_PY" -m pip install --quiet -e "$PROJECT_DIR[$EXTRAS]"
ok "domaine-analyser installé (extras : $EXTRAS)"

# --- 4. cache de la Public Suffix List ---------------------------------------

step "Cache de la Public Suffix List"

# Amorcé maintenant plutôt qu'au premier audit : sans lui, la détermination du
# domaine organisationnel — donc l'héritage DMARC — serait faite sur une liste
# embarquée potentiellement datée.
if "$VENV_PY" -c 'import tldextract; tldextract.TLDExtract().update()' 2>/dev/null; then
    ok "liste à jour"
else
    warn "mise à jour impossible (réseau ?) ; la liste embarquée sera utilisée"
fi

# --- 5. fichier de configuration ---------------------------------------------

step "Configuration locale"

if [ -f "$PROJECT_DIR/.env" ]; then
    ok ".env déjà présent, laissé intact"
else
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    ok ".env créé depuis .env.example"
fi

# --- 6. binaires système optionnels ------------------------------------------

step "Binaires système optionnels"

# Seul `whois` est concerné : c'est le unique binaire externe que l'outil
# consulte, et uniquement en dernier recours. Installer d'autres utilitaires
# DNS n'apporterait rien puisqu'ils ne sont jamais appelés.
install_system_tools() {
    if command -v whois >/dev/null 2>&1; then
        ok "whois déjà présent"
        return
    fi

    if [ "$WITH_SYSTEM_TOOLS" -eq 0 ]; then
        warn "whois absent (installation désactivée par --no-system-tools)"
        return
    fi

    local manager="" packages="whois"
    if command -v apt-get >/dev/null 2>&1; then
        manager="apt-get"
    elif command -v dnf >/dev/null 2>&1; then
        manager="dnf"
    elif command -v pacman >/dev/null 2>&1; then
        manager="pacman"
    elif command -v brew >/dev/null 2>&1; then
        manager="brew"
    fi

    if [ -z "$manager" ]; then
        warn "whois absent — gestionnaire de paquets non reconnu"
        return
    fi

    printf '    installation de « %s » via %s…\n' "$packages" "$manager"

    local status=0
    case "$manager" in
        apt-get) sudo apt-get update -qq && sudo apt-get install -y -qq $packages || status=$? ;;
        dnf)     sudo dnf install -y -q $packages || status=$? ;;
        pacman)  sudo pacman -S --noconfirm --quiet $packages || status=$? ;;
        brew)    brew install $packages || status=$? ;;
    esac

    if [ "$status" -eq 0 ]; then
        ok "whois installé"
    else
        # Volontairement non bloquant : ce binaire enrichit la sortie WHOIS
        # brute mais n'est jamais nécessaire. Le client WHOIS natif de l'outil
        # fonctionne sans lui.
        warn "installation impossible (droits insuffisants ?) — sans conséquence :"
        warn "l'outil embarque son propre client WHOIS en TCP/43"
    fi
}

install_system_tools

# --- 7. vérification ---------------------------------------------------------

step "Vérification"
echo
"$VENV_DIR/bin/da" doctor || true

cat <<EOF

${BOLD}Installation terminée.${RESET}

  Activer l'environnement :   source .venv/bin/activate
  Premier audit :             da domain example.com
  Rapport complet :           da domain example.com --output rapport.md

Sans activer l'environnement, utiliser directement ./.venv/bin/da
EOF
