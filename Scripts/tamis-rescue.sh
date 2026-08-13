#!/bin/bash
#
# tamis-rescue.sh — diagnostiquer, réparer, ou retirer entièrement Tamis de ce Mac.
#
# Écrit après une panne réelle : le résolveur DNS refusait ses arguments de
# lancement, launchd le relançait en boucle, et le réglage système pointait
# déjà la résolution vers 127.0.0.1. Résultat, un Mac qui ne résout plus rien —
# y compris après redémarrage, parce que les réglages réseau y survivent.
#
# Ce script est fait pour ce moment-là. Il ne dépend ni de l'application ni du
# dépôt : tous les chemins sont écrits en clair, il fonctionne même si Tamis.app
# a déjà été jeté à la corbeille — ce qui est justement le cas où les démons et
# le certificat racine restent en place, invisibles.
#
# TROIS RÈGLES, et elles expliquent la forme du fichier :
#
#   1. Pas de « set -e ». Un script de secours qui s'arrête à la première étape
#      qui ne trouve rien est un script de secours qui ne secourt personne.
#   2. Il ne supprime que ce qui porte l'identité de Tamis. Jamais un « rm -rf »
#      sur un motif large : chaque suppression est précédée d'une vérification
#      d'identifiant, y compris pour l'application elle-même — un autre
#      « Tamis.app » sur ce Mac ne sera pas emporté.
#   3. Il vérifie à la fin, et dit ce qu'il trouve. Un script qui affirme avoir
#      réparé sans regarder ne vaut pas mieux que l'annulation qui prétendait
#      avoir tout remis en état alors qu'elle laissait des binaires root.
#
# Sans argument, il ouvre un menu. Avec un argument, il fait une chose et sort,
# ce qui le rend utilisable depuis un autre script :
#
#   --diagnostic       examen complet, ne modifie rien, ne demande pas de mot de passe
#   --reseau           répare DNS et proxy (retire aussi l'URL PAC résiduelle)
#   --dns-dhcp         rend le DNS au DHCP sur tous les services
#   --reseau-complet   coupe TOUS les proxys et renouvelle les baux DHCP
#   --nettoyer         retire tout Tamis, garde vos listes et scripts
#   --tout             retire tout Tamis, y compris vos données
#
# GPLv3, comme le reste du projet.

BUNDLE_ID="io.github.black0s.tamis"
PREFIXE="io.github.black0s."
DAEMON_LABEL="io.github.black0s.tamisd"
RESOLVER_LABEL="io.github.black0s.tamis-dnsd"
HELPER_LABEL="io.github.black0s.tamis-pac"
PRIVILEGED_DIR="/Library/Application Support/Tamis"
CA_NAME="Tamis Local CA"
PAC_PORT=7655
PROXY_PORT=7654

# ---------------------------------------------------------------------------
# Qui sommes-nous
#
# Le script a besoin de root pour les démons et les réglages réseau, mais le
# trousseau et l'agent PAC appartiennent à l'utilisateur. Lancé sous sudo, root
# n'a ni le bon trousseau ni la bonne session : on retient donc qui a appelé.
# ---------------------------------------------------------------------------

UTILISATEUR="${SUDO_USER:-$(id -un)}"
UID_UTILISATEUR="${SUDO_UID:-$(id -u)}"
MAISON="$(dscl . -read "/Users/$UTILISATEUR" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[ -z "$MAISON" ] && MAISON="/Users/$UTILISATEUR"
TROUSSEAU="$MAISON/Library/Keychains/login.keychain-db"

en_utilisateur() {
    if [ "$(id -u)" -eq 0 ]; then
        launchctl asuser "$UID_UTILISATEUR" sudo -u "$UTILISATEUR" "$@"
    else
        "$@"
    fi
}

# Tous les trousseaux à examiner, chacun une seule fois.
#
# `list-keychains` renvoie déjà la liste de recherche, qui contient en général
# le trousseau de session et celui du système : les ajouter à la main derrière
# faisait examiner deux fois les mêmes fichiers et afficher deux fois la même
# réponse. On les ajoute quand même — une liste de recherche peut être
# personnalisée et ne plus les contenir — mais on déduplique.
trousseaux() {
    { en_utilisateur security list-keychains 2>/dev/null | tr -d ' "'
      echo "$TROUSSEAU"
      echo "/Library/Keychains/System.keychain"
    } | awk 'NF && !vu[$0]++'
}

titre()  { echo; echo "── $* ──"; }
ok()     { echo "    ✓ $*"; }
info()   { echo "    · $*"; }
alerte() { echo "    ! $*"; }

# Les services réseau, sans le « * » qui préfixe ceux qui sont désactivés.
services_reseau() {
    networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\*//'
}

# Supprime un paquet d'application seulement si son identifiant est bien celui
# de Tamis. Un autre logiciel portant le même nom de fichier reste intact.
supprimer_si_cest_tamis() {
    app="$1"
    [ -d "$app" ] || return 1
    identifiant="$(defaults read "$app/Contents/Info" CFBundleIdentifier 2>/dev/null)"
    if [ "$identifiant" = "$BUNDLE_ID" ]; then
        rm -rf "$app" && ok "application supprimée : $app"
    else
        alerte "ignoré : $app (identifiant « $identifiant », pas le nôtre)"
    fi
}

exiger_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "==> cette action a besoin de votre mot de passe"
        exec sudo -- "$0" "$1"
    fi
}

# ===========================================================================
# DIAGNOSTIC — ne modifie rien, ne demande rien
# ===========================================================================

diagnostic() {
    echo "Diagnostic — aucune modification ne sera faite."
    PROBLEMES=0

    titre "1. Processus"
    if pgrep -l -x "Tamis" >/dev/null 2>&1 || pgrep -l "tamisd|tamis-dnsd|tamis-pac" >/dev/null 2>&1; then
        pgrep -fl "Tamis.app|tamisd|tamis-dnsd|tamis-pac" 2>/dev/null | sed 's/^/    ! /'
        PROBLEMES=$((PROBLEMES + 1))
    else
        ok "aucun processus Tamis"
    fi

    titre "2. Services launchd"
    trouves="$(find /Library/LaunchDaemons /Library/LaunchAgents \
                    "$MAISON/Library/LaunchAgents" -maxdepth 1 \
                    \( -iname "*tamis*" -o -iname "*black0s*" \) 2>/dev/null)"
    if [ -n "$trouves" ]; then
        echo "$trouves" | sed 's/^/    ! /'
        PROBLEMES=$((PROBLEMES + 1))
    else
        ok "aucun fichier de service"
    fi
    if launchctl list 2>/dev/null | grep -qi "black0s\|tamis"; then
        launchctl list 2>/dev/null | grep -i "black0s\|tamis" | sed 's/^/    ! chargé : /'
        PROBLEMES=$((PROBLEMES + 1))
    else
        ok "rien de chargé dans launchd"
    fi

    titre "3. Fichiers système"
    for p in "$PRIVILEGED_DIR" "/Library/Logs/Tamis" "/var/log/tamis.log"; do
        if [ -e "$p" ]; then alerte "présent : $p"; PROBLEMES=$((PROBLEMES + 1))
        else ok "absent : $p"; fi
    done

    titre "4. Application"
    vu=0
    for a in "/Applications/Tamis.app" "$MAISON/Applications/Tamis.app" \
             "$MAISON/Downloads/Tamis.app" "$MAISON/Desktop/Tamis.app"; do
        [ -d "$a" ] && { alerte "présente : $a"; vu=1; }
    done
    while read -r trouvee; do
        [ -z "$trouvee" ] && continue
        case "$trouvee" in */build/*) continue ;; esac
        alerte "présente : $trouvee"; vu=1
    done <<< "$(mdfind "kMDItemCFBundleIdentifier == '$BUNDLE_ID'" 2>/dev/null)"
    if [ "$vu" -eq 1 ]; then PROBLEMES=$((PROBLEMES + 1))
    else ok "aucune application installée (hors produits de compilation)"; fi

    # La partie la plus importante : une racine de confiance dont plus personne
    # ne détient la clé reste une racine que le Mac croit sur parole.
    titre "5. Certificats racine"
    for k in $(trousseaux); do
        [ -e "$k" ] || continue
        if en_utilisateur security find-certificate -c "$CA_NAME" "$k" >/dev/null 2>&1; then
            alerte "présente dans $k"; PROBLEMES=$((PROBLEMES + 1))
        else
            ok "absente de $k"
        fi
    done
    for domaine in "" "-d"; do
        etiquette="utilisateur"; [ -n "$domaine" ] && etiquette="administrateur"
        if en_utilisateur security dump-trust-settings $domaine 2>&1 | grep -qi "tamis"; then
            alerte "réglage de confiance Tamis dans le domaine $etiquette"
            PROBLEMES=$((PROBLEMES + 1))
        else
            ok "aucun réglage de confiance Tamis ($etiquette)"
        fi
    done

    titre "6. Ports"
    for port in 53 "$PROXY_PORT" "$PAC_PORT"; do
        if lsof -nP -i:"$port" 2>/dev/null | grep -q .; then
            alerte "port $port occupé :"
            lsof -nP -i:"$port" 2>/dev/null | tail -2 | sed 's/^/        /'
            PROBLEMES=$((PROBLEMES + 1))
        else
            ok "port $port libre"
        fi
    done

    titre "7. Réglages réseau"
    # Le compteur est incrémenté hors du tube : un « while » alimenté par un
    # tube tourne dans un sous-shell, et ce qu'il compte y reste.
    RESEAU_ACTIF=0
    while read -r s; do
        [ -z "$s" ] && continue
        dns="$(networksetup -getdnsservers "$s" 2>/dev/null | tr '\n' ' ')"
        pac="$(networksetup -getautoproxyurl "$s" 2>/dev/null | tr '\n' ' ')"

        # Une URL PAC qui subsiste avec « Enabled: No » ne redirige rien : c'est
        # du texte que macOS garde en mémoire. La signaler comme un problème
        # ferait chercher une panne là où il n'y en a pas — mais la passer sous
        # silence ferait douter quand elle réapparaît dans les Réglages Système.
        marque="·"; note=""
        case "$dns" in *127.0.0.1*|*::1*) marque="!"; note=" ← DNS détourné"; RESEAU_ACTIF=1 ;; esac
        case "$pac" in
            *tamis*|*"$PAC_PORT"*)
                case "$pac" in
                    *"Enabled: Yes"*) marque="!"; note="$note ← proxy ACTIF"; RESEAU_ACTIF=1 ;;
                    *) [ "$marque" = "·" ] && note=" (URL résiduelle, désactivée — inerte)" ;;
                esac ;;
        esac
        echo "    $marque $s$note"
        echo "        DNS : $dns"
        echo "        PAC : $pac"
    done <<< "$(services_reseau)"
    [ "$RESEAU_ACTIF" -eq 1 ] && PROBLEMES=$((PROBLEMES + 1))
    echo "    état effectif vu par le système :"
    echo "        DNS  : $(scutil --dns 2>/dev/null | awk '/nameserver\[/{print $3}' | sort -u | tr '\n' ' ')"
    echo "        PAC  : $(scutil --proxy 2>/dev/null | awk '/ProxyAutoConfigEnable/{print $3}')  (0 = désactivé)"

    # La question qui compte plus que toutes les autres.
    titre "8. Est-ce que ça marche ?"
    printf "    résolution DNS      : "
    if dscacheutil -q host -a name apple.com 2>/dev/null | grep -q ip_address; then
        echo "✓"
    else
        echo "✗ EN PANNE"; PROBLEMES=$((PROBLEMES + 1))
    fi
    code="$(curl -s -m 10 -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null)"
    printf "    HTTPS (example.com) : "
    if [ "$code" = "200" ]; then echo "✓ $code"
    else echo "✗ $code"; PROBLEMES=$((PROBLEMES + 1)); fi

    # La preuve décisive : si quoi que ce soit interceptait encore, on lirait
    # « Tamis Local CA » ici plutôt qu'une autorité publique.
    emetteur="$(echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
                | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')"
    printf "    émetteur du certif. : "
    case "$emetteur" in
        *"$CA_NAME"*) echo "✗ $emetteur"
                      alerte "votre trafic est encore déchiffré par Tamis"
                      PROBLEMES=$((PROBLEMES + 1)) ;;
        "")           echo "? illisible (pas de réseau ?)" ;;
        *)            echo "✓ $emetteur" ;;
    esac

    echo
    if [ "$PROBLEMES" -eq 0 ]; then
        echo "  ✓ Ce Mac est propre, et il navigue."
    else
        echo "  ! $PROBLEMES point(s) à corriger — voir « Réparer » ou « Tout retirer » au menu."
    fi
    echo
}

# ===========================================================================
# RÉSEAU
# ===========================================================================

reparer_reseau() {
    titre "Réglages réseau"
    services_reseau | while read -r service; do
        [ -z "$service" ] && continue

        dns="$(networksetup -getdnsservers "$service" 2>/dev/null)"
        case "$dns" in
            *127.0.0.1*|*::1*)
                networksetup -setdnsservers "$service" empty >/dev/null 2>&1 \
                    && ok "$service — DNS rendu au DHCP" \
                    || alerte "$service — échec de la remise à zéro du DNS" ;;
            *) info "$service — DNS déjà normal" ;;
        esac

        # Le chemin du PAC porte le nom « tamis » exprès : c'est ce qui permet
        # de distinguer un réglage posé par Tamis d'un réglage déjà présent.
        pac="$(networksetup -getautoproxyurl "$service" 2>/dev/null | head -1)"
        case "$pac" in
            *tamis*|*"$PAC_PORT"*)
                networksetup -setautoproxystate "$service" off >/dev/null 2>&1
                # L'URL survit à la désactivation, et macOS la garde en mémoire.
                # Inerte, mais elle réapparaît dans les Réglages Système et fait
                # croire que quelque chose est resté. Une espace est ce que
                # networksetup accepte comme « vide ».
                networksetup -setautoproxyurl "$service" " " >/dev/null 2>&1
                networksetup -setautoproxystate "$service" off >/dev/null 2>&1
                ok "$service — proxy automatique désactivé et URL effacée" ;;
            *) info "$service — pas de proxy automatique Tamis" ;;
        esac
    done

    echo "    ⟳ vidage du cache DNS"
    dscacheutil -flushcache >/dev/null 2>&1
    killall -HUP mDNSResponder >/dev/null 2>&1
    ok "cache DNS vidé"
}

dns_dhcp() {
    titre "DNS rendu au DHCP"
    # Volontairement sans condition : c'est l'action qu'on choisit quand on veut
    # reprendre les serveurs de sa box, y compris à la place d'un DNS public
    # qu'on avait mis en dépannage.
    services_reseau | while read -r service; do
        [ -z "$service" ] && continue
        avant="$(networksetup -getdnsservers "$service" 2>/dev/null | tr '\n' ' ')"
        networksetup -setdnsservers "$service" empty >/dev/null 2>&1 \
            && ok "$service — était : $avant" \
            || alerte "$service — échec"
    done
    dscacheutil -flushcache >/dev/null 2>&1
    killall -HUP mDNSResponder >/dev/null 2>&1
    ok "cache DNS vidé"
}

reseau_complet() {
    reparer_reseau
    titre "Remise à zéro brutale"
    # Assumé : coupe aussi les proxys que Tamis n'a pas posés. C'est pour ça que
    # ce n'est pas le comportement par défaut.
    services_reseau | while read -r service; do
        [ -z "$service" ] && continue
        for type in setwebproxystate setsecurewebproxystate setsocksfirewallproxystate \
                    setftpproxystate setstreamingproxystate setgopherproxystate; do
            networksetup "$type" "$service" off >/dev/null 2>&1
        done
        ok "$service — tous les proxys coupés"
    done
    # Un bail neuf : celui obtenu pendant la panne peut porter les mauvais
    # serveurs de noms.
    for interface in $(networksetup -listallhardwareports 2>/dev/null | awk '/Device/{print $2}'); do
        ipconfig set "$interface" DHCP >/dev/null 2>&1 && ok "$interface — bail DHCP renouvelé"
    done
}

# ===========================================================================
# NETTOYAGE
# ===========================================================================

nettoyer() {
    avec_donnees="$1"

    # Le réseau d'abord, délibérément : tant que le DNS pointe vers un résolveur
    # mort, la machine est hors ligne. On lui rend la résolution tout de suite,
    # puis on fait le ménage tranquillement.
    reparer_reseau

    titre "Processus"
    for processus in "Tamis" "tamisd" "tamis-dnsd" "tamis-pac"; do
        if pgrep -x "$processus" >/dev/null 2>&1; then
            pkill -x "$processus" >/dev/null 2>&1; ok "$processus — arrêté"
        else
            info "$processus — ne tournait pas"
        fi
    done

    # Par préfixe d'identifiant plutôt que par liste de noms : une version
    # antérieure a pu poser un service que la liste d'aujourd'hui ne connaît
    # plus, et c'est ce genre de reste qui survit à une désinstallation.
    titre "Services launchd"
    for label in "$RESOLVER_LABEL" "$DAEMON_LABEL"; do
        launchctl print "system/$label" >/dev/null 2>&1 && {
            launchctl bootout "system/$label" >/dev/null 2>&1; ok "$label — arrêté"; }
    done
    en_utilisateur launchctl bootout "gui/$UID_UTILISATEUR/$HELPER_LABEL" >/dev/null 2>&1

    vu=0
    while read -r plist; do
        [ -z "$plist" ] && continue
        vu=1
        label="$(basename "$plist" .plist)"
        launchctl bootout "system/$label" >/dev/null 2>&1
        en_utilisateur launchctl bootout "gui/$UID_UTILISATEUR/$label" >/dev/null 2>&1
        rm -f "$plist" && ok "supprimé : $plist"
    done <<< "$(find /Library/LaunchDaemons /Library/LaunchAgents \
                     "$MAISON/Library/LaunchAgents" -maxdepth 1 \
                     \( -iname "*tamis*" -o -iname "*black0s*" \) 2>/dev/null)"
    [ "$vu" -eq 0 ] && info "aucun fichier de service Tamis"

    titre "Fichiers système"
    if [ -e "$PRIVILEGED_DIR" ]; then
        rm -rf "$PRIVILEGED_DIR" && ok "supprimé : $PRIVILEGED_DIR"
    else
        info "absent : $PRIVILEGED_DIR"
    fi
    for reste in "/Library/Logs/Tamis" "/var/log/tamis.log"; do
        [ -e "$reste" ] && rm -rf "$reste" && ok "supprimé : $reste"
    done

    titre "Certificats racine"
    retire=0
    for trousseau in $(trousseaux); do
        [ -e "$trousseau" ] || continue
        # En boucle : plusieurs installations laissent plusieurs exemplaires, et
        # delete-certificate n'en retire qu'un par appel.
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            en_utilisateur security find-certificate -c "$CA_NAME" "$trousseau" >/dev/null 2>&1 || break
            en_utilisateur security delete-certificate -c "$CA_NAME" "$trousseau" >/dev/null 2>&1 \
                || security delete-certificate -c "$CA_NAME" "$trousseau" >/dev/null 2>&1 \
                || break
            retire=$((retire + 1)); ok "autorité retirée de $trousseau"
        done
    done
    [ "$retire" -eq 0 ] && info "aucune autorité Tamis dans les trousseaux"

    titre "Application"
    vu=0
    for app in "/Applications/Tamis.app" "$MAISON/Applications/Tamis.app" \
               "$MAISON/Downloads/Tamis.app" "$MAISON/Desktop/Tamis.app"; do
        [ -d "$app" ] && { vu=1; supprimer_si_cest_tamis "$app"; }
    done
    while read -r app; do
        [ -z "$app" ] && continue
        case "$app" in
            */build/*) info "conservé : $app (produit de compilation)"; continue ;;
        esac
        [ -d "$app" ] && { vu=1; supprimer_si_cest_tamis "$app"; }
    done <<< "$(mdfind "kMDItemCFBundleIdentifier == '$BUNDLE_ID'" 2>/dev/null)"
    [ "$vu" -eq 0 ] && info "aucune application Tamis installée"

    titre "Fichiers de votre compte"
    SUPPORT="$MAISON/Library/Application Support/Tamis"
    for reste in "$SUPPORT/proxy.pac" "$SUPPORT/staging" \
                 "$MAISON/Library/Preferences/$BUNDLE_ID.plist" \
                 "$MAISON/Library/Caches/$BUNDLE_ID" \
                 "$MAISON/Library/HTTPStorages/$BUNDLE_ID" \
                 "$MAISON/Library/WebKit/$BUNDLE_ID" \
                 "$MAISON/Library/Containers/$BUNDLE_ID" \
                 "$MAISON/Library/Saved Application State/$BUNDLE_ID.savedState"; do
        [ -e "$reste" ] && rm -rf "$reste" && ok "supprimé : $reste"
    done
    # Les préférences sont mises en cache par cfprefsd : les supprimer sans le
    # prévenir les fait réapparaître au prochain lancement.
    en_utilisateur defaults delete "$BUNDLE_ID" >/dev/null 2>&1 && ok "préférences purgées du cache"

    if [ "$avec_donnees" = yes ]; then
        for donnee in "$SUPPORT/Lists" "$SUPPORT/Scripts" "$SUPPORT/history.sqlite" \
                      "$SUPPORT/applications.json"; do
            [ -e "$donnee" ] && rm -rf "$donnee" && ok "supprimé : $donnee"
        done
        rm -rf "$SUPPORT" 2>/dev/null
        ok "vos données ont été supprimées"
    else
        # Vos listes et vos scripts sont à vous : ils ne partent que si on les
        # demande, et jamais dans le même geste que le logiciel.
        [ -d "$SUPPORT" ] && info "vos listes, scripts et historique sont conservés"
    fi

    echo
    echo "════ vérification après nettoyage ════"
    diagnostic
}

# ===========================================================================
# MENU
# ===========================================================================

menu() {
    while true; do
        cat <<'MENU'

╭──────────────────────────────────────────────────────────╮
│  Tamis — secours                                         │
╰──────────────────────────────────────────────────────────╯

  1)  Diagnostic complet
      Examine tout et ne touche à rien. Aucun mot de passe.

  2)  Réparer le réseau
      Rend le DNS au DHCP, coupe le proxy automatique de Tamis
      et efface l'URL PAC résiduelle. Laisse le reste en place.

  3)  Rendre le DNS au DHCP
      Sur tous les services, sans condition — y compris pour
      remplacer un DNS public mis en dépannage.

  4)  Remise à zéro réseau brutale
      Coupe TOUS les proxys, même ceux que Tamis n'a pas posés,
      et renouvelle les baux DHCP.

  5)  Tout retirer
      Application, démons, certificat racine, fichiers, réseau.
      Vos listes, scripts et historique sont conservés.

  6)  Tout retirer, données comprises
      Comme 5, mais supprime aussi vos listes et vos scripts.

  q)  Quitter

MENU
        printf "  Votre choix : "
        read -r choix
        case "$choix" in
            1) diagnostic ;;
            2) exiger_root --reseau;          reparer_reseau;  echo; diagnostic ;;
            3) exiger_root --dns-dhcp;        dns_dhcp;        echo; diagnostic ;;
            4) exiger_root --reseau-complet;  reseau_complet;  echo; diagnostic ;;
            5) exiger_root --nettoyer;        nettoyer no ;;
            6) confirmer_donnees && { exiger_root --tout; nettoyer yes; } ;;
            q|Q|"") echo "  Rien n'a été modifié à la sortie."; exit 0 ;;
            *) echo "  Choix inconnu : « $choix »" ;;
        esac
    done
}

# Le seul choix irréversible du menu se fait confirmer. Les listes et les
# scripts que quelqu'un a écrits ne se suppriment pas sur une faute de frappe.
confirmer_donnees() {
    echo
    echo "  Cela supprimera aussi vos listes de filtres, vos scripts et votre"
    echo "  historique. Cette partie n'est pas récupérable."
    printf "  Tapez « supprimer » pour confirmer : "
    read -r reponse
    [ "$reponse" = "supprimer" ] && return 0
    echo "  Annulé — rien n'a été supprimé."
    return 1
}

# ===========================================================================

case "${1:-}" in
    "")                menu ;;
    --diagnostic|--verifier) diagnostic ;;
    --reseau)          exiger_root --reseau;         reparer_reseau; echo; diagnostic ;;
    --dns-dhcp)        exiger_root --dns-dhcp;       dns_dhcp;       echo; diagnostic ;;
    --reseau-complet)  exiger_root --reseau-complet; reseau_complet; echo; diagnostic ;;
    --nettoyer)        exiger_root --nettoyer;       nettoyer no ;;
    --tout)            exiger_root --tout;           nettoyer yes ;;
    -h|--help)         sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//' ;;
    *) echo "argument inconnu : $1 (essayez --help)" >&2; exit 2 ;;
esac
