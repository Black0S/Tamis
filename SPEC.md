# Tamis — Spécification

> Bloqueur de publicités et de télémétrie pour macOS, entièrement natif Swift.
> Filtre tous les navigateurs et les applications depuis l'extérieur, sans extension.

**Version du document :** 1.0 — 9 août 2026
**Auteur :** Tao ([@Black0S](https://github.com/Black0S))

---

## 1. Contraintes de projet — non négociables

| Contrainte | Détail |
|---|---|
| **Zéro dépendance à un compte Apple** | Aucun entitlement, aucun certificat Developer ID, aucune approbation Apple. Quiconque clone le dépôt obtient une app pleinement fonctionnelle |
| Plateforme | macOS 26+, Apple Silicon (arm64) uniquement |
| Langage | Swift 6.3+, SwiftUI. Pas d'Objective-C, pas de webview |
| Licence | GPLv3 |
| Télémétrie | **Aucune. Jamais.** Pas même un rapport de crash |
| Distribution | Sources + `.dmg` non notarisé, build reproductible via GitHub Actions |

Toute décision technique se mesure à la première ligne. La couche NetworkExtension
(proxy transparent) est **définitivement hors périmètre** : un entitlement est lié à
un Team ID, donc un fork ne pourrait pas produire un binaire fonctionnel.

---

## 2. Vue d'ensemble

Tamis agit sur deux couches complémentaires :

```
┌─ Couche 1 ── DNS ────────────────────────────────────┐
│  Résolveur local, blocklists hosts, DoH chiffré      │
│  Portée : toute la machine, y compris daemons système │
└───────────────────────────────────────────────────────┘
┌─ Couche 2 ── Proxy MITM ─────────────────────────────┐
│  Blocage ABP, filtrage cosmétique, injection JS/CSS  │
│  Portée : navigateurs + apps respectant le proxy     │
└───────────────────────────────────────────────────────┘
```

**Positionnement.** Safari n'a plus d'uBlock Origin, et Chrome n'a plus qu'uBO Lite
bridé par Manifest V3. Tamis est fort précisément là où les extensions ont perdu du
terrain, et il déborde du navigateur.

**Limite assumée.** Sur Firefox, uBlock Origin reste supérieur en filtrage cosmétique :
il s'exécute dans la page avec un accès DOM complet. Tamis injecte depuis l'extérieur.

---

## 3. Architecture — trois processus

| Composant | Privilèges | Rôle |
|---|---|---|
| `tamisd` — LaunchDaemon | **root**, minimal | `networksetup`, trousseau système, `launchctl`, signature des certificats feuille, garde-fou de désinstallation. **Aucun parsing de données réseau.** ~500 lignes |
| `tamis-dnsd` — LaunchDaemon | `_tamis`, socket activé | Résolveur DNS, blocklists, DoH amont. Actif dès le boot |
| `Tamis.app` | session utilisateur | UI + proxy MITM + serveur PAC + moteur de filtres |

**Propriété centrale :** aucun code exposé à du contenu hostile ne tourne jamais en root.

### 3.1 Le port 53 sans root

`tamis-dnsd` n'est **jamais** root. launchd lie le socket lui-même au chargement et
passe le descripteur au processus :

```xml
<key>UserName</key>       <string>_tamis</string>
<key>Sockets</key>
  <key>DNS</key>
    <key>SockServiceName</key> <string>53</string>
    <key>SockNodeName</key>    <string>127.0.0.1</string>
```

Récupération via `launch_activate_socket()`. L'utilisateur `_tamis` est créé par `dscl`
pendant le lot élevé de l'onboarding.

### 3.2 Le proxy dans l'app

Décidé ainsi parce que **quitter l'app équivaut à une pause** (voir §12.1) : le proxy
n'a pas besoin de survivre. Bénéfices : un seul target à lancer en développement,
statistiques temps réel sans flux XPC. Le fail-open couvre le crash.

### 3.3 Sécurité de l'IPC

`tamisd` expose un service Mach. Sans validation, **tout processus local pourrait lui
donner des ordres en root**.

```swift
listener.setConnectionCodeSigningRequirement(requirement)  // macOS 13+
```

**Le certificat étant auto-signé, il faut épingler son empreinte, pas son CN** —
n'importe qui peut fabriquer un certificat portant le même nom :

```
❌  identifier "io.github.black0s.tamis" and certificate leaf[subject.CN] = "Tamis"
✅  identifier "io.github.black0s.tamis" and certificate leaf = H"<SHA-1 DER>"
```

Validation dans les deux sens. Ne **jamais** valider par PID (réutilisation d'identifiants).

### 3.4 Vocabulaire minimal du daemon

Même authentifié, un client compromis ne doit pas pouvoir nuire :

```swift
enum Operation {
    case dns(.tamis | .system)              // deux états, pas plus
    case proxy(.pac(port: UInt16) | .off)   // port validé par plage
    case signLeaf(domain: String)           // nom strictement validé
    case installCA | renewCA | uninstall
}
```

Jamais de chemin, de commande shell ou de nom de service réseau venu du client.

### 3.5 Conséquence opérationnelle

Le **certificat de signature auto-signé est un actif critique** :
15-20 ans de validité, sauvegardé hors ligne, jamais renouvelé à la légère.
Le perdre casse l'exigence de signature XPC **et** l'ACL Keychain de la CA.

---

## 4. Couche 1 — DNS

### 4.1 Fonctions

- Résolveur local sur `127.0.0.1:53` **et `[::1]:53`**
- Upstream DoH/DoT — Cloudflare, Quad9, AdGuard, NextDNS, personnalisé
- Blocklists format hosts (§8)
- Cache respectant les TTL
- Règles par domaine via `/etc/resolver/` (split-DNS d'entreprise)
- DNS par app — **uniquement sur le trafic proxifié** (§4.4)

### 4.2 Bootstrap DoH

> **Règle absolue : `tamis-dnsd` n'appelle JAMAIS `getaddrinfo`.**
> Toute résolution via la bibliothèque système remonte à mDNSResponder, qui redescend
> vers `tamis-dnsd`. Interblocage, DNS mort sur toute la machine.

Fournisseurs connus → IP en dur, certificat validé sur le SAN IP :

| Fournisseur | IP |
|---|---|
| Cloudflare | `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111` |
| Quad9 | `9.9.9.9`, `149.112.112.112` |
| AdGuard | `94.140.14.14`, `94.140.15.15` |
| Google | `8.8.8.8`, `8.8.4.4` |

Serveur personnalisé → amorçage par requête UDP **directe** vers les résolveurs DHCP
relevés avant la bascule, résultat mis en cache persistant.

**Vérifié en conditions réelles :** Quad9, AdGuard et Google servent bien un
certificat portant leurs IP en SAN (`IP Address:9.9.9.9`, `149.112.112.112`…), donc
la connexion par IP littérale valide sans aucune résolution de nom.

**Mais `1.1.1.1` s'est révélé intercepté** sur le réseau de test : il répond au ping
en 6-12 ms et échoue pourtant la validation TLS, alors que `1.0.0.1` et l'adresse
IPv6 de Cloudflare sont propres. Cette adresse est largement détournée par des box
et des FAI.

D'où une distinction obligatoire dans le client :

| Échec | Signification | Traitement |
|---|---|---|
| Connexion refusée, timeout | Panne réseau | Bascule silencieuse sur l'endpoint suivant |
| **Certificat non valide** | **Interception du DNS chiffré** | Bascule **et alerte** |

Basculer en silence dans le second cas masquerait précisément ce que Tamis existe
pour révéler. Les diagnostics par endpoint sont conservés même en cas de succès, pour
que l'UI puisse dire « 1.1.1.1 est intercepté sur ce réseau, 1.0.0.1 utilisé à la
place » plutôt que de laisser croire que le résolveur choisi est celui qui répond.

### 4.3 Fail-open

DoH injoignable → **repli sur le DNS DHCP en clair**, avec alerte visible.
Pas de DNS = pas d'Internet ; aucun bénéfice de confidentialité ne justifie de rendre
la machine inutilisable.

### 4.4 Ce que le DNS ne peut pas faire

Toutes les requêtes DNS de macOS transitent par **`mDNSResponder`**. Le client vu par
le résolveur est toujours ce daemon — l'app d'origine est perdue.

**Les règles DNS sont donc globales.** Le DNS par app n'est possible que sur le trafic
proxifié, où le proxy résout lui-même pour le compte de l'app identifiée.

### 4.5 Navigateurs en DoH

Firefox fait son propre DoH. Parade officielle : répondre **NXDOMAIN** sur le domaine
sentinelle `use-application-dns.net` → Firefox désactive son DoH de lui-même.

Ne fonctionne qu'en mode automatique. Si l'utilisateur a explicitement activé DoH,
la sentinelle est ignorée.

Chrome et dérivés n'activent leur DoH automatique que si le DNS système figure dans
leur liste de fournisseurs connus. `127.0.0.1` n'y est pas → ils restent sur le système.

**Diagnostic DNS** — détection des navigateurs qui contournent :
- Firefox → `network.trr.mode` dans le `prefs.js` du profil
- Chromium → `dns_over_https.mode` dans le `Preferences` JSON

### 4.6 IPv6 — dans le périmètre

- Sert les AAAA ; un domaine bloqué l'est **pour A et AAAA**
- `networksetup -setdnsservers` → `127.0.0.1` **et** `::1`
- PAC gère les littéraux entre crochets `[2001:db8::1]`
- Proxy amont en Happy Eyeballs v2

> Bloquer uniquement sur `A` laisse passer tout le trafic IPv6. Fuite silencieuse
> et permanente sur une box moderne.

---

## 5. Couche 2 — Proxy MITM

### 5.1 Le PAC

- Servi sur un port haut par un helper qui **survit à l'app**
- **Sans `dnsResolve()`** — matching de chaînes pur, sinon l'évaluation du PAC
  déclenche elle-même des résolutions DNS
- Renvoie `DIRECT` pour les exclusions HTTPS → le trafic bancaire ne traverse
  jamais le process
- **Fail-open** : si le proxy ne répond plus, le helper sert `return "DIRECT"`

**Exclusions de développement local — `DIRECT` inconditionnel :**

```
localhost · 127.0.0.0/8 · ::1
10.0.0.0/8 · 172.16.0.0/12 · 192.168.0.0/16 · fc00::/7
*.local · *.internal · *.test · *.localhost
host.docker.internal · docker.internal
tout nom d'hôte sans point
```

Sans elles, les serveurs de développement, les stacks Docker exposées sur des ports
locaux et les services LAN traversent le proxy pour rien : surcoût inutile et risque
de casse sur du WebSocket local ou du HTTP non standard. Ni Zen ni AdGuard ne le
documentent — c'est de la logique PAC, pas une liste de domaines, donc facile à
oublier et très visible quand ça manque.

### 5.2 HTTP/2 des deux côtés

**Décision d'architecture :** normaliser les deux protocoles vers un modèle interne
unique de forme HTTP/1, via `HTTP2FramePayloadToHTTP1ServerCodec`.

```
Client h2 ─┐                                  ┌─ Amont h2
           ├─→ modèle interne → moteur → ─────┤
Client h1 ─┘    requête/réponse   injection   └─ Amont h1
```

Le moteur, la classification et l'injection ignorent le protocole de transport.
Le mélange h2/h1 est un chemin de première classe, pas un cas d'exception.

**Gain :** pool de connexions amont indexé par `(hôte, port, ALPN)`. Une page à
80 ressources passe de 80 handshakes TLS à un seul.

**Quatre pièges :**

| Piège | Traitement |
|---|---|
| `chunked` interdit en h2 | N'émettre ce cadrage que si le client est en HTTP/1.1 |
| Pseudo-en-têtes | `:authority` remplace `Host` — seule la couche de normalisation lit les en-têtes bruts |
| Contrôle de flux | **Plafond dur de 2 Mo** sur le buffer d'injection, sinon retenir des données bloque toute la connexion |
| Server push | `SETTINGS_ENABLE_PUSH = 0`, jamais implémenté |

### 5.3 Éligibilité à l'injection — prédicat positif

On bufferise **si et seulement si** :

```
statut == 200                      (ni 206, ni 304, ni 3xx, ni 1xx)
Content-Type  text/html | application/xhtml+xml
Sec-Fetch-Dest  document | iframe  (quand présent)
Content-Encoding  décodable        (gzip, br)
pas de Content-Range
taille sous 2 Mo
```

Tout le reste : relais pur, zéro copie. Formulation positive → **tout cas non prévu
tombe du bon côté**.

> `103 Early Hints` arrive **avant** la vraie réponse. Un parseur naïf le prend pour
> la réponse finale et casse la page. Relayer les `1xx` et continuer d'attendre.

### 5.4 Négociation de compression

Les navigateurs annoncent désormais **zstd**. Si le serveur répond en zstd et qu'on
ne sait pas le décoder, l'injection échoue **en silence**.

Sur les seules requêtes injectables, réécrire l'en-tête sortant :

```
Accept-Encoding: gzip, deflate, br, zstd  →  gzip, deflate, br
```

**Brotli est conservé** : le framework `Compression` d'Apple l'implémente
(`COMPRESSION_BROTLI`), donc le supporter ne coûte aucun décompresseur C tiers dans un
processus dont toute l'entrée est hostile. Vérifié par aller-retour.

Le coût de l'exclure a été mesuré sur de vraies pages, et il est loin d'être
négligeable : les sites qui servent effectivement du brotli perdent **de +13 % à
+50 %** sur le document, et jusqu'à **+191 %** dans un cas. En revanche, beaucoup de
grands sites (Le Monde, Wikipédia, GitHub, Le Figaro) servent du gzip même quand le
navigateur propose brotli — coût nul pour eux.

**zstd reste exclu**, et c'est vérifié plutôt que supposé :

- `COMPRESSION_ZSTD` n'existe pas ; le framework expose BROTLI, LZ4, LZBITMAP, LZFSE,
  LZMA, ZLIB. Aucune `libzstd` n'est présente sur le système
- Sur **dix sites testés**, aucun ne sert de zstd — pas même ceux de Cloudflare, qui le
  supportent pourtant. Avec l'en-tête complet d'un navigateur ils choisissent tous
  brotli ou gzip ; avec `zstd` seul ils retombent en `identity`
- L'ajouter imposerait de vendoriser un décompresseur C dans un processus dont toute
  l'entrée est hostile — le compromis refusé pour brotli, sans l'implémentation Apple
  pour l'éviter

**À instrumenter :** une origine qui enverrait du zstd malgré notre `Accept-Encoding`
verrait sa page privée de filtrage cosmétique, silencieusement. Le verdict
`undecodableEncoding` doit donc alimenter un compteur du panneau diagnostic — c'est ce
qui transformera cette hypothèse en observation le jour où elle cessera d'être vraie.

**Borne obligatoire au décodage.** Quelques kilo-octets de gzip peuvent devenir des
gigaoctets ; un décodeur non borné est un déni de service muni d'un en-tête
`Content-Encoding`. La limite est celle du budget d'injection.

### 5.5 CSP

Beaucoup de sites interdisent les styles et scripts inline. Sans réécriture de
l'en-tête `Content-Security-Policy`, **toutes les injections échouent silencieusement**.
C'est le bug numéro un des implémentations naïves.

### 5.6 WebSocket

- HTTP/1.1 → `Upgrade: websocket` classique
- **HTTP/2 → CONNECT étendu (RFC 8441)**, `SETTINGS_ENABLE_CONNECT_PROTOCOL`,
  pseudo-en-tête `:protocol`. Deux chemins de code

`$websocket` s'applique **au handshake, et lui seul**. Après le `101`, la connexion
est opaque. Ensuite : relais bidirectionnel sans inspection.

### 5.7 Réponse à une requête bloquée

**Jamais** couper la connexion ni envoyer `RST_STREAM` — certains sites cassent sur
une erreur réseau. Renvoyer une réponse vide bien formée (`204`, ou `200` vide avec
le bon `Content-Type`). Pour `$redirect`, la ressource neutralisée d'uBO.

### 5.8 Écoute

`127.0.0.1` et `::1` **uniquement**, jamais `0.0.0.0`. Pas d'authentification : un
processus local peut déjà ouvrir ses propres sockets, Tamis ne lui donne aucune
capacité nouvelle — il la rend seulement **visible** dans l'historique.
À écrire tel quel dans le threat model.

### 5.9 QUIC / HTTP3

Non intercepté. Avec un PAC configuré, Chrome désactive QUIC de lui-même et retombe
sur TLS/TCP.

---

## 6. Moteur de filtres

### 6.1 Périmètre — syntaxe ABP intégrale

```
Type       $script $image $stylesheet $object $xmlhttprequest $subdocument
           $document $font $media $websocket $ping $other
Portée     $domain= $from= $to= $third-party $strict1p $strict3p
           $method $ipaddress
Action     $important $badfilter $all $empty $redirect $redirect-rule
           $removeparam $replace $csp $header $permissions $urltransform
Exceptions @@ · $elemhide $generichide $specifichide $document $content

Cosmétique ##  #@#
Procédural :has() :has-text() :matches-css() :matches-media() :matches-path()
           :matches-attr() :min-text-length() :others() :upward() :xpath()
           :watch-attr() :remove() :style()
Styles     #$#
Scriptlets ##+js()  — ~200 scriptlets à porter depuis uBO (GPLv3, compatible)
HTML       ##^ — retrait dans le flux, avant parse
```

### 6.2 Classification des requêtes — clé de voûte

uBlock connaît le type de chaque requête via l'API `webRequest`. Un proxy ne voit
que du HTTP.

Reconstitution via **`Sec-Fetch-Dest`** (`image`, `script`, `style`, `document`,
`iframe`, `font`), complété par `Accept` et l'extension. **À implémenter en premier
et à tester sérieusement** — tout le support des modificateurs de type en dépend.

Dégradé pour les apps non-navigateur, qui n'envoient pas cet en-tête.

### 6.3 Hors de portée — par nature d'un proxy

| | Pourquoi |
|---|---|
| `$popup` fiable | Le proxy ne sait pas qu'une navigation est une popup |
| `$webrtc` | WebRTC sort en UDP direct |
| `$ping` précis | `sendBeacon` indiscernable d'un `fetch` en `no-cors` |

À documenter comme non supportés.

### 6.4 Supériorités sur uBlock

- **`$cname`** — décloisonnement CNAME. Les trackers se déguisent en sous-domaines
  du site via un CNAME. uBO ne peut le contrer que sur Firefox ; Tamis **est** le
  résolveur DNS, sur tous les navigateurs
- **Filtrage HTML avant parse** — aucun scintillement
- **Tous les navigateurs à la fois**, plus les apps hors navigateur
- **Immunité au Manifest V3** — aucun quota de règles

### 6.5 Cache compilé

```
magic(4) │ formatVersion(2) │ engineVersion │ hashSources(32) │ payload
```

Version ou hash différents → **on jette et on recompile**.
**On ne migre jamais un cache** : c'est de la donnée dérivée, régénérable en quelques
secondes. Du code de migration pour ça est une dette permanente.

---

## 7. Certificats et sécurité TLS

### 7.1 Autorité de certification

- ECDSA P-256, **10 ans**, `notBefore` antidaté d'une heure
- CN : `Tamis Local CA (<nom-du-Mac>)` — rend la désinstallation ciblée et distingue
  les CA après une restauration
- **La clé privée ne quitte jamais `tamisd`.** Le daemon signe lui-même les
  certificats feuille sur demande

> Le proxy représente des dizaines de milliers de lignes exposées à du TLS, du HTML
> et des règles venues d'Internet. Le daemon en fait 500 et ne lit rien d'hostile.
> La clé maîtresse est tenue par le petit composant.
>
> **Même une compromission complète du proxy ne permet pas d'exfiltrer la CA.**

### 7.2 Certificats feuille

- Validité **7 jours**, `notBefore` antidaté d'une heure
- **Une seule paire de clés partagée par tous les feuilles** — la génération de clé
  est l'opération coûteuse, la signature ne l'est pas (pratique de mitmproxy)
- Cache LRU 2 000 entrées, **TTL 24 h** — nettement inférieur à la validité, sinon
  un certificat expire en cache et la connexion casse sans raison apparente
- `CONNECT` vers une IP sans SNI → certificat avec **IP en SAN**

### 7.3 Validation du certificat amont

Code critique. Chaîne, dates, SANs, révocation, avec la même rigueur qu'un navigateur.
Sans cela on **dégrade** la sécurité au lieu de la protéger, et le navigateur ne voit
rien puisqu'il nous fait confiance.

Tests dédiés : certificat expiré, auto-signé, mauvais domaine → la connexion **doit**
échouer visiblement.

**Utiliser `SecTrustEvaluate` avec le magasin de confiance du système, jamais un jeu
de racines embarqué.** Ce que le Mac approuve, Tamis l'approuve — y compris les CA de
développement ajoutées par l'utilisateur (Caddy Local Authority, `mkcert`, CA
d'entreprise). Un CA bundle embarqué « pour être sûr » casserait tout environnement
de développement HTTPS local, avec un échec bruyant et incompréhensible.

### 7.4 Replis automatiques

| Échec | Signification | Réponse |
|---|---|---|
| Le **client** refuse **notre** certificat | Certificate pinning | Tunnel aveugle ✅ |
| `CertificateRequest` reçu du serveur | mTLS — certificat client requis | Tunnel aveugle ✅ |
| Le certificat du **serveur amont** est invalide | Possible attaque réelle | **Échouer bruyamment** ❌ |

Confondre les deux derniers masquerait un problème de sécurité réel.

**Mécanisme :** échec → enregistrement → l'app retente → tunnel aveugle → après
3 échecs, cache de passthrough → après plusieurs domaines, alerte proposant
l'exclusion permanente. L'app se répare seule avant de demander quoi que ce soit.

### 7.5 Expiration et renouvellement

```
T-90 j    alerte condition, non rejetable
T-30 j    + notification système
T-7  j    notification quotidienne
Expirée   ⚠️  PROTECTION MISE EN PAUSE AUTOMATIQUEMENT
```

Une CA expirée casserait **tous les sites**. On préfère la pause — Tamis ne doit
jamais être la raison pour laquelle un Mac devient inutilisable.

**Ordre de renouvellement — critique :**

```
1. générer la nouvelle CA
2. l'installer (trousseau + profils Firefox)
3. VÉRIFIER qu'elle est approuvée
4. basculer la signature des feuilles
5. vider le cache de certificats
6. seulement maintenant : retirer l'ancienne
```

**Réinstallation :** CA Tamis + clé privée présentes → réutiliser, aucun mot de passe.
CA sans clé → retirer et régénérer. **Jamais deux CA Tamis empilées.**

### 7.6 Pile TLS

Ne **pas** épingler `swift-nio-ssl` sur une version exacte. Les navigateurs négocient
l'échange de clés post-quantique `X25519MLKEM768` par défaut. Le risque n'est pas la
casse — c'est de perdre la protection post-quantique sans s'en apercevoir.

Mesures : job CI vérifiant le groupe négocié, affichage du groupe dans le diagnostic.

### 7.7 Firefox

Magasin NSS séparé (`cert9.db`) par profil. Sans injection de la CA, **erreur de
certificat sur chaque site**.

---

## 8. Listes

### 8.1 Principe fondateur

> **Au premier lancement, aucune blocklist n'est téléchargée ni active.**
> Le choix appartient entièrement à l'utilisateur.

**Exception, et ce n'en est pas une :** les listes d'exclusion HTTPS sont embarquées
et actives d'emblée. Ce n'est pas un filtre mais un mécanisme de sécurité — sans
elles, la première connexion bancaire serait déchiffrée.

### 8.2 Exclusions HTTPS — verrouillées

**Sources indépendantes, jamais fusionnées.** Chacune conserve son origine, sa licence,
sa cadence de mise à jour, son diff et son garde-fou propres.

> Fusionner rendrait le diff inexploitable (quelle source a bougé ?), imposerait une
> re-fusion à chaque mise à jour amont, diluerait l'attribution, et on ne saurait plus
> chez qui remonter un domaine manquant.

**Union au matching, pas au stockage.** Un domaine exclu par n'importe quelle source
est exclu, avec dédoublonnage à la volée. Les recouvrements — `apple.com` figure dans
les deux — sont sans conséquence. C'est le modèle déjà retenu pour les blocklists.

**Source 1 — [AdguardTeam/HttpsExclusions](https://github.com/AdguardTeam/HttpsExclusions), MIT**

| Fichier | Domaines | Contenu |
|---|---:|---|
| `banks.txt` | 4 000 | Banques et services financiers |
| `sensitive.txt` | 188 | Gestionnaires de mots de passe, messageries chiffrées, sécurité sociale |
| `issues.txt` | 74 | Cas cassés identifiés — Syncthing, `idmsa.apple.com`… |
| `mac.txt` | 19 | Spécifique macOS |
| `firefox.txt` | 18 | Sans quoi : plus d'add-ons ni de sync Firefox |
| **Total** | **4 289** | après dédoublonnage |

**Source 2 — [Zen](https://github.com/irbis-sh/zen-desktop) `internal/sysproxy/exclusions`, MIT**

| Fichier | Domaines | Contenu |
|---|---:|---|
| `darwin.txt` | ~130 | Services Apple, sourcés de l'article **Apple HT210060** — installation, MDM, mises à jour système, validation de certificats, Apple Pay, iCloud Private Relay, Apple Intelligence |
| `common.txt` | ~20 | Pages de connexion et sites gouvernementaux — dont `gouv.fr` |

Bien plus complète que le `mac.txt` d'AdGuard sur le périmètre Apple (~130 contre 19).
L'article Apple comporte une section « Recent changes » à surveiller.

**Source 3 — Mes exclusions**

Ajoutées par l'utilisateur, pleinement éditables, stockées à part, jamais écrasées.

**UI :** les sources sont affichées séparément, chacune avec son cadenas, son compteur,
sa date et son toggle de mise à jour. La recherche « ma banque est-elle protégée ? »
répond **par quelle source**.

**Syntaxe :**

```
example.com                        domaine + sous-domaines
"example.com"                      domaine exact uniquement
example.com$app=com.openai.atlas   restreint à une app
a.com$app=com.foo|com.bar          plusieurs apps
```

Commentaires : les fichiers utilisent `//`, le README annonce `#` — **parser les deux**.
63 règles portent déjà `$app=`, en bundle ID sur macOS : la liste s'ingère telle quelle.

**Conséquence majeure :** `mac.txt` exclut `apple.com`, `icloud.com`, `mzstatic.com`,
et `issues.txt` ajoute `idmsa.apple.com`, `updates.cdn-apple.com`.
**La télémétrie Apple ne sera jamais filtrable en couche 2.** La couche 1 est le seul
levier — ce n'est plus un choix d'architecture, c'est imposé.

**UI :** verrouillées, cadenas, non désactivables. Toggle de mise à jour auto par
liste. Champ de recherche répondant à « ma banque est-elle protégée ? » — couverte
ou non, par quelle liste, en exact ou avec sous-domaines, avec quelle restriction
`$app=`. Section « Mes exclusions » séparée, éditable, jamais écrasée.

**Verrou dur** sur `banks` et `sensitive`. Surcharge d'entrée individuelle possible
sur `issues`, `mac` et `firefox` — ce sont des correctifs de compatibilité.

### 8.3 Catalogue de blocklists

Fusion dédoublonnée par URL de téléchargement de deux registres :

| Source | Entrées | Groupes |
|---|---:|---|
| uBO `assets.json` | 71 | default 6, ads 3, privacy 3, malware 2, annoyances 17, multipurpose 2, regions 38 |
| AdGuard `filters.json` | 88 | Ad blocking, Privacy, Social widgets, Annoyances, Security, Other, Language-specific |

≈ 150 listes, avec les descriptions riches d'AdGuard (`description`, `homepage`,
`downloadUrl`, `languages`, `tags`, `trustLevel`, `deprecated`).

**Section DNS supplémentaire** — format hosts, absente des deux registres :
Hagezi, OISD, StevenBlack, AdGuard DNS filter.

**Seules les métadonnées sont embarquées** (~100 Ko) : le catalogue est consultable
hors ligne dès le premier lancement, sans qu'aucune liste ne soit téléchargée.

**UI :** rien n'est coché. Badge « recommandé » purement informatif. Bouton
**« Sélection suggérée »** cochant un ensemble raisonnable en un clic, à l'initiative
de l'utilisateur. Entrée « Ajouter par URL ».

### 8.4 Garde-fous de mise à jour

```
1. Transport   HTTP 200, Content-Length == octets reçus, TLS strict
2. Syntaxe     le fichier parse, en-têtes cohérents
3. Non vide    > 0 entrée
4. Amplitude   rejet si nouveau < 80 % de l'actuel ET perte > 25 entrées
5. Global      contrôle appliqué au TOTAL, pas fichier par fichier
```

Les points 1-2 attrapent le cas fréquent — téléchargement tronqué. Le point 4 combine
relatif et absolu pour ne pas être nerveux sur les petites listes (`mac.txt` = 19
entrées). Le point 5 absorbe les réorganisations amont.

**Contrôles 4-5 réservés aux exclusions.** Pour les blocklists, une diminution est
sans danger ; 1-3 suffisent.

### 8.5 Diff et validation

Fréquence mesurée des exclusions : **30 commits sur 12 mois**, médiane **+1 ligne**,
plus gros changement de l'année 44 lignes. La validation systématique est donc
soutenable.

**Traitement par direction, pas par taille :**

| Changement | Effet | Traitement |
|---|---|---|
| Domaine **ajouté** | Plus de protection | Appliqué immédiatement, consigné |
| Domaine **retiré** | Moins de protection | **Validation requise** |

Bloquer un ajout en attendant une validation laisserait une banque non protégée
pendant l'absence de l'utilisateur : l'attente irait dans le mauvais sens.

Résultat : 3 à 5 validations par an, toutes pertinentes.

```
📋 ROUTINE      Ajouts appliqués, diff consultable au journal. Aucune interruption
🔔 VALIDATION   Retraits proposés. Non appliqué tant que l'utilisateur n'a pas tranché
🚨 ANOMALIE     Garde-fou déclenché. Notification système, badge rouge, rien d'appliqué
```

**Blocklists :** application automatique, journal consultable, alerte seulement si
les contrôles de transport ou de syntaxe échouent. EasyList change plusieurs fois
par jour par milliers de lignes — deux natures de listes différentes.

**Les deux dernières versions sont conservées** → diff et **retour arrière** gratuits.

### 8.6 Liste blanche interne — priorité absolue

> **Une blocklist peut bloquer le domaine nécessaire à la mise à jour des blocklists.**

Une liste agressive contenant `raw.githubusercontent.com` verrouillerait l'app
définitivement, sans que l'utilisateur puisse comprendre pourquoi.

La liste blanche interne prime sur **tout** : blocklists, règles utilisateur,
exclusions. C'est la seule règle du système sans aucune exception.

Elle contient : endpoints DoH, sources de listes, domaines de release GitHub.

**Et elle est visible.** Écran en lecture seule « Domaines système de Tamis », chaque
exception avec sa justification. Une liste blanche codée en dur et invisible dans un
logiciel qui intercepte tout le trafic a la forme exacte d'une porte dérobée.

Le trafic propre de Tamis ne passe **ni par son proxy** (`connectionProxyDictionary = [:]`)
**ni par ses filtres**.

---

## 9. Userscripts et userstyles

### 9.1 Formats

- **Userscripts** — en-tête Tampermonkey : `@match`, `@include`/`@exclude`,
  `@run-at`, `@grant`, `@require`, `@resource`, `@version`, `@downloadURL`
- **Userstyles** — CSS brut avec portée définie dans l'UI, **ou** UserCSS
  (`==UserStyle==`, `@-moz-document domain()`, `url-prefix()`, `regexp()`)

Le matching d'URL réutilise le matcher de domaines du moteur — aucun code en double.

### 9.2 Timing

`document-start` est natif (injection dans le `<head>`). `document-end` et
`document-idle` s'obtiennent par un listener `DOMContentLoaded` ou `load`.

### 9.3 Deux supériorités sur une extension

- **`GM_xmlhttpRequest`** — son intérêt est de contourner le CORS, normalement
  impossible depuis du JS de page. Mais **Tamis est le proxy** : un endpoint interne
  reçoit l'appel du shim et exécute la requête cross-origin côté natif
- **`unsafeWindow`** — injection en contexte de page, pas de monde isolé, donc
  `unsafeWindow === window`. Revers : pas d'isolation, la page peut voir le script

Reste du shim `GM_*` : quelques centaines de lignes de JS.

### 9.4 Portée par app

Bidimensionnelle — `@match` **et** application :

```
Script « YouTube sans Shorts »
  @match  https://youtube.com/*
  Apps    Safari, Helium         ← pas Chrome, pas Firefox
```

**Définie dans l'UI, pas dans le fichier.** Une mise à jour du script écraserait une
restriction écrite dans l'en-tête. Un `@app` optionnel est lu comme valeur par défaut
s'il est présent ; le format Tampermonkey ignore les clés inconnues, donc aucune
divergence introduite.

Le même mécanisme s'applique aux userstyles et aux listes de filtres.

**Apps Electron :** Slack, Notion, Discord rendent du HTML qui traverse le proxy —
l'injection y fonctionne. Réserves : une partie de leur UI vient de fichiers locaux
hors HTTP, et toutes ne respectent pas le proxy. À présenter comme un bonus.

### 9.5 Fail-closed

Attribution d'app échouée → **on n'injecte pas**. Exécuter du JS arbitraire dans une
app inconnue est plus grave que rater un blocage. Règle différente de celle du
filtrage, pour un niveau de risque différent.

Même règle pour les styles : une injection réussissant sur certaines connexions et
échouant sur d'autres produit des pages à moitié stylées et du scintillement.

### 9.6 Ordre d'injection

Filtrage cosmétique **d'abord**, userstyles **ensuite** — pour qu'un style utilisateur
puisse surcharger une règle de masquage.

### 9.7 Organisation — l'arborescence est le système de fichiers

Les dossiers créés dans l'UI sont de **vrais dossiers** dans
`~/Library/Application Support/Tamis/Scripts/`, chaque script un vrai fichier
`.user.js` / `.user.css`.

Gains immédiats : ouverture dans VS Code ou Zed, versionnement **git**, sauvegarde
par copie, réorganisation depuis le Finder.

Un manifeste unique à la racine porte les métadonnées (portée, activation, URL source,
empreinte d'origine), indexé par chemin relatif, avec réconciliation au lancement.

**Un dossier porte un interrupteur qui cascade.** Pas d'héritage de portée par app :
dès qu'un enfant surcharge un parent, « pourquoi ce script ne s'exécute pas ? »
devient indiagnosticable.

### 9.8 Mises à jour et édition

- Rafraîchissement **par script, par dossier, global**
- **Diff affiché avant application**, jamais de mise à jour aveugle
- Empreinte de l'original conservée → script modifié localement détecté → choix
  entre garder, prendre la nouvelle, comparer
- **« Revenir à la version d'origine »** gratuit
- Éditeur intégré monospace + **« Ouvrir dans un éditeur externe »** avec surveillance
  du fichier et rechargement (coloration syntaxique en second temps)
- **Validation à l'enregistrement sans dépendance :** `JavaScriptCore` est un
  framework système ; envelopper la source dans un constructeur `Function` la fait
  **parser sans l'exécuter**

### 9.9 Sécurité

Écran d'installation affichant la **portée `@match`** et la source.
**Pas de mise à jour automatique silencieuse** depuis une URL tierce — opt-in par script.

---

## 10. Applications et navigateurs

### 10.1 Attribution

Port source → PID via `libproc` (`proc_pidinfo` + `PROC_PIDLISTFDS`,
`proc_pidfdinfo` + `PROC_PIDFDSOCKETINFO`) → `proc_pidpath` → bundle ID.

**Deux précautions :**
- **Coût** — scan des processus et de leurs descripteurs. Ne l'exécuter que si des
  règles par app sont actives ; caches `port → PID` et `PID → app`
- **Course** — une connexion très courte peut fermer son socket avant le scan.
  Politique de repli explicite et configurable

### 10.2 Trois états par app

**Filtrer** (MITM complet) · **Laisser passer** (tunnel `CONNECT` aveugle) · **Bloquer**

Exclusions pré-remplies pour le certificate pinning : Signal, Dropbox, Docker,
App Store. **Ce n'est pas du confort** — sans elles, ces logiciels sont inutilisables.

### 10.3 Découverte des navigateurs — dynamique

```swift
NSWorkspace.shared.urlsForApplications(toOpen: URL(string: "https://example.com")!)
```

macOS tient le registre de toutes les apps déclarant gérer le HTTP. Retourne **tous**
les navigateurs, y compris ceux sortis après la release. Zéro maintenance.

**Caractérisation par structure, pas par nom :**

| Signature dans le bundle | Moteur |
|---|---|
| `Contents/Frameworks/*.framework` + `Contents/Versions/` | Chromium |
| `Contents/Resources/browser/omni.ja` | Gecko |
| Safari ou liaison WebKit | WebKit |

Extensions : on cherche une **structure**. Un profil Chromium se reconnaît à
`Local State` + `Default/Preferences` dans `~/Library/Application Support/`.
Un fork inconnu est traité comme n'importe quel Chromium.

**Base de connaissances** — le seul point nécessitant une liste, car indéductible :

```
Blocage natif intégré
  Brave (Shields) · Vivaldi · Opera · Orion · DuckDuckGo · Helium
```

Navigateur inconnu → défaut **Filtrer**.

### 10.4 Deux navigateurs verrouillés en exclusion

```
🧅 Tor Browser        ⛔ Exclu — non modifiable
🛡️ Mullvad Browser    ⛔ Exclu — non modifiable
```

MITM-er Tor Browser détruit exactement ce pour quoi il existe, et sa signature TLS
uniforme — qui protège de l'identification — disparaît. **L'utilisateur ne doit pas
pouvoir se tirer dessus par inadvertance.**

### 10.5 Recommandations motivées

Jamais un verdict sec. Le paysage justifie l'app :

| Navigateur | Situation | Verdict |
|---|---|---|
| **Safari** | uBlock Origin **n'existe plus** | **Filtrer** ✅ |
| **Chrome / Edge** | Manifest V3, uBO **Lite** bridé | **Filtrer** ✅ |
| Firefox | uBO complet, cosmétique supérieur | Exclure ⚖️ |
| Helium | uBO intégré | Exclure ⚖️ |
| Brave | Shields intégré | Exclure ⚖️ |

Détection des **extensions VPN/proxy** : elles utilisent `chrome.proxy`, qui écrase
les réglages système pour ce navigateur. **Tamis y est totalement contourné** — pas
seulement la couche 1. À signaler explicitement.

### 10.6 Périmètre du scan

Manifestes d'extensions et deux clés de préférences. **Jamais** l'historique, les
cookies, les mots de passe ni les favoris. À écrire dans l'UI et le README.

Safari est protégé par TCC : plutôt qu'exiger Full Disk Access, on détecte ses
bloqueurs par la présence de leurs apps hôtes dans `/Applications`.

---

## 11. Interface

**Direction :** natif sobre. Aucune couleur de marque — `Color.accentColor` suit
l'accent système. Sémantique portée par des SF Symbols, jamais par du texte coloré.
SF Pro partout, `.monospaced()` uniquement sur les domaines et les règles.
`Form` + `.formStyle(.grouped)` pour les réglages. macOS 26 → Liquid Glass gratuit
sur sidebar, toolbar et popover.

**Fenêtre :** 900 × 600 minimum, sidebar 200 pt. Fermer la fenêtre ne quitte pas l'app.

### 11.1 Écrans

| Écran | Contenu |
|---|---|
| **Tableau de bord** | Interrupteur, tuiles (bloquées, économisées, flux non filtrés), sparkline 24 h, sélecteur DNS, top 5 domaines |
| **Historique** | `Table` + inspecteur, recherche, segmented Tous/Bloqués/Autorisés. L'inspecteur montre la requête, la règle exacte et sa liste d'origine |
| **Filtres** | 2 segments : Listes de blocage / Exclusions HTTPS |
| **DNS** | Upstream, profil télémétrie, règles par domaine, diagnostic |
| **Applications** | 2 segments : Navigateurs / Toutes les apps |
| **Scripts** | 3 colonnes : arborescence / liste / éditeur |
| **Alertes** | Conditions et événements (§13.1) |
| **Réglages** | Démarrage, état de la CA, licences, diagnostic, désinstallation |

### 11.2 MenuBarExtra

```
┌────────────────────────────────┐
│  Protection            ●━━━○   │
│  ────────────────────────────  │
│  1 284 bloquées aujourd'hui    │
│                                │
│  DNS      Cloudflare       ⌄   │
│  ────────────────────────────  │
│  ⏸  Pause 5 minutes            │
│  ⊘  Ne pas filtrer ce site     │
│  ────────────────────────────  │
│  Ouvrir Tamis…            ⌘,   │
└────────────────────────────────┘
```

Largeur 320 pt. Icône lisible d'un coup d'œil, **l'état se lit à la forme, jamais à
la couleur** — un point coloré de 16 pt est illisible et contraire aux conventions macOS.

### 11.3 État vide

Le tableau de bord sans liste active doit avoir l'air **délibéré**, pas cassé :

> **Tamis est actif, mais aucune liste de filtres n'est activée.**
> Tamis protège déjà vos connexions sensibles et n'envoie aucune donnée.
> [ Choisir des listes de filtres ]

### 11.4 Accessibilité

Pas d'audit dédié. SwiftUI natif fournit les libellés VoiceOver de base.

### 11.5 Localisation

FR + EN via String Catalog **dès le premier jour** — gratuit maintenant, pénible
à rétrofitter.

---

## 12. Onboarding

Cible : **moins de 90 secondes, un seul mot de passe**.
Principe : **tout expliquer avant de le faire, ne rien laisser si l'utilisateur renonce.**

| # | Écran | Contenu |
|---|---|---|
| 0 | Bienvenue | Le contrat, pas du marketing |
| 1 | Vérification préalable | Emplacement de l'app, autre proxy MITM, port 53, CA résiduelle, VPN actif. **Avant de demander quoi que ce soit** |
| 2 | Ce que Tamis va faire | Les 4 modifications **et** les 4 limites |
| 3 | Mot de passe | « C'est la seule fois. » Annulation → rien n'a changé |
| 4 | Installation | Progression pas à pas, **transactionnel** |
| 5 | Vos navigateurs | Analyse §10, pré-cochée sur la recommandation. Injection NSS Firefox ici |
| 6 | DNS | Upstream + profil télémétrie |
| 7 | **Vérification** | 5 tests réels contre le banc local |
| 8 | Terminé | Pointe vers la barre de menus, **et vers le catalogue de listes** |

### 12.1 Écran 2 — le plus important

La seconde moitié compte autant que la première :

```
🔐  Installer une autorité de certification locale
🌐  Configurer le proxy système
📡  Configurer le DNS
⚙️  Installer un service système

─────────────────────────────────────────

Ce que Tamis ne fait pas :
·  Aucune donnée ne quitte ce Mac. Jamais.
·  Les sites bancaires ne sont jamais déchiffrés.
·  La clé de l'autorité ne quitte pas votre Mac.
·  Tout est annulable en un clic.
```

Un logiciel qui énonce ses limites est plus crédible qu'un logiciel qui n'énonce
que ses pouvoirs.

### 12.2 Le lot élevé — un seul mot de passe

```
1. créer l'utilisateur _tamis                      (dscl)
2. copier le daemon → /Library/Application Support/Tamis/tamisd
3. root:wheel 0755
4. écrire les plists → /Library/LaunchDaemons/
5. launchctl bootstrap system
6. security add-trusted-cert -d                    (CA)
7. networksetup -setautoproxyurl                   (par service)
8. networksetup -setdnsservers                     (127.0.0.1 et ::1)
```

**Le binaire du daemon ne reste pas dans le bundle :** launchd refuse de lancer un
démon root depuis un emplacement modifiable par l'utilisateur. Bénéfice décisif — le
daemon devient **indépendant du bundle**, condition pour que le garde-fou fonctionne.

### 12.3 Transactionnel

Journal des opérations effectuées ; en cas d'échec, annulation dans l'ordre inverse,
retour à l'état initial, message explicite. **Jamais d'état intermédiaire.**

App tuée en cours de route → la vérification d'intégrité du lancement suivant détecte
l'installation partielle et propose de reprendre ou de nettoyer.

### 12.4 Écran 7 — prouver plutôt qu'annoncer

```
✓  Blocage réseau          règle de test interne
✓  Filtrage cosmétique     élément masqué correctement
✓  Résolution DNS          domaine de suivi bloqué
✓  Exclusion bancaire      connexion non déchiffrée
✓  Certificat amont        certificat invalide rejeté
```

Le premier test utilise une **règle de test interne**, non exposée à l'utilisateur :
prouver que la chaîne fonctionne sans imposer le moindre filtre (§8.1).

Si quelque chose ne va pas, l'utilisateur l'apprend **ici**, pas dans trois jours
devant un site cassé.

---

## 13. Résilience

### 13.1 Centre d'alertes

**Distinction structurante :**

| | Comportement |
|---|---|
| **Condition** — état en cours | Disparaît **seule** quand résolu. **Non rejetable** |
| **Événement** — fait ponctuel | Rejetable, s'efface après lecture |

Laisser rejeter « le VPN a repris le DNS » alors que c'est toujours le cas, c'est
fabriquer un utilisateur qui se croit protégé.

```
CONDITIONS   VPN/outil tiers a repris le DNS ou le proxy
             Portail captif détecté → en pause
             Proxy injoignable → fail-open actif
             CA absente, non approuvée, ou expirant sous 90 j
             Autre proxy MITM détecté
             Navigateur en DoH forcé
             DoH amont injoignable → repli en clair
             Disque plein → journalisation suspendue
             Horloge du Mac incorrecte

ÉVÉNEMENTS   Mise à jour de liste échouée
             Mise à jour REJETÉE par le garde-fou
             Échecs TLS répétés sur une app → proposer l'exclusion
             Nouveau navigateur installé
             Mise à jour de Tamis disponible
```

**Notifications système** réservées à ce qui exige une action immédiate : protection
tombée, CA cassée, VPN qui a repris la main. Pas pour un échec de mise à jour de liste.

### 13.2 Fail-open partout

| Composant | Comportement en échec |
|---|---|
| Proxy | Helper PAC sert `return "DIRECT"` |
| DNS | Repli sur les résolveurs DHCP en clair |
| CA expirée | Protection mise en pause |
| Journalisation | Best-effort, **jamais bloquante** |

> **L'écriture de l'historique ne doit jamais bloquer le chemin de données.**
> Le tampon d'événements déborde et jette, il n'applique jamais de contre-pression
> sur le proxy. Règle générale, pas une rustine pour le disque plein.

### 13.3 Vérification d'intégrité au lancement

| Contrôle | Sonde |
|---|---|
| CA présente et approuvée | `SecTrustSettingsCopyTrustSettings` |
| Clé privée accessible | `SecItemCopyMatching` |
| CA non expirée, T-90 | lecture du `notAfter` |
| Daemon chargé | ping XPC |
| Résolveur en écoute | requête DNS de test |
| PAC sur **tous** les services | `networksetup -getautoproxyurl` par service |
| DNS sur `127.0.0.1` et `::1` | `scutil --dns` |
| CA dans les profils Firefox | lecture de `cert9.db` |

**Le daemon tourne déjà en root : il répare tout sans le moindre mot de passe.**
Seule sa disparition nécessite l'utilisateur.

**Nuance :** si l'utilisateur a **volontairement** retiré la CA, la réinstaller en
silence serait hostile. Distinguer la dérive accidentelle — réparée — de l'action
délibérée — signalée et respectée.

Contrainte : **sous 100 ms**, sondes avec timeout. Au lancement, après réveil et
après changement de réseau.

Absorbe sans code spécifique : Assistant de migration, mise à jour majeure de macOS,
désinstallation partielle, CA supprimée à la main, nouveau service réseau manqué.

### 13.4 Veille et changements de réseau

**Le piège le plus vicieux :** un service réseau qui **apparaît** après l'installation
(dock Ethernet) est créé **sans PAC ni DNS**. Tout le trafic contourne Tamis en silence.

| Source | Action |
|---|---|
| `NSWorkspace.didWakeNotification` | Revérifier PAC et DNS, purger le cache DNS, rouvrir les connexions DoH, refermer les connexions proxy suspendues |
| `NWPathMonitor` | Relire les résolveurs DHCP, revérifier le portail captif, vider le cache DNS |
| `SCDynamicStore` sur les services | Nouveau service → PAC et DNS immédiatement |

**Anti-rebond de ~2 s obligatoire.** Un changement de réseau déclenche une rafale ;
sans regroupement, on reconfigure cinq fois et on crée l'instabilité qu'on corrige.

### 13.5 Coexistence

**VPN système.** Le loopback n'entre pas dans le tunnel : Tamis filtre, puis sa
connexion sortante emprunte le VPN. **Ordre idéal.** Mais presque tous les VPN
imposent leur résolveur et écrasent `127.0.0.1`.

**Ne pas se battre.** Réimposer son DNS contre un VPN provoque exactement la fuite
DNS que l'utilisateur cherche à éviter. On observe `State:/Network/Global/DNS` via
`SCDynamicStore` — en réactif — et on affiche une condition.

**VPN navigateur.** Ce sont des proxies internes utilisant `chrome.proxy`, qui écrase
les réglages système pour ce navigateur. **Tamis y est totalement contourné.**

**Autre proxy MITM.** Détecté à l'onboarding et à chaque lancement : proxy système
déjà configuré, CA tierce dans le trousseau (Charles, Proxyman, mitmproxy, Fiddler,
Burp, AdGuard), apps dans `/Applications`, port 53 occupé.
**Aucune correction automatique** — on affiche et on laisse choisir.

> **Détecter sur des CN connus de proxies MITM, jamais sur « racine ajoutée par
> l'utilisateur ».** Une *Caddy Local Authority*, une CA `mkcert` ou une racine
> d'entreprise ressemblent structurellement à un proxy concurrent — ce sont des outils
> légitimes. Les confondre déclencherait une alerte à chaque lancement sur toute
> machine de développement.

**Portail captif.** Détecté → pause automatique, tentatives de mise à jour suspendues.

**Docker Desktop.** Les conteneurs tournent dans une VM Linux et ne lisent pas les
réglages proxy de macOS : leur trafic sort par le NAT de la VM, sans passer par Tamis.

**Sauf** si l'option Docker Desktop → Resources → Proxies → *Use system proxy settings*
est activée : Docker injecte alors `HTTP_PROXY=http://127.0.0.1:<port>` dans les
conteneurs. Or depuis un conteneur, `127.0.0.1` désigne **le conteneur lui-même**.
**Tout le réseau des conteneurs casse**, avec des erreurs incompréhensibles.

À détecter à l'onboarding et dans la vérification d'intégrité, avec un avertissement
explicite. Docker figure déjà dans les exclusions de pinning pré-remplies (§10.2).

### 13.6 Horloge fausse

Il n'existe **aucune source de temps fiable** dans ce cas : interroger un serveur en
HTTPS suppose une connexion TLS qui échoue justement parce que l'horloge est fausse.

**On infère depuis le motif d'échec.** Plusieurs domaines **sans rapport entre eux**
échouant avec un motif de date dans une courte fenêtre → c'est l'horloge, pas une
attaque. Une vraie attaque ne se manifeste pas simultanément sur douze domaines
indépendants.

### 13.7 Désinstallation

| | Effet |
|---|---|
| **Réinitialiser** | Défait les modifications système, conserve scripts, listes et réglages |
| **Désinstaller** | Tout, sans laisser de trace |

```
Système     CA du trousseau + trust settings
            CA des magasins NSS de chaque profil Firefox
            PAC désactivé sur tous les services
            DNS restauré en DHCP sur tous les services
            LaunchDaemons bootés out + plists supprimés
            /Library/Application Support/Tamis
            utilisateur _tamis
            cache DNS vidé

Utilisateur clé privée de la CA (Keychain)
            ~/Library/Application Support/Tamis
            ~/Library/Preferences/io.github.black0s.tamis.plist
            ~/Library/Caches/io.github.black0s.tamis
            LaunchAgent de démarrage auto
```

**Export proposé** avant effacement des scripts et exclusions personnalisées.

**Garde-fou — déclencheur = absence du bundle, jamais l'inactivité.** Un utilisateur
peut ne pas ouvrir l'app pendant deux semaines.

- Surveillance `kqueue` du chemin du bundle → suppression détectée → restauration
  complète et auto-démontage
- Vérification au démarrage du daemon → bundle absent au boot → même traitement

**Troisième filet :** un `uninstall.sh` autonome publié dans le dépôt. Si l'app est
cassée au point de ne plus se désinstaller, la commande existe et personne ne reste
avec une CA orpheline.

### 13.8 Multi-utilisateur

Le daemon appartient à l'utilisateur ayant fait l'onboarding. Une autre session voit
« Tamis est configuré par un autre utilisateur de ce Mac », en lecture seule, sans
tenter de reprendre la main.

---

## 14. Données

### 14.1 Schéma

```
domains(id, name)          ← googleads.g.doubleclick.net stocké UNE fois
apps(id, bundle_id, name)

events(ts, domain_id, app_id, action, rule_id, bytes)   ~40 octets/ligne
blocked_details(event_id, url, referer)                 bloquées uniquement
```

**Décision :** ne pas stocker les URL complètes des requêtes **autorisées**. Une query
string contient des jetons de session et des identifiants. L'URL complète n'a de valeur
diagnostique que sur ce qu'on a bloqué.

### 14.2 Écriture et purge

Jamais un `INSERT` par requête. Tampon circulaire en mémoire, vidé toutes les secondes
ou tous les mille événements, dans un acteur dédié, en mode WAL. Même tampon que l'UI.

Purge : **7 jours par défaut** (1 / 7 / 30), **et** un plafond dur en taille — le
premier atteint déclenche. Au lancement et tous les N inserts, jamais par timer.

Sous 1 Go disponible ou sur échec d'écriture : arrêt de la journalisation, alerte
condition, **le filtrage continue**.

### 14.3 Chiffrement

Pas de SQLCipher en v1. FileVault est actif par défaut, le fichier est en 0600, et le
vrai levier est la rétention courte et le bouton « Effacer l'historique ». Ajouter une
dépendance de chiffrement pour une base déjà chiffrée par le disque est du théâtre.
**À documenter honnêtement plutôt qu'à masquer.**

### 14.4 Hors base

Réglages en `UserDefaults`. Règles par app et métadonnées de scripts en **JSON lisible** —
cohérent avec les scripts stockés en vrais fichiers, et versionnable avec git.

**Migration et sauvegarde :** tout tient dans `~/Library/Application Support/Tamis/`.
Le copier suffit. Une entrée « Révéler dans le Finder » dans les Réglages.

---

## 15. Performance

> **L'optimisation fait partie de la pensée de l'app, pas d'une passe ultérieure.**

| Engagement | Détail |
|---|---|
| **Ne pas déchiffrer l'inutile** | Seules les réponses `text/html` sont bufferisées. Images, vidéos, JS, fonts, JSON traversent en flux. **> 90 % des octets** |
| **Ne pas faire entrer l'inutile** | Le PAC renvoie `DIRECT` sur les exclusions |
| **Parser une fois** | Listes compilées en structure binaire, chargées par `mmap` |
| **Zéro polling** | `SCDynamicStore` en callback, `FSEvents` pour les fichiers, aucun timer |
| **Cacher le stable** | Certificats LRU, attribution par port et PID, DNS avec TTL |
| **UI non coûteuse** | Tampon circulaire, rafraîchissement à quelques hertz |
| **Une clé feuille partagée** | La génération de clé est l'opération coûteuse |

**Cibles, vérifiées par des benchmarks en CI :**

```
latence ajoutée   p95 < 5 ms
mémoire           < 300 Mo, listes complètes chargées
CPU au repos      0 %
```

Sans mesure automatique à chaque push, le principe se dégrade en trois mois.

### 15.1 Panneau diagnostic

Latence p50/p95/p99, taux des caches, mémoire par composant, connexions h2, groupe
TLS négocié. Bouton **« Copier le rapport »** produisant un bloc **anonymisé** —
compteurs uniquement, aucun domaine, aucune app nommée.

Complément naturel du zéro télémétrie : Tamis n'envoie jamais rien, mais une issue
GitHub peut contenir des données réelles sans exposer la navigation.

---

## 16. Nommage — figé

```
Nom                  Tamis
Bundle ID app        io.github.black0s.tamis
Label daemon         io.github.black0s.tamis.daemon
Label résolveur      io.github.black0s.tamis.dnsd
Service Mach         io.github.black0s.tamis.daemon.xpc
Service Keychain     io.github.black0s.tamis
Domaine de prefs     io.github.black0s.tamis
Utilisateur système  _tamis
Plists LaunchDaemon  /Library/LaunchDaemons/io.github.black0s.tamis.*.plist
Support système      /Library/Application Support/Tamis/
Support utilisateur  ~/Library/Application Support/Tamis/
CN de la CA          Tamis Local CA (<nom-du-Mac>)
Dépôt                github.com/Black0S/tamis
```

> **Le service Mach est le plus critique.** Inscrit dans le plist du daemon et dans
> l'exigence de signature — le changer après publication casse toutes les installations.

---

## 17. Projet

### 17.1 Licence — GPLv3

Trois raisons, dont deux sont des contraintes techniques :

1. **EasyList** est en double licence GPLv3 / CC BY-SA 3.0
2. **`swift-nio`, `swift-nio-ssl`, `swift-certificates`, `swift-crypto`** sont en
   Apache 2.0 — compatible **GPLv3 mais pas GPLv2**. Ça tranche la version
3. **La confiance.** Tamis installe une **autorité de certification racine**. Le
   copyleft garantit que tout fork reste auditable : personne ne peut reprendre le
   code, ajouter une CA qui exfiltre, et distribuer un binaire fermé

GPLv3 est incompatible avec le Mac App Store — sans coût réel, une app installant une
CA et modifiant les réglages réseau n'y serait jamais acceptée.

### 17.2 Dépendances

| Paquet | Licence | Usage |
|---|---|---|
| `swift-nio`, `swift-nio-ssl`, `swift-nio-http2` | Apache 2.0 | Proxy, TLS, h2 |
| `swift-certificates`, `swift-crypto` | Apache 2.0 | CA et certificats feuille |
| `GRDB` | MIT | Historique |
| `Sparkle` | MIT | Mises à jour |
| Scriptlets uBO | GPLv3 | Bibliothèque de scriptlets |
| Métadonnées de catalogue | uBO GPLv3 / AdGuard | Catalogue de listes |

**Frameworks système :** SwiftUI, Network, NetworkExtension (non), Security,
SystemConfiguration, JavaScriptCore, `libproc`.

### 17.3 Signature

**Certificat auto-signé**, 15-20 ans, **identique d'une version à l'autre** — sinon
l'ACL Keychain et l'exigence XPC sautent à chaque mise à jour. Contrainte de release
à ne jamais enfreindre. Sauvegardé hors ligne.

### 17.4 CI et distribution

```
Local (Xcode, swift build/test)  →  push
GitHub Actions                   →  tests + benchmarks à chaque push
                                 →  sur tag : build, .dmg, SHA-256, release
```

Un runner avec le SDK macOS 26 est requis — à vérifier ; sinon releases locales
en attendant.

**Distribution :** `.dmg` non notarisé **et** sources. Sur macOS 15+, le clic-droit →
Ouvrir ne fonctionne plus : la procédure est **Réglages Système → Confidentialité et
sécurité → Ouvrir quand même**, à documenter avec capture d'écran.

> **Ne jamais écrire `xattr -d com.apple.quarantine` dans la documentation.**
> Apprendre à contourner Gatekeeper par une commande copiée, pour une app qui installe
> une CA racine, est le réflexe exact qu'exploitent les malwares macOS.

**Mises à jour :** Sparkle avec appcast généré depuis les releases, signature **EdDSA**
indépendante d'Apple. Sparkle retire la quarantaine après validation → l'utilisateur
n'approuve qu'à la première installation.

### 17.5 Tests

**Automatisable en CI, plus large que prévu :** un proxy se teste sans toucher au
système — `curl -x http://127.0.0.1:8080`. Moteur, proxy, classification, injection
et cosmétique passent tous en CI.

**Banc de test :** serveur d'origine local avec sa propre CA, corpus de pages —
pubs correspondant à des règles connues, cibles cosmétiques, CSP strict, gzip et
brotli, `<head>` coupé entre deux chunks, variantes de `Sec-Fetch-Dest` — plus des
certificats délibérément mauvais.

**Checklist manuelle par release :**

```
□ Onboarding sur un compte vierge
□ Désinstallation → script vérifiant qu'il ne reste rien
□ Veille/réveil · changement de Wi-Fi · dock Ethernet
□ VPN activé puis désactivé
□ Portail captif
□ Signal et Dropbox fonctionnent toujours
□ Site bancaire : l'émetteur du certificat est le vrai, PAS Tamis
```

Le dernier valide d'un coup d'œil que les exclusions font leur travail.

### 17.6 Documentation du dépôt

- **README** — ce que fait Tamis, instructions de build soignées (c'est la porte
  d'entrée), procédure Gatekeeper, périmètre du scan des navigateurs
- **THREAT_MODEL.md** — ce qui est protégé, ce qui ne l'est pas, ce qu'un attaquant
  gagnerait à compromettre Tamis, le choix d'absence d'authentification sur le proxy
- **Zéro télémétrie**, affirmé et tenu

---

## 18. Limites connues — à documenter

| Limite | Cause |
|---|---|
| Cosmétique moins fin qu'uBlock Origin sur Firefox | Injection depuis l'extérieur : SPA, iframes dynamiques |
| Règles DNS non séparables par app | Tout le DNS macOS transite par `mDNSResponder` |
| Les blocklists DNS s'appliquent aussi aux conteneurs Docker | Docker Desktop résout via l'hôte, et l'origine est effacée par `mDNSResponder` |
| Télémétrie Apple non filtrable en couche 2 | `apple.com` et `icloud.com` sont exclus par nécessité |
| Sites bancaires non filtrés | Exclusion volontaire |
| Apps à pinning à exclure | Elles cassent sous MITM |
| `$popup`, `$webrtc`, `$ping` | Structurellement hors de portée d'un proxy |
| Navigateur en DoH forcé | Couche 1 contournée (couche 2 intacte) |
| Extension VPN/proxy dans un navigateur | Couches 1 **et** 2 contournées |
| Chaînage vers un proxy d'entreprise | Hors périmètre |
| Trafic vers IP en dur, UDP | Nécessiterait NetworkExtension — hors périmètre |

---

## 19. Ordre de construction

Une seule livraison, mais un ordre d'écriture. Chaque étape doit être **vérifiable
avant de passer à la suivante** — sinon, quand quelque chose casse à l'étape 6, on ne
sait plus si le bug vient du matcher, du proxy ou de l'injection.

```
1. Moteur de filtres        parser + matcher, testable en CI, sans système
2. Daemon + résolveur DNS   le premier composant réellement fonctionnel
3. Proxy + CA + MITM        Sec-Fetch-Dest et classification en premier
4. Cosmétique + injection   CSP, procéduraux, scriptlets
5. Scripts et styles        réutilise le canal d'injection
6. UI complète
7. Onboarding, désinstallation, détection de conflits
8. Navigateurs, alertes, diagnostics
```
