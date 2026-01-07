## Audit de sécurité du projet Vuln_JS – Rapport de correction

### 1) Objectif du projet

L’objectif de ce travail est de :
- **auditer** l’application web (frontend React + backend Express/MySQL),
- **identifier** les vulnérabilités de sécurité,
- **implémenter** des correctifs dans le code,
- **documenter** la démarche et les remédiations dans un rapport exploitable.

L’application fournit un blog avec gestion d’utilisateurs, d’articles et de commentaires.

---

### 2) Méthodologie utilisée

- **Cartographie de l’application**
  - Analyse de la stack : Node/Express (backend), React/TypeScript (frontend), MySQL (DB), JWT pour l’authentification.
  - Revue des routes backend (`server.js`, `routes/auth.js`, `routes/users.js`, `routes/articles.js`, `routes/comments.js`) et des pages frontend (`Home`, `Article`, `Login`, `Register`, `AdminArticles`, `AdminUsers`).
- **Revue de code ciblée (scan statique manuel)**
  - Recherche de patterns sensibles : `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `query(`, `execute(`, `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `jwt`, etc.
  - Focalisation sur :
    - injection SQL,
    - XSS (stockée / réfléchie),
    - défauts d’authentification / autorisation (IDOR, élévation de privilèges),
    - gestion des mots de passe et des sessions,
    - configuration CORS,
    - headers de sécurité HTTP.
- **Élaboration de scénarios de tests dynamiques (sans exécution automatisée)**
  - Préparation de requêtes `curl` et scénarios navigateur pour chaque vulnérabilité trouvée.
  - Définition de payloads d’attaque typiques (SQLi, XSS, abus d’API) et de l’impact attendu.
- **Implémentation des correctifs**
  - Utilisation de bonnes pratiques adaptées à la stack :
    - requêtes SQL préparées,
    - hachage de mot de passe `bcrypt`,
    - sanitisation HTML via `sanitize-html`,
    - contrôles d’authentification/autorisation côté backend,
    - ajout d’headers de sécurité via `helmet`,
    - gestion d’erreurs centralisée.

---

### 3) Tableau de synthèse des vulnérabilités

Chaque vulnérabilité est listée avec : ID, Titre, Sévérité, Composant, Description, Steps to reproduce, Evidence, Fix summary, Fichiers modifiés.

#### **VULN-001 – Mots de passe stockés en clair**
- **Sévérité** : Critique  
- **Composant** : `auth.js`, `users.js`, `db/init.sql`
- **Description** : les mots de passe étaient stockés et comparés en clair dans la base, sans hachage.
- **Steps to reproduce** :
  - Créer un utilisateur, puis inspecter la table `users.password` dans MySQL.
  - Observer que le mot de passe correspond exactement à la valeur saisie.
- **Evidence** :
  - Insertion en clair dans `auth.js` (avant correction) et `init.sql`.
- **Fix summary** :
  - Ajout de `bcrypt` et hachage systématique des mots de passe à la création et à la mise à jour.
  - Migration douce des anciens comptes : si un mot de passe en clair est détecté lors du login, il est re-haché.
- **Fichiers modifiés** :
  - `vulnerable/backend/routes/auth.js`
  - `vulnerable/backend/routes/users.js`
  - `vulnerable/backend/package.json`

#### **VULN-002 – Injection SQL sur la recherche d’articles**
- **Sévérité** : Critique  
- **Composant** : `routes/articles.js`
- **Description** : la requête `SELECT * FROM articles WHERE title LIKE '%${title}%'` concaténait directement l’entrée utilisateur dans la chaîne SQL.
- **Steps to reproduce** :
  - Requête : `POST /api/articles/search` avec `{"title":"%' OR 1=1 -- "}`.
  - Observer un résultat anormalement large ou des erreurs SQL.
- **Evidence** :
  - Usage de `req.db.query(sql)` avec interpolation directe du champ `title`.
- **Fix summary** :
  - Remplacement par une requête préparée avec paramètre : `WHERE a.title LIKE ?`.
  - Ajout d’une jointure avec `users` pour exposer `author_username` sans appel supplémentaire à `/users`.
- **Fichiers modifiés** :
  - `vulnerable/backend/routes/articles.js`

#### **VULN-003 – Injection SQL sur la création de commentaires**
- **Sévérité** : Critique  
- **Composant** : `routes/comments.js`
- **Description** : la requête `INSERT INTO comments (user_id, article_id, content) VALUES (${user_id}, ${id}, '${content}')` utilisait une concaténation directe de `user_id`, `id` et `content`.
- **Steps to reproduce** :
  - Requête : `POST /api/articles/1/comments` avec un `content` ou un `id` malveillant (ex. `1; DROP TABLE users; --`).
- **Evidence** :
  - Usage de backticks et interpolation dans la requête d’insertion.
- **Fix summary** :
  - Passage à une requête préparée : `INSERT INTO comments (content, user_id, article_id) VALUES (?, ?, ?)`.
  - Utilisation exclusive de l’`id` utilisateur issu du JWT (`req.user.id`) au lieu de `user_id` venant du client.
  - Sanitisation HTML du contenu des commentaires (`sanitizeRichText`).
- **Fichiers modifiés** :
  - `vulnerable/backend/routes/comments.js`
  - `vulnerable/backend/utils/sanitize.js`

#### **VULN-004 – Absence d’authentification / autorisation sur les routes utilisateurs (IDOR / élévation de privilèges)**
- **Sévérité** : Critique  
- **Composant** : `routes/users.js`
- **Description** :
  - Les routes `/api/users`, `/api/users/:id`, `DELETE /api/users/:id`, `PUT /api/users/:id` étaient accessibles sans contrôle, permettant :
    - la lecture de tous les utilisateurs,
    - la suppression arbitraire,
    - la modification des rôles (ex. se passer en `admin`).
- **Steps to reproduce** :
  - `GET /api/users` sans header `Authorization`.
  - `PUT /api/users/2` avec un body définissant `role: "admin"`.
- **Evidence** :
  - Absence de `authenticate` / `authorizeAdmin` sur ces routes.
- **Fix summary** :
  - Ajout de `authenticate` + `authorizeAdmin` pour lister et supprimer des utilisateurs.
  - Autorisation de la consultation / modification de son propre profil uniquement, ou par un admin.
  - Hachage des nouveaux mots de passe via `bcrypt` lors des mises à jour.
  - Exclusion du champ `password` dans les réponses JSON.
- **Fichiers modifiés** :
  - `vulnerable/backend/routes/users.js`

#### **VULN-005 – Manque de contrôle d’authentification sur la création / modification d’articles**
- **Sévérité** : Élevée à Critique  
- **Composant** : `routes/articles.js`
- **Description** :
  - Les routes `POST /api/articles` et `PUT /api/articles/:id` n’imposaient aucune authentification côté backend.
  - Le client pouvait choisir librement `author_id`.
- **Steps to reproduce** :
  - `POST /api/articles` sans token, avec n’importe quel `author_id`.
- **Evidence** :
  - Absence d’utilisation de `authenticate` sur ces routes.
- **Fix summary** :
  - Ajout de `authenticate` sur `POST` et `PUT`.
  - Forçage de l’auteur à partir du JWT (`req.user.id`) plutôt que du body.
  - Vérification que seul l’auteur ou un admin peut modifier un article.
- **Fichiers modifiés** :
  - `vulnerable/backend/routes/articles.js`

#### **VULN-006 – Suppression de commentaires sans contrôle d’accès**
- **Sévérité** : Moyenne / Élevée  
- **Composant** : `routes/comments.js`
- **Description** : `DELETE /api/comments/:id` était accessible sans authentification, permettant à n’importe qui de supprimer les commentaires.
- **Steps to reproduce** :
  - `DELETE /api/comments/1` sans header `Authorization`.
- **Evidence** :
  - Pas de middleware `authenticate` ou `authorizeAdmin` sur la route.
- **Fix summary** :
  - Ajout de `authenticate` + `authorizeAdmin` pour limiter l’action aux administrateurs.
- **Fichiers modifiés** :
  - `vulnerable/backend/routes/comments.js`

#### **VULN-007 – Risque de XSS stockée sur le contenu des articles et des commentaires**
- **Sévérité** : Critique  
- **Composant** : `routes/articles.js`, `routes/comments.js`, frontend (`Home.tsx`, `Article.tsx`, `AdminArticles.tsx`)
- **Description** :
  - Le contenu riche (HTML) des articles et commentaires était stocké tel quel et rendu via `dangerouslySetInnerHTML` sans nettoyage.
  - En présence d’un script injecté, n’importe quel visiteur exécutait le code malveillant.
- **Steps to reproduce (avant correction)** :
  - Créer un article ou commentaire avec `<script>alert('XSS')</script>`.
  - Ouvrir la page `/` ou `/article/:id` et observer l’exécution du script.
- **Evidence** :
  - `dangerouslySetInnerHTML` sur `article.content` et `comment.content`.
- **Fix summary** :
  - Ajout d’un utilitaire `sanitizeRichText` basé sur `sanitize-html`, utilisé lors de la création / mise à jour d’articles et de commentaires.
  - Conservation d’un sous-ensemble sûr de balises HTML (mise en forme, listes, liens).
- **Fichiers modifiés** :
  - `vulnerable/backend/utils/sanitize.js`
  - `vulnerable/backend/routes/articles.js`
  - `vulnerable/backend/routes/comments.js`

#### **VULN-008 – CORS permissif et headers de sécurité manquants**
- **Sévérité** : Moyenne  
- **Composant** : `server.js`
- **Description** :
  - `app.use(cors())` sans configuration explicite.
  - Aucun header de sécurité (`CSP`, `X-Content-Type-Options`, `X-Frame-Options`, etc.) appliqué.
- **Steps to reproduce** :
  - `curl -I http://localhost:4001/api/articles` et vérifier l’absence de headers de sécurité.
- **Evidence** :
  - Fichier `server.js` avant correction.
- **Fix summary** :
  - Ajout de `helmet` pour définir des headers de sécurité par défaut.
  - Configuration explicite de CORS (origines, méthodes et headers autorisés, configurables via variables d’environnement).
- **Fichiers modifiés** :
  - `vulnerable/backend/server.js`
  - `vulnerable/backend/package.json`

#### **VULN-009 – Absence de gestion d’erreurs centralisée**
- **Sévérité** : Basse / Moyenne  
- **Composant** : `server.js`
- **Description** :
  - Les erreurs non gérées pouvaient potentiellement exposer des traces ou des détails internes.
- **Fix summary** :
  - Ajout d’un middleware d’erreur global qui loggue côté serveur et renvoie une réponse générique : `Erreur interne du serveur`.
- **Fichiers modifiés** :
  - `vulnerable/backend/server.js`

---

### 4) Résumé des patchs (bullet list)

- **Mots de passe**
  - Intégration de `bcrypt` pour hasher les mots de passe à l’inscription et lors des mises à jour.
  - Migration transparente des anciens mots de passe en clair lors du prochain login.
- **Injection SQL**
  - Remplacement des concaténations SQL par des requêtes préparées (`execute`) pour la recherche d’articles et la création de commentaires.
- **XSS**
  - Création d’un utilitaire `sanitizeRichText` basé sur `sanitize-html`.
  - Nettoyage systématique du HTML des articles et commentaires avant stockage en base.
- **Contrôles d’accès**
  - Ajout massif d’`authenticate` / `authorizeAdmin` sur les routes sensibles (`/users`, suppression de commentaires, création/modification d’articles).
  - Restrictions de lecture/écriture des profils utilisateurs (un utilisateur ne peut modifier que son propre compte, l’admin gère les rôles).
- **Headers de sécurité & CORS**
  - Ajout de `helmet` pour les en-têtes de sécurité (CSP simplifiée, X-Content-Type-Options, X-Frame-Options, etc.).
  - Configuration CORS avec options explicites, basées sur l’environnement.
- **Erreurs**
  - Middleware global d’erreurs pour éviter de renvoyer des détails internes au client.

---

### 5) Étapes de vérification après correctifs

- **Vérifier l’authentification et les mots de passe**
  - Créer un nouvel utilisateur, vérifier en base que `password` est un hash `bcrypt` (préfixe `$2b$`).
  - Tester le login avec un ancien compte (ex. `admin`), vérifier qu’un hash est généré à la première connexion réussie.
- **Tester les routes protégées**
  - Appeler `GET /api/users` sans token : obtenir `401` ou `403`.
  - Appeler `GET /api/users` avec un token d’admin : obtenir la liste sans le champ `password`.
  - Tenter de modifier ou supprimer un autre utilisateur avec un simple compte `user` : obtenir `403`.
- **Tester la création / modification d’articles**
  - Créer un article avec un utilisateur authentifié et vérifier que `author_id` correspond à l’ID du JWT.
  - Tenter de modifier un article d’un autre utilisateur sans être admin : obtenir `403`.
- **Tester les commentaires**
  - Créer un commentaire avec du HTML potentiellement dangereux (`<script>...`), vérifier côté navigateur que le script n’est pas exécuté.
  - Tenter de supprimer un commentaire sans être admin : obtenir `403`.
- **Tester les protections SQLi**
  - Rejouer les payloads SQLi précédemment décrits sur `/api/articles/search` et `/api/articles/:id/comments` :
    - vérifier qu’aucune erreur SQL n’apparaît,
    - vérifier que la base n’est pas altérée.
- **Vérifier les headers de sécurité**
  - `curl -I http://localhost:4001/api/articles` et confirmer la présence de headers `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, etc.

---

### 6) Checklist de sécurité / leçons apprises

- **Entrées utilisateur**
  - Toujours valider et nettoyer les données côté serveur (en plus des validations frontend).
  - Jamais concaténer directement les valeurs utilisateur dans des requêtes SQL ou du HTML.
- **Mots de passe & authentification**
  - Ne jamais stocker un mot de passe en clair.
  - Utiliser des fonctions de hachage robustes (`bcrypt`, `Argon2`).
  - Éviter de mettre des informations sensibles (mot de passe, token brut) dans les réponses API.
- **Autorisations**
  - Ne jamais se reposer uniquement sur le frontend pour la logique de rôles (admin/user).
  - Implémenter systématiquement les contrôles d’accès côté serveur, en se basant sur une identité forte (JWT, session).
- **XSS**
  - Éviter `dangerouslySetInnerHTML` autant que possible.
  - Si nécessaire (contenu riche), appliquer une sanitisation stricte du HTML côté serveur.
  - Compléter avec une politique CSP adaptée.
- **CORS & Headers de sécurité**
  - Configurer explicitement CORS (origines, méthodes, headers).
  - Utiliser des librairies comme `helmet` pour simplifier l’ajout d’headers de sécurité.
- **Gestion des erreurs**
  - Centraliser la gestion des erreurs.
  - Logguer côté serveur, mais exposer au client uniquement des messages génériques.

Ce rapport résume l’audit et les corrections de sécurité appliquées au projet. Il peut servir de base à des audits ultérieurs, ainsi qu’à la mise en place de contrôles automatisés (linting sécurité, SAST/DAST, revues de code régulières).

