const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const { generateToken } = require('../utils/jwt');

// Route pour s'inscrire
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const checkSql = 'SELECT * FROM users WHERE email = ? OR username = ?';
  const insertSql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
  try {
    const [existingUsers] = await req.db.execute(checkSql, [email, username]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email ou nom d\'utilisateur déjà utilisé' });
    }

    // SECURITY FIX: hachage des mots de passe avant stockage en base pour éviter le stockage en clair
    const hashedPassword = await bcrypt.hash(password, 10);

    const [results] = await req.db.execute(insertSql, [username, email, hashedPassword]);
    res.status(201).json({ message: 'Utilisateur créé avec succès', id: results.insertId });
  } catch (err) {
    console.error('Erreur lors de l\'inscription :', err);
    res.status(500).json({ error: 'Erreur lors de l\'inscription' });
  }
});

// Route pour se connecter
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ?';
  try {
    const [results] = await req.db.execute(sql, [email]);
    if (results.length === 0) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }
    const user = results[0];

    // SECURITY FIX: comparaison des mots de passe avec bcrypt (et migration douce des anciens mots de passe en clair)
    let passwordMatches = false;
    if (user.password && typeof user.password === 'string' && user.password.startsWith('$2')) {
      // Mot de passe déjà haché en bcrypt
      passwordMatches = await bcrypt.compare(password, user.password);
    } else {
      // Ancien compte stocké en clair : on compare en clair puis on migre vers un hash sécurisé
      passwordMatches = user.password === password;
      if (passwordMatches) {
        const newHash = await bcrypt.hash(password, 10);
        await req.db.execute('UPDATE users SET password = ? WHERE id = ?', [newHash, user.id]);
      }
    }

    if (!passwordMatches) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    const token = generateToken(user);
    res.json({ message: 'Connexion réussie', token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    console.error('Erreur lors de la connexion :', err);
    res.status(500).json({ error: 'Erreur lors de la connexion' });
  }
});

module.exports = router;
