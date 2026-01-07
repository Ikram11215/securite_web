const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const { authenticate, authorizeAdmin } = require('../middlewares/authMiddleware');

// Route pour lister les utilisateurs (admin uniquement)
router.get('/', authenticate, authorizeAdmin, async (req, res) => {
  // SECURITY FIX: restriction à l'admin et exclusion du mot de passe dans la réponse
  const sql = 'SELECT id, username, email, role, created_at FROM users';
  try {
    const [results] = await req.db.execute(sql);
    res.json(results);
  } catch (err) {
    console.error('Erreur lors de la récupération des utilisateurs :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des utilisateurs' });
  }
});

// Route pour récupérer un utilisateur spécifique (soi-même ou admin)
router.get('/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  // SECURITY FIX: contrôle d'accès – un utilisateur ne peut voir que son propre profil, l'admin peut tout voir
  if (req.user.role !== 'admin' && Number(req.user.id) !== Number(id)) {
    return res.status(403).json({ error: 'Accès interdit' });
  }

  const sql = 'SELECT id, username, email, role, created_at FROM users WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [id]);
    if (results.length === 0) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Erreur lors de la récupération de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération de l\'utilisateur' });
  }
});

// Route pour supprimer un utilisateur (admin uniquement)
router.delete('/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM users WHERE id = ?';
  try {
    await req.db.execute(sql, [id]);
    res.json({ message: 'Utilisateur supprimé avec succès' });
  } catch (err) {
    console.error('Erreur lors de la suppression de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la suppression de l\'utilisateur' });
  }
});

// Route pour modifier un utilisateur (admin uniquement pour les autres, utilisateur pour lui-même)
router.put('/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { username, email, password, role } = req.body;

  // SECURITY FIX: contrôle d'accès fin – seul l'admin peut changer les rôles, l'utilisateur ne peut modifier que son propre compte
  if (req.user.role !== 'admin' && Number(req.user.id) !== Number(id)) {
    return res.status(403).json({ error: 'Accès interdit' });
  }
  if (req.user.role !== 'admin' && role && role !== 'user') {
    return res.status(403).json({ error: 'Accès interdit : seul un admin peut changer les rôles' });
  }

  let hashedPassword = undefined;
  if (password) {
    // SECURITY FIX: hachage du nouveau mot de passe avant mise à jour
    hashedPassword = await bcrypt.hash(password, 10);
  }

  const sql = `
    UPDATE users
    SET username = ?, email = ?, ${hashedPassword ? 'password = ?, ' : ''} role = ?
    WHERE id = ?
  `;

  const params = hashedPassword
    ? [username, email, hashedPassword, role || 'user', id]
    : [username, email, role || 'user', id];

  try {
    await req.db.execute(sql, params);
    const newUser = { id, username, email, role: role || 'user' };
    res.json({ message: 'Utilisateur modifié avec succès', user: newUser });
  } catch (err) {
    console.error('Erreur lors de la modification de l\'utilisateur :', err);
    res.status(500).json({ error: 'Erreur lors de la modification de l\'utilisateur' });
  }
});

module.exports = router;
