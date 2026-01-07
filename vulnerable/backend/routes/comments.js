const express = require('express');
const router = express.Router();
const { authenticate, authorizeAdmin } = require('../middlewares/authMiddleware');
const { sanitizeRichText } = require('../utils/sanitize');

// Route pour lister les commentaires d'un article
router.get('/articles/:id/comments', async (req, res) => {
  const { id } = req.params;

  // SECURITY FIX: jointure avec users pour exposer directement le nom d'utilisateur sans requête supplémentaire
  const sql = `
    SELECT c.*, u.username AS username
    FROM comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.article_id = ?
  `;

  try {
    const [results] = await req.db.execute(sql, [id]);
    res.json(results);
  } catch (err) {
    console.error('Erreur lors de la récupération des commentaires :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des commentaires' });
  }
});

// Route pour récupérer un commentaire spécifique
router.get('/comments/:id', async (req, res) => {
  const { id } = req.params;
  const sql = `
    SELECT c.*, u.username AS username
    FROM comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.id = ?
  `;
  try {
    const [results] = await req.db.execute(sql, [id]);
    if (results.length === 0) {
      return res.status(404).json({ error: 'Commentaire introuvable' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Erreur lors de la récupération du commentaire :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération du commentaire' });
  }
});

// Route pour ajouter un commentaire
router.post('/articles/:id/comments', authenticate, async (req, res) => {
  const { id } = req.params;
  const { content } = req.body;

  // SECURITY FIX: utilisation de l'id utilisateur issu du JWT et requête préparée pour éviter les injections SQL
  const userId = req.user.id;
  const sanitizedContent = sanitizeRichText(content || '');

  const sql = 'INSERT INTO comments (content, user_id, article_id) VALUES (?, ?, ?)';
  try {
    const [results] = await req.db.execute(sql, [sanitizedContent, userId, id]);
    const newComment = {
      id: results.insertId,
      content: sanitizedContent,
      user_id: userId,
      article_id: id
    };
    res.status(201).json({ message: "Commentaire ajouté à l'article", comment: newComment });
  } catch (err) {
    console.error('Erreur lors de la création du commentaire :', err);
    res.status(500).json({ error: 'Erreur lors de la création du commentaire' });
  }
});

// Route pour supprimer un commentaire (admin seulement)
router.delete('/comments/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM comments WHERE id = ?';
  try {
    await req.db.execute(sql, [id]);
    res.json({ message: 'Commentaire supprimé avec succès' });
  } catch (err) {
    console.error('Erreur lors de la suppression du commentaire :', err);
    res.status(500).json({ error: 'Erreur lors de la suppression du commentaire' });
  }
});

module.exports = router;
