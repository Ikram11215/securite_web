const express = require('express');
const router = express.Router();
const { authenticate, authorizeAdmin } = require('../middlewares/authMiddleware');
const { sanitizeRichText } = require('../utils/sanitize');

// Route pour récupérer tous les articles
router.get('/', async (req, res) => {
  // SECURITY FIX: jointure avec la table users pour éviter un appel séparé non sécurisé à /users côté frontend
  const sql = `
    SELECT a.*, u.username AS author_username
    FROM articles a
    JOIN users u ON a.author_id = u.id
  `;
  try {
    const [results] = await req.db.execute(sql);
    res.json(results);
  } catch (err) {
    console.error('Erreur lors de la récupération des articles :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des articles' });
  }
});

// Route pour chercher un article par titre
router.post('/search', async (req, res) => {
  const { title } = req.body;

  // SECURITY FIX: requête préparée pour éviter les injections SQL sur le champ title
  const sql = `
    SELECT a.*, u.username AS author_username
    FROM articles a
    JOIN users u ON a.author_id = u.id
    WHERE a.title LIKE ?
  `;

  try {
    const [results] = await req.db.execute(sql, [`%${title}%`]);
    res.json(results);
  } catch (err) {
    console.error('Erreur lors de la recherche des articles :', err);
    res.status(500).json({ error: 'Erreur lors de la recherche des articles' });
  }
});

// Route pour récupérer un article spécifique
router.get('/:id', async (req, res) => {
  const { id } = req.params;
  const sql = `
    SELECT a.*, u.username AS author_username
    FROM articles a
    JOIN users u ON a.author_id = u.id
    WHERE a.id = ?
  `;
  try {
    const [results] = await req.db.execute(sql, [id]);
    if (results.length === 0) {
      return res.status(404).json({ error: 'Article introuvable' });
    }
    res.json(results[0]);
  } catch (err) {
    console.error('Erreur lors de la récupération de l\'article :', err);
    res.status(500).json({ error: 'Erreur lors de la récupération de l\'article' });
  }
});

// Route pour créer un nouvel article
router.post('/', authenticate, async (req, res) => {
  const { title, content, author_id } = req.body;

  // SECURITY FIX: on fait confiance à l'identité injectée par le JWT plutôt qu'à l'author_id venant du client
  const safeAuthorId = req.user.id;
  const sanitizedContent = sanitizeRichText(content || '');

  const sql = 'INSERT INTO articles (title, content, author_id) VALUES (?, ?, ?)';
  try {
    const [results] = await req.db.execute(sql, [title, sanitizedContent, safeAuthorId]);
    const newArticle = {
      id: results.insertId,
      title,
      content: sanitizedContent,
      author_id: safeAuthorId
    };
    res.status(201).json({ message: 'Article créé avec succès', article: newArticle });
  } catch (err) {
    console.error('Erreur lors de la création de l\'article :', err);
    res.status(500).json({ error: 'Erreur lors de la création de l\'article' });
  }
});

// Route pour modifier un article
router.put('/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;

  // SECURITY FIX: nettoyage du HTML et contrôle d'ownership de l'article côté serveur
  const sanitizedContent = sanitizeRichText(content || '');

  // Vérifier que l'utilisateur connecté est bien l'auteur ou un admin
  const [articles] = await req.db.execute('SELECT author_id FROM articles WHERE id = ?', [id]);
  if (articles.length === 0) {
    return res.status(404).json({ error: 'Article introuvable' });
  }
  const article = articles[0];
  if (req.user.role !== 'admin' && Number(article.author_id) !== Number(req.user.id)) {
    return res.status(403).json({ error: 'Accès interdit : vous n\'êtes pas l\'auteur de cet article' });
  }

  const sql = 'UPDATE articles SET title = ?, content = ? WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [title, sanitizedContent, id]);
    if (results.affectedRows === 0) {
      return res.status(404).json({ error: 'Article introuvable' });
    }
    const updatedArticle = {
      id,
      title,
      content: sanitizedContent,
      author_id: article.author_id
    };
    res.json({ message: 'Article modifié avec succès', article: updatedArticle });
  } catch (err) {
    console.error('Erreur lors de la modification de l\'article :', err);
    res.status(500).json({ error: 'Erreur lors de la modification de l\'article' });
  }
});

// Route pour supprimer un article
router.delete('/:id', authenticate, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM articles WHERE id = ?';
  try {
    const [results] = await req.db.execute(sql, [id]);
    if (results.affectedRows === 0) {
      return res.status(404).json({ error: 'Article introuvable' });
    }
    res.json({ message: 'Article supprimé avec succès' });
  } catch (err) {
    console.error('Erreur lors de la suppression de l\'article :', err);
    res.status(500).json({ error: 'Erreur lors de la suppression de l\'article' });
  }
});

module.exports = router;
