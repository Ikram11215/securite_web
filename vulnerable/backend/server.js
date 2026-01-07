const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const initializeDbConnection = require('./db');

const app = express();

// SECURITY FIX: configuration CORS explicite (origines autorisées configurables via environnement)
const corsOptions = {
  origin: process.env.FRONTEND_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));

app.use(bodyParser.json());

// SECURITY FIX: ajout d'headers de sécurité HTTP standard via helmet
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", '*'],
    },
  },
}));

const startServer = async () => {
  try {
    // Attente que la base de données soit prête
    const db = await initializeDbConnection();
    console.log('Base de données initialisée avec succès.');

    // Injection de la connexion DB dans les routes
    app.use((req, res, next) => {
      req.db = db; // Ajout de la connexion à l'objet requête
      next();
    });

    // Importation des routes
    const authRoutes = require('./routes/auth');
    const userRoutes = require('./routes/users');
    const articleRoutes = require('./routes/articles');
    const commentRoutes = require('./routes/comments');

    // Utilisation des routes
    app.use('/api/auth', authRoutes);
    app.use('/api/users', userRoutes);
    app.use('/api/articles', articleRoutes);
    app.use('/api/', commentRoutes);

    // SECURITY FIX: gestion d'erreurs centralisée pour éviter la fuite de détails techniques
    // (doit être enregistrée après les routes)
    app.use((err, req, res, next) => {
      console.error('Erreur serveur non gérée :', err);
      res.status(500).json({ error: 'Erreur interne du serveur' });
    });

    const PORT = 5100;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

  } catch (error) {
    console.error('Erreur lors de l\'initialisation du serveur :', error);
    process.exit(1); // Arrêt en cas d'erreur critique
  }
};

startServer();