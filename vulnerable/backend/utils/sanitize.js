const sanitizeHtml = require('sanitize-html');

// SECURITY FIX: utilitaire centralisé pour nettoyer le HTML riche venant des utilisateurs
const sanitizeRichText = (html) => {
  return sanitizeHtml(html, {
    allowedTags: [
      'p', 'b', 'i', 'em', 'strong', 'u',
      'ul', 'ol', 'li',
      'a',
      'h1', 'h2', 'h3', 'h4',
      'blockquote', 'code', 'pre',
      'span', 'br'
    ],
    allowedAttributes: {
      a: ['href', 'title', 'target', 'rel'],
      '*': ['class']
    },
    allowedSchemes: ['http', 'https', 'mailto']
  });
};

module.exports = {
  sanitizeRichText,
};


