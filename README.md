# 🚀 Express.js Auth Boilerplate

Un **boilerplate backend** complet en Node.js + Express avec gestion d'authentification par JWT, MongoDB via Mongoose, middlewares personnalisés et structure organisée. Parfait pour démarrer rapidement un nouveau projet API 🔥

---

## 📦 Stack technique

- ⚙️ **Node.js / Express**
- 🔐 **JWT Authentication (Access + Refresh token)**
- 🍃 **MongoDB + Mongoose**
- 🍪 **Cookie-based token storage**
- 🧱 **Middleware error handling**
- 📂 Structure de projet modulaire
- 🔧 `dotenv` pour variables d'environnement

## 🧭 Structure du projet

📦 backend/
├── 📁 models/
├── 📁 routes/
├── 📁 middleware/
├── 📁 public/
├── .env
├── app.js
├── server.js
└── package.json

---

## 🚀 Démarrage rapide

1. **Clone le repo**

```bash
git clone https://github.com/Tobear91/boilerplate-express-api.git mon-backend
cd mon-backend
rm -rf .git
yarn reset
```

2. **Clone les variables d'env**

```bash
cp .env.exemple .env
```