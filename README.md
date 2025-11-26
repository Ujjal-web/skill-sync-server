# SkillSync Backend API

This is the backend API for the **SkillSync** platform – a skill‑exchange marketplace where users can register/login, authenticate via JWT, and create/manage skill listings. It is intended to be used with the SkillSync Next.js frontend.

client side repo: https://github.com/Ujjal-web/skill-sync-nextjs

---

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Express
- **Database:** MongoDB
- **Auth:** JSON Web Tokens (JWT) + bcrypt password hashing
- **CORS:** `cors` (configured for the frontend URL)
- **Env management:** `dotenv`

---

## Features

- User registration & login with hashed passwords
- OAuth-style user upsert endpoint (`/auth/oauth`)
- Skill CRUD operations:
  - Create a skill (authenticated)
  - List all skills (public)
  - List current user’s skills (authenticated)
  - Get a single skill by ID (public)
  - Delete own skills (authenticated + owner check)

---
