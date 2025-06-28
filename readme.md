# PDF to CSV

> This repo is under VERY active development. Use at your own discretion

The absolute safest way to convert bank statements to CSV format.

---

# Table of Contents

- [Getting Started](#getting-started)
  - [Project Requirements](#project-requirements)
  - [Set up locally](#set-up-locally)
  - [Running the Application](#running-the-application)
- [Running the Application with Docker](#running-the-application-with-docker)
  - [Staging with Docker](#staging-with-docker)
  - [Production with Docker](#production-with-docker)
- [About the core stack](#about-the-core-stack)
- [Database Management](#database-management)
  - [Persistence](#persistence)
  - [Backup](#backup)
  - [Restore](#restore)
  - [List All Backups](#list-all-backups)
  - [Database Initialization](#database-initialization)
- [Troubleshooting](#troubleshooting)

## Getting Started

### Project Requirements

If you plan on running the project locally, you're going to need the following installed on your machine. The versions defined are what I am explicitly running right now, if I had to take a guess in the dark I'd say you're good to run with and version greater than or equal to whats defined below.

- [OpenAI API Key](https://openai.com/index/openai-api/)
- [Docker](https://www.docker.com/) version 25.0.2
- [Node.js](https://nodejs.org/en/download/) version 18.0
- [Go](https://go.dev/) version 1.23.1
- [SQLite](https://www.sqlite.org/download.html) version 3.43.2
- [Python](https://www.python.org/downloads/) version 3.12

## Set up locally

Watch this 5 minute getting started video here: https://www.youtube.com/watch?v=BhJ3JFsOh2g

1. **Clone the Repository**
2. **Environment Configuration**
   - Duplicate `.env.example` to `.env`
3. **Generate Base64 Key**
   - Navigate to `cmd/generate_base64_key` and run:
     ```sh
     go run main.go
     ```
   - Add the generated key to `SESSION_SECRET_KEY` in `.env`
4. **Add OpenAI API Key**
   - Update `.env` with your OpenAI API key

### Running the Application

1. **Start the Server**
   - From the root directory, run:
     ```sh
     go run main.go
     ```
2. **Client Setup**
   - In a separate terminal, navigate to `routes/` and install dependencies:
     ```sh
     npm install
     ```
   - Launch the client dev server:
     ```sh
     npm run dev
     ```
3. **Image Service Setup**
   - In another terminal, navigate to `/lib/pdf-service` and install dependencies:
     ```sh
     python -m venv venv
     source venv/bin/activate  # On Windows, use: venv\Scripts\activate
     pip install -r requirements.txt
     python main.py
     ```
   - Tip: If you don't need to change code in this server, you might just run the [Docker image](#build-the-libimage-python-service)

## Running the Application with Docker

The docker version of the application supports multiple environments:

### Staging with Docker

Useful for running observing what the application will look like in production.

```bash
# Copy example env file
cp .env.example .env.staging
# Edit .env.development with your development settings
docker compose up --build
```

### Production with Docker

Secure encryption and proper configuration is required and enforced in this environment.

```bash
# Copy example env file
cp .env.example .env.production
# Edit .env.production with your production settings
DOCKER_ENV=production docker compose -f docker-compose.yml -f docker-compose.production.yml up --build
```

## About the core stack

Backend

- [Go](https://go.dev/) - Server side programming language
- [Gin](https://gin-gonic.com/) - HTTP framework
- [SQLite](https://www.sqlite.org/) - Database that's easy to work with

Client

- [React](https://react.dev/) - Web library
- [TanStack Router](https://tanstack.com/router) - Web routing system
- [Vite](https://vite.dev/) - JavaScript build tool
- [TypeScript](https://www.typescriptlang.org/) - Type safe javascript
- [TailwindCSS](https://tailwindcss.com) - Style framework
- [Shadcn/ui](https://ui.shadcn.com/) - Accessible components built on top of TailwindCSS
- [Fabric.js](https://fabricjs.com/) - Used for drawing on canvas (Pdf's)

PDF Service (Micro Service /lib/pdf-service)

- [Python](https://www.python.org/downloads)
- [PyMuPDF](https://pymupdf.readthedocs.io/en/latest/)

## Database Management

### Persistence

The database is stored in a Docker named volume that persists between container restarts. Each environment (staging, production) has its own separate volume.

### Backup

To backup the database:

```bash
# Make scripts executable
chmod +x scripts/backup.sh
chmod +x scripts/restore.sh

# Create a backup (defaults to staging environment)
./scripts/backup.sh [environment]

# Example:
./scripts/backup.sh production
```

### Restore

To restore from a backup:

```bash
./scripts/restore.sh [environment] path/to/backup/file.db

# Example:
./scripts/restore.sh production ./backups/production/backup_20241201_120000.db
```

### List All Backups

```bash
ls -l backups/[environment]/
```

### Database Initialization

Before running backups, ensure your database is properly initialized:

```bash
# Start the containers first
docker compose up -d

# Now you can create your first backup
./scripts/backup.sh [environment]
```

## Troubleshooting

```
docker compose down
docker compose build --no-cache
docker compose up -d
```
