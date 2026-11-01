# VYREX BIO

English frontend and Chinese administration dashboard, Flask + Docker.

## Deploy on Render
- Connect a private GitHub repository and choose Docker runtime (Dockerfile at repository root).
- Configure VYREX_SECRET_KEY (random 32+ characters), VYREX_ADMIN_USER, VYREX_ADMIN_PASSWORD (12+ characters), VYREX_DATA_DIR=/app/data.
- Use HTTPS and persistent storage mounted to /app/data before accepting inquiries or uploading documents.
- Do not upload .env, SQLite files, uploaded files or customer data to GitHub.
- This package is not security audited or production verified. Verify local deployment, access controls and product compliance before publishing.
