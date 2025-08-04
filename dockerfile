# Production-ready Dockerfile for Flask using Gunicorn
FROM python:3.11-slim

# Environment settings
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Work directory
WORKDIR /app

# System dependencies (for building wheels of some packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose service port
EXPOSE 8080

# Run with Gunicorn.
# Assumes your Flask app object is named "app" inside app.py (i.e., app = Flask(__name__)).
# If different, change the last argument to <module>:<app_object>, e.g., "wsgi:app".
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
