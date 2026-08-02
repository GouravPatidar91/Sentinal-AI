FROM python:3.11-slim

# Set python environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /src

# Copy and install dependencies first
COPY requirements.txt ./backend/
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Copy backend files
COPY . ./backend/

# Expose FastAPI API port
EXPOSE 8000

# Start Uvicorn pointing to our backend package main app entrypoint
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
