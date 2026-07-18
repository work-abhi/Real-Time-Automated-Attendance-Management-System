FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r backend/requirements.txt && \
    pip install --no-cache-dir --no-deps face-recognition==1.3.0

COPY . .

WORKDIR /app/backend

ENV PYTHONUNBUFFERED=1

CMD gunicorn --bind 0.0.0.0:$PORT app:app --timeout 120 --workers 1