FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mailbridge ./mailbridge

RUN mkdir -p /data

EXPOSE 8080

CMD ["uvicorn", "mailbridge.main:app", "--host", "0.0.0.0", "--port", "8080"]

