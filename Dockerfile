FROM python:3.10-slim

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y gcc python3-dev libpq-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y --auto-remove gcc python3-dev

EXPOSE 5000

CMD ["python", "anomaly_detector.py"]
