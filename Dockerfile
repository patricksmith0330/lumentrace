FROM python:3.13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nut-client iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
 && python -m pip install --no-cache-dir -r requirements.txt

COPY main.py config.py models.py extensions.py ./
COPY utils/ ./utils/
COPY services/ ./services/
COPY routes/ ./routes/
COPY templates/ ./templates/
COPY static/ ./static/

RUN mkdir -p /data
ENV PYTHONUNBUFFERED=1 DATA_DIR=/data
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=3)" || exit 1
CMD ["python", "main.py"]
