FROM python:3.13.7-slim

# Install only what you need and keep layers clean
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nut-client \
      iputils-ping \
      tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# (Optional) keep pip itself current for security/bugfixes
RUN python -m pip install --upgrade --no-cache-dir pip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py config.py models.py ./
COPY utils/ ./utils/
COPY services/ ./services/
COPY routes/ ./routes/
COPY templates/ ./templates/
COPY static/ ./static/

RUN mkdir -p /data
ENV PYTHONUNBUFFERED=1
ENV DATA_DIR=/data

EXPOSE 5000
CMD ["python", "main.py"]
