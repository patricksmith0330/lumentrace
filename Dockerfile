FROM python:3.13-slim
RUN apt-get update && apt-get install -y nut-client iputils-ping && rm -rf /var/lib/apt/lists/*
WORKDIR /app
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