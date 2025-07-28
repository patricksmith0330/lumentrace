FROM python:3.11-alpine3.22 AS builder

ARG APP_UID=1000
ARG APP_GID=1000
RUN addgroup -g ${APP_GID} -S appgroup || \
    true && \
    adduser -S -u ${APP_UID} -G appgroup -h /home/appuser -D appuser
RUN apk add --no-cache \
    build-base \
    libffi-dev \
    libpcap-dev \
    libxml2-dev \
    libxslt-dev \
    gfortran \
    openblas-dev \
    lapack-dev && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

WORKDIR /app
COPY main.py ./
COPY templates/ ./templates/
COPY static/ ./static/
RUN pip install --no-cache-dir \
    flask \
    scapy \
    ping3 \
    lxml \
    scipy \
    filelock \
    python-dotenv \
    Flask-Limiter \
    python-json-logger \
    waitress \
    redis # Added Flask-Limiter, python-json-logger, waitress, and redis

FROM python:3.11-alpine3.22

ARG APP_UID=1000
ARG APP_GID=1000
RUN addgroup -g ${APP_GID} -S appgroup || \
    true && \
    adduser -S -u ${APP_UID} -G appgroup -h /home/appuser -D appuser || \
    true
RUN apk add --no-cache \
    nmap \
    nut \
    iproute2 \
    procps \
    openblas \
    lapack \
    gfortran \
    libpcap \
    libxml2 \
    libxslt \
    libcap && \
    setcap 'cap_net_raw+eip cap_net_admin+eip' /usr/local/bin/python3.11 && \
    setcap 'cap_net_raw+eip cap_net_admin+eip cap_net_bind_service+eip' /usr/bin/nmap && \
    getcap /usr/local/bin/python3.11 && \
    getcap /usr/bin/nmap && \
    apk del libcap && \
    mkdir -p /app /data && \
    chown -R ${APP_UID}:${APP_GID} /data && \
    chown -R ${APP_UID}:${APP_GID} /app && \
    chmod 755 /app /data && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

WORKDIR /app
COPY --from=builder --chown=${APP_UID}:${APP_GID} /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder --chown=${APP_UID}:${APP_GID} /app/main.py /app/main.py
COPY --from=builder --chown=${APP_UID}:${APP_GID} /app/templates/ /app/templates/
COPY --from=builder --chown=${APP_UID}:${APP_GID} /app/static/ /app/static/
RUN chown -R ${APP_UID}:${APP_GID} /app 
EXPOSE 5000
USER appuser
CMD ["python3", "/app/main.py"]