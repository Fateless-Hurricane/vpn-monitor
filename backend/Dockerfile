FROM python:3.12-slim

# --- xray-core install (needed for real proxy connectivity checks) ---
ARG XRAY_VERSION=v1.8.24
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && ARCH=$(uname -m) \
    && if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then XRAY_ARCH="arm64-v8a"; else XRAY_ARCH="64"; fi \
    && curl -L -o /tmp/xray.zip \
       "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip" \
    && unzip /tmp/xray.zip -d /usr/local/bin xray \
    && chmod +x /usr/local/bin/xray \
    && rm /tmp/xray.zip \
    && apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

ENV XRAY_BINARY_PATH=/usr/local/bin/xray

WORKDIR /app
COPY backend/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY frontend /frontend

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

