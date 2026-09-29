FROM python:3.11-slim

# Playwright + Chromium dependencies
RUN apt-get update && apt-get install -y \
    wget curl gnupg ca-certificates \
    libglib2.0-0 libnss3 libnspr4 libdbus-1-3 libatk1.0-0 \
    libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir playwright==1.44.0 tldextract requests

# Install Chromium browser
RUN playwright install chromium

WORKDIR /sandbox
COPY run.py /sandbox/run.py

ENTRYPOINT ["python", "/sandbox/run.py"]
