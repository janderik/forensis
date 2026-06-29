FROM python:3.11-slim

LABEL maintainer="forensis@example.com"
LABEL description="Forensis Digital Forensics Toolkit"

WORKDIR /opt/forensis

RUN apt-get update && apt-get install -y --no-install-recommends \
    sleuthkit \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["forensis"]
CMD ["--help"]
