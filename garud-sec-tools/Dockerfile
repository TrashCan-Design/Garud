FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl git nmap sqlmap perl libnet-ssleay-perl \
    libjson-perl libxml-writer-perl \
    ca-certificates unzip default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Nikto from GitHub
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Go (required for Nuclei)
ARG GO_VERSION=1.22.2
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Nuclei + Templates 
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN nuclei -ut

# --- Tsunami ---
# Extract pre-compiled binaries and configs directly from official Google image
COPY --from=ghcr.io/google/tsunami-scanner-full:latest /usr/tsunami /opt/tsunami
RUN rm -f /opt/tsunami/plugins/generic_weak_credential_detector-0.0.1-SNAPSHOT.jar

ENV TSUNAMI_JAR=/opt/tsunami/tsunami.jar
ENV TSUNAMI_PLUGINS=/opt/tsunami/plugins

# Python service deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 8001
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "1"]