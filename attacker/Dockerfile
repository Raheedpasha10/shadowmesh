FROM python:3.10-slim

# Install nmap for network scanning
RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /attacker

# Install dependencies before copying code — leverages Docker layer cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create a non-root user and switch to it — never run containers as root
RUN adduser --disabled-password --gecos "" attacker
USER attacker

CMD ["python", "simulate.py"]
