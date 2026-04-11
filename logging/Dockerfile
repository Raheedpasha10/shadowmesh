FROM python:3.10-slim

WORKDIR /forwarder

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user
RUN adduser --disabled-password --gecos "" forwarder
USER forwarder

CMD ["python", "forwarder.py"]
