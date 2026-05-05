FROM python:3.10-slim

WORKDIR /app

COPY agent/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY agent ./agent

RUN adduser --disabled-password --gecos "" shadowagent
USER shadowagent

CMD ["python", "-m", "agent.runner", "--once"]
