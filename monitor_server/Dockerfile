FROM python:3.12-slim

WORKDIR /app

# Install dependencies (context is repo root — see docker-compose.yml)
COPY monitor_server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy monitor server files
COPY monitor_server/ .

# Copy the wmintelliops multi-agent package so agents are importable
COPY wmintelliops/ ./wmintelliops/

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
