FROM python:3.12-slim

WORKDIR /app

# Install dependencies (context is repo root — see docker-compose.yml)
COPY wmintelliops/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the multi-agent package
COPY wmintelliops/ ./wmintelliops/

EXPOSE 8001

CMD ["uvicorn", "wmintelliops.api.app:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2"]
