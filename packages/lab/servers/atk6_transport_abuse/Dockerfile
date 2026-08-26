FROM python:3.12-slim

RUN groupadd -g 10001 mcplab && useradd -u 10001 -g mcplab -m -s /bin/bash mcplab

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py tool_configs.py ./

USER mcplab:mcplab

ENV VULN_MODE=safe
ENV PORT=8006

EXPOSE 8006

CMD ["python", "server.py", "--transport", "http", "--port", "8006"]
