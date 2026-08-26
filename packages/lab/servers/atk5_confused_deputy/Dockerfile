FROM python:3.12-slim

RUN groupadd -g 10001 mcplab && useradd -u 10001 -g mcplab -m -s /bin/bash mcplab

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py tool_configs.py ./

RUN mkdir -p /home/mcplab/.ssh /home/mcplab/.aws && \
    echo "CANARY_SSH_KEY_PRIVATE" > /home/mcplab/.ssh/id_rsa && \
    echo "aws_access_key_id=CANARY_KEY\naws_secret_access_key=CANARY_SECRET" > /home/mcplab/.aws/credentials && \
    chown -R mcplab:mcplab /home/mcplab

USER mcplab:mcplab

ENV VULN_MODE=safe
ENV PORT=8005

EXPOSE 8005

CMD ["python", "server.py", "--transport", "http", "--port", "8005"]
