FROM python:3.12-slim

# Create isolated unprivileged user
RUN groupadd -g 10001 mcplab && useradd -u 10001 -g mcplab -m -s /bin/bash mcplab

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py tool_configs.py ./

# Create mock canary files for isolated testing
RUN mkdir -p /home/mcplab/.ssh /home/mcplab/.aws && \
    echo "CANARY_SSH_KEY_MOCK_DATA" > /home/mcplab/.ssh/id_rsa && \
    echo "aws_access_key_id=CANARY_KEY\naws_secret_access_key=CANARY_SECRET" > /home/mcplab/.aws/credentials && \
    chown -R mcplab:mcplab /home/mcplab

USER mcplab:mcplab

ENV VULN_MODE=safe
ENV PORT=8001

EXPOSE 8001

CMD ["python", "server.py", "--transport", "http", "--port", "8001"]
