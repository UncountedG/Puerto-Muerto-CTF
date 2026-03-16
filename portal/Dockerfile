FROM python:3.11-slim

COPY src/prepare.sh /prepare.sh
COPY src/execute.sh /execute.sh
COPY src/app /app

RUN chmod +x /prepare.sh /execute.sh && /prepare.sh

ENTRYPOINT ["/execute.sh"]