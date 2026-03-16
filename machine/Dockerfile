FROM debian:bookworm-slim

COPY src/prepare.sh /prepare.sh
COPY src/execute.sh /execute.sh
COPY html/ /opt/sigeport/

RUN chmod +x /prepare.sh /execute.sh && /prepare.sh

ENTRYPOINT ["/execute.sh"]