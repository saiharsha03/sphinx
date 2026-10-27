FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY sphinx_relay.py .
# Pairings live in /data (mount a volume to keep them across restarts). Put TLS in front (Caddy, nginx, a tunnel):
# the phone and the extension only talk https.
# SPHINX_REGISTER_TOKEN is required at run time (docker run -e SPHINX_REGISTER_TOKEN=...): the relay won't start
# open. SPHINX_INSECURE_DEV=1 is for a local test relay only.
ENV SPHINX_STATE=/data/sphinx-relay.json SPHINX_HOST=0.0.0.0 SPHINX_PORT=8080
RUN mkdir /data && useradd -r relay && chown relay /data
USER relay
EXPOSE 8080
CMD ["python", "sphinx_relay.py"]
