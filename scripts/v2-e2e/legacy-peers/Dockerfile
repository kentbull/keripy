FROM python:3.12.15-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
RUN apt-get update && apt-get install -y --no-install-recommends libsodium23 gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/legacy
COPY profiles.json install.py requirements-1.2.14.lock requirements-1.3.6.lock /opt/legacy
ARG KERI_VERSION
RUN python -m pip install pip==25.3 setuptools==80.9.0 wheel==0.45.1 && python install.py "$KERI_VERSION" && python -m pip check
COPY peer.py /opt/legacy/peer.py
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python", "peer.py"]
