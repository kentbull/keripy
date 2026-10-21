FROM python:3.14.8-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170
RUN apt-get update && apt-get install -y --no-install-recommends libsodium23=1.0.18-1+deb13u1 gcc=4:14.2.0-1 libc6-dev=2.41-12+deb13u4 && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY setup.py /build/setup.py
COPY scripts/v2-e2e/requirements.lock /build/requirements.lock
RUN python -m pip install -c /build/requirements.lock pip==26.2.1 setuptools==84.0.0 wheel==0.48.0
RUN python -m pip install --no-build-isolation -r /build/requirements.lock
RUN mkdir -p /build/src && cd /build && python -m pip install --no-deps --no-build-isolation '.[test]'
ENV PYTHONPATH=/workspace/src
CMD ["python", "-m", "pytest", "-q", "tests/acdc"]
