# Exploratory public-synthetic CPU toolchain image. NOT an approved production lock.
# Immutable multiarch base qualified by Agent Dispatch public OCI run 43109332161.
ARG BASE=python@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    ghostscript tesseract-ocr tesseract-ocr-eng poppler-utils >/dev/null \
    && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
    --only-binary=:all: 'pypdf>=5,<8' 'jsonschema>=4,<5'
COPY --chown=65532:65532 scripts/python_ocr_toolchain_probe.py /opt/probe.py
USER 65532:65532
WORKDIR /tmp
CMD ["python", "/opt/probe.py", "--inner"]
