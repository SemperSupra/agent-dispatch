# Exploratory public-synthetic CPU toolchain image. NOT an approved production lock.
# Immutable multiarch base qualified by Agent Dispatch public OCI run 43109332161.
ARG BASE=python@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    ghostscript=10.05.1~dfsg-1+deb13u3 \
    tesseract-ocr=5.5.0-1+b1 \
    tesseract-ocr-eng=1:4.1.0-2 \
    poppler-utils=25.03.0-5+deb13u4 >/dev/null \
    && rm -rf /var/lib/apt/lists/*
COPY experiments/python-ocr-toolchain/requirements-candidate.txt /opt/requirements-candidate.txt
COPY experiments/python-ocr-toolchain/wheel_capture.py /opt/wheel_capture.py
RUN mkdir -p /opt/wheels \
    && python -m pip download --disable-pip-version-check --no-cache-dir --require-hashes --only-binary=:all: \
         --no-deps --dest /opt/wheels -r /opt/requirements-candidate.txt \
    && python /opt/wheel_capture.py \
    && python -m pip install --disable-pip-version-check --no-index --no-deps --require-hashes \
         --find-links=/opt/wheels -r /opt/requirements-candidate.txt \
    && python -m pip check \
    && rm -rf /opt/wheels
COPY --chown=65532:65532 scripts/python_ocr_toolchain_probe.py /opt/probe.py
USER 65532:65532
WORKDIR /tmp
CMD ["python", "/opt/probe.py", "--inner"]
