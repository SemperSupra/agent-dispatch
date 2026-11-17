# syntax=docker/dockerfile:1.7
ARG R15_IMAGE
FROM ${R15_IMAGE}
COPY run.py /guest/r26-m3-run.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/r26-m3-run.py"]
