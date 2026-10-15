FROM python:3.12-slim-bookworm@sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d
COPY scripts/takeout_synthetic_fixture.py /app/fixture.py
COPY scripts/takeout_application_completion.py /app/takeout_application_completion.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python3", "/app/fixture.py"]
CMD ["--output", "/archive", "--state", "/state"]
