# Image simple pour `bgpmon run`. La configuration et les données sont montées dans /data.
#   docker build -t bgpmon .
#   docker run --rm -v "$PWD/data:/data" -e BGPMON_WEBHOOK_URL bgpmon
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BGPMON_CONFIG=/data/config.yaml

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY bgpmon/ bgpmon/

RUN useradd --system --uid 10001 --home-dir /data bgpmon \
    && mkdir -p /data && chown bgpmon /data
USER bgpmon
WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT ["python", "-m", "bgpmon"]
CMD ["run"]
