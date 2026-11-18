FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd -m scanner && mkdir -p /srv/data && chown scanner /srv/data
USER scanner
# Non-loopback bind => the app REFUSES to start unless DASHBOARD_USER and DASHBOARD_PASSWORD are set.
ENV BIND_HOST=0.0.0.0 DB_PATH=/srv/data/vulnscanner.db
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host $BIND_HOST --port 8000"]
