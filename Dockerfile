FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends file binutils libimage-exiftool-perl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY flagforge /app/flagforge
COPY apostrophe /app/apostrophe
RUN useradd --uid 10001 --create-home analyst && mkdir /data && chown analyst:analyst /data
USER analyst
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8787
CMD ["python", "-m", "apostrophe", "--host", "0.0.0.0", "--data-dir", "/data", "--native-tools"]
