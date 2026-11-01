FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 vyrex
COPY --chown=10001:10001 app.py ./
COPY --chown=10001:10001 static ./static
RUN mkdir -p /app/data && chown 10001:10001 /app/data
USER 10001
EXPOSE 8000
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:8000", "--timeout", "60", "app:app"]
