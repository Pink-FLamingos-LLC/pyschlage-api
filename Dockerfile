FROM python:3.11.11-slim-bookworm

ENV PYTHONUNBUFFERED=1

RUN addgroup --system --gid 1001 app && \
    adduser --system --uid 1001 --ingroup app --no-create-home app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

RUN chown -R app:app /app

USER app

EXPOSE 8080

CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
