# Fixture: secrets-in-env.Dockerfile
#
# Bakes API credentials into image layers via ENV. The dockerfile
# scanner's secret-in-env rule flags any ENV / ARG line whose name
# contains PASSWORD, SECRET, TOKEN, API_KEY, or PRIVATE_KEY. This
# fixture deliberately uses three of those names, but the regex
# only emits one finding per matching line so the total count is
# three (one per offending ENV row).
FROM python:3.12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
USER 10001
ENV API_KEY=baked-into-the-image
ENV DB_PASSWORD=do-not-do-this
ENV STRIPE_SECRET=sk_live_fake
WORKDIR /app
COPY app.py .
CMD ["python", "app.py"]
