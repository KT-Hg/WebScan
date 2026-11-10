# No official Wapiti image: build a minimal pinned one.
FROM python:3.12-slim

ARG WAPITI_VERSION=3.3.2
RUN pip install --no-cache-dir "wapiti3==${WAPITI_VERSION}"

RUN useradd --create-home --uid 10001 wapiti \
 && mkdir /out && chown wapiti /out
USER wapiti
WORKDIR /out

ENTRYPOINT ["wapiti"]
