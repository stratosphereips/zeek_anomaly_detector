FROM python:3.9-slim

LABEL org.opencontainers.image.authors="vero.valeros@gmail.com,eldraco@gmail.com"

ENV DESTINATION_DIR /zeek_anomaly_detector/

COPY . ${DESTINATION_DIR}/

WORKDIR ${DESTINATION_DIR}

RUN pip install -r requirements.txt
