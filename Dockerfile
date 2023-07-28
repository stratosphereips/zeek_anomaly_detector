FROM python:3.9-slim

LABEL org.opencontainers.image.title="Zeek Anomaly Detector" \
      org.opencontainers.image.description="This image runs the Zeek Anomaly Detector tool for network data analysis." \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.created="2023-07-27" \
      org.opencontainers.image.source="https://github.com/stratosphereips/zeek_anomaly_detector" \
      org.opencontainers.image.authors="Veronica Valeros <vero.valeros@gmail.com>, Sebastian Garcia <eldraco@gmail.com>"

ENV DEBIAN_FRONTEND=noninteractive
ENV DESTINATION_DIR /zeek_anomaly_detector/

RUN apt update && \ 
    apt install -y --no-install-recommends git && \
    apt clean

RUN git clone --depth 1 --recurse-submodules https://github.com/stratosphereips/zeek_anomaly_detector.git ${DESTINATION_DIR}

WORKDIR ${DESTINATION_DIR}

RUN pip install -r requirements.txt

RUN git submodule update --init --recursive --remote
