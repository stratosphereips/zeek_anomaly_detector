FROM python:3.9-slim

LABEL org.opencontainers.image.authors="vero.valeros@gmail.com,eldraco@gmail.com"

ENV DEBIAN_FRONTEND=noninteractive
ENV DESTINATION_DIR /zeek_anomaly_detector/

RUN apt update && \ 
    apt install -y --no-install-recommends git && \
    apt clean

RUN git clone --depth 1 --recurse-submodules https://github.com/stratosphereips/zeek_anomaly_detector.git ${DESTINATION_DIR}

WORKDIR ${DESTINATION_DIR}

RUN pip install -r requirements.txt

RUN git submodule update --init --recursive --remote
