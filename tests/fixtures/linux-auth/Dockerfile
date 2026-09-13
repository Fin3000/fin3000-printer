# Isolated G0 experiment only, never a product image or printer installer.
ARG BASE_IMAGE=ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517
FROM ${BASE_IMAGE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    cups-daemon cups-client cups-core-drivers cups-filters python3 && \
    useradd --uid 2000 --no-create-home probeowner && \
    useradd --uid 2001 --no-create-home probeforeign
COPY probe.py /probe/probe.py
RUN chmod 0555 /probe/probe.py
ENV FIN3000_G0_CONTAINER=1
ENTRYPOINT ["/usr/bin/python3", "-B", "/probe/probe.py"]
