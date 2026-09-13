# Send only this Dockerfile as build context. Test sources are individually
# mounted read-only at runtime; no keys, user data, reports or host sockets.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER 0:0
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-apt apt gpg gpg-agent dpkg openssl ca-certificates
ENV FIN3000_INSTALLER_APT_CONTAINER=1
CMD ["/usr/bin/python3", "-B", "-I", "/src/tests/test_linux_installer_apt.py", "-v"]
