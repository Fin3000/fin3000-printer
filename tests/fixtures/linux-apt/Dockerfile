# Context contains only the four allowlisted source/test files, never reports,
# VM images, account credentials, private signing material or a repository root.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 apt gpg gpg-agent dpkg && dpkg-query -W -f='${Package}\t${Version}\n' > /qa-package-versions.tsv
COPY scripts/ /probe/scripts/
COPY tests/ /probe/tests/
WORKDIR /probe
USER 1000:1000
CMD ["python3", "-B", "-I", "-m", "unittest", "discover", "-s", "tests", "-p", "test_linux_archive.py"]
