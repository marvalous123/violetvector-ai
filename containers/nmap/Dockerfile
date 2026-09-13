FROM kalilinux/kali-rolling@sha256:45eeb73d6f144a6a2fcf699b849c1d72ff5f2007ec952c98ab3084b77e9114a5

LABEL org.opencontainers.image.title="WAR-R00M bounded Nmap runtime"
LABEL org.opencontainers.image.description="Target-facing runtime for the disabled Project 15 TCP service-version adapter"
LABEL org.opencontainers.image.source="local Project 15 build"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends nmap=7.99+dfsg-1kali1 \
    && rm -rf /var/lib/apt/lists/*

USER 65534:65534
ENTRYPOINT ["/usr/bin/nmap"]
