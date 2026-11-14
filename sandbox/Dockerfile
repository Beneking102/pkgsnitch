# The pkgsnitch observation sandbox for npm packages.
# Built automatically on first use; the tag is derived from this directory's
# contents, so editing any file here produces a fresh image.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends strace ca-certificates git python3 make g++ \
 && rm -rf /var/lib/apt/lists/*

# /probe is root-owned so observed code cannot tamper with the network log.
RUN useradd --create-home --uid 1500 --shell /bin/bash dev \
 && mkdir -p /work /out /probe /opt/pkgsnitch \
 && chown dev:dev /work /out

COPY probe.js fetch.sh trace.sh honey.sh /opt/pkgsnitch/
RUN chmod 0555 /opt/pkgsnitch/*.sh

ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false NPM_CONFIG_AUDIT=false
WORKDIR /work
# A sandbox that is never torn down (the host was interrupted) ends itself.
CMD ["sleep", "3600"]
