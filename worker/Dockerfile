# syntax=docker/dockerfile:1
ARG SANDBOX_TOOLS_IMAGE=docker.io/cloudflare/sandbox:1.0.3
FROM --platform=linux/amd64 ${SANDBOX_TOOLS_IMAGE} AS sandbox-tools

FROM --platform=linux/amd64 node:26-bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends bash ca-certificates curl git make python3 diffutils ripgrep procps util-linux \
  && rm -rf /var/lib/apt/lists/*
RUN npm install --global @anthropic-ai/claude-code@2.1.316
COPY --from=sandbox-tools /usr/local/bin/sandbox-shim /usr/local/bin/sandbox-shim
ADD --checksum=sha256:9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec https://go.dev/dl/go1.26.11.linux-amd64.tar.gz /tmp/go.tgz
RUN tar -xzf /tmp/go.tgz -C /opt \
  && rm /tmp/go.tgz \
  && groupmod -n agent node \
  && usermod --login agent --home /home/agent --move-home node \
  && test "$(id -u agent):$(id -g agent)" = "1000:1000" \
  && test -x /usr/bin/setpriv \
  && install -d -o root -g root -m 0755 /factory /factory/ctl
WORKDIR /factory
CMD ["sleep","infinity"]
