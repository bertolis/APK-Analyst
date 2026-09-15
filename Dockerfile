# APKAnalyst web app — container image.
#
# Image-level hardening lives here (minimal base, pinned tools, non-root user).
# The rest of the hardening is applied at RUN time — see the sample command at
# the bottom of this file (read-only fs, dropped caps, resource + pid limits,
# no-new-privileges). Keep both together.

FROM python:3.12-slim AS base

ARG JADX_VERSION=1.5.0
ARG APKTOOL_VERSION=2.9.3

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APK_ANALYST_DATA_DIR=/data \
    PATH="/opt/jadx/bin:/opt/apktool:${PATH}"

# System deps: a JRE for jadx/apktool, binutils for `strings`, unzip/curl to
# fetch the tools. Clean apt lists to keep the image small.
RUN apt-get update && apt-get install -y --no-install-recommends \
        default-jre-headless binutils unzip curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# jadx (pinned release)
RUN curl -fsSL -o /tmp/jadx.zip \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    && mkdir -p /opt/jadx && unzip -q /tmp/jadx.zip -d /opt/jadx && rm /tmp/jadx.zip

# apktool (pinned jar + wrapper)
RUN curl -fsSL -o /opt/apktool/apktool.jar \
        "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
        --create-dirs \
    && curl -fsSL -o /opt/apktool/apktool \
        "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
    && chmod 755 /opt/apktool /opt/apktool/apktool \
    && chmod 644 /opt/apktool/apktool.jar

WORKDIR /app

# Install Python deps first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code.
COPY . .

# Prebuild the RAG index into the image so agentic grounding works without a
# runtime Voyage key. The Voyage key is passed as a BuildKit secret so it is
# used only during this step and never stored in an image layer:
#
#   DOCKER_BUILDKIT=1 docker build \
#     --secret id=voyage,env=VOYAGE_API_KEY -t apkanalyst .
#
# If the secret is absent the build still succeeds and ships a MASVS-only (or
# empty) index — you can rebuild later with --build-kb.
RUN --mount=type=secret,id=voyage \
    mkdir -p /data && \
    VOYAGE_API_KEY="$(cat /run/secrets/voyage 2>/dev/null || true)" \
        python3 run.py --build-kb \
    || echo "KB build skipped — build later with --build-kb"

# Non-root user; own the app + data dirs.
RUN useradd --system --uid 10001 --home /home/appuser --create-home appuser \
    && chown -R appuser:appuser /app /data
USER appuser

EXPOSE 8077

# The server reads keys from the environment (pass them with `docker run -e`).
CMD ["python3", "-m", "uvicorn", "webapp.server:app", "--host", "0.0.0.0", "--port", "8077"]

# ---------------------------------------------------------------------------
# Hardened run (apply the runtime-only protections here, not in the image):
#
#   docker run --rm \
#     -p 8077:8077 \
#     --log-opt max-size=10m --log-opt max-file=3 \
#     --read-only \
#     --tmpfs /app/webapp/_jobs:rw,size=1g,noexec,nosuid \
#     --tmpfs /tmp:rw,size=256m,noexec,nosuid \
#     --cap-drop=ALL \
#     --security-opt=no-new-privileges \
#     --pids-limit=256 \
#     --memory=3g --cpus=2 \
#     -e ANTHROPIC_API_KEY -e VOYAGE_API_KEY -e METRICS_TOKEN \
#     apkanalyst
#
# Notes:
# - --read-only + tmpfs keeps the filesystem immutable except the scratch dirs.
# - For per-scan isolation at scale, run each scan in its own ephemeral
#   container, or use a stronger sandbox runtime (gVisor / Kata / Firecracker).
# - The decompile step needs no internet; only the model calls do. If you can,
#   restrict egress to the Anthropic/Voyage API hosts.
# ---------------------------------------------------------------------------
