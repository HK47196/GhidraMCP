# Dockerfile for running GhidraMCP E2E tests in complete isolation
FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    python3-venv \
    openjdk-21-jdk \
    maven \
    xvfb \
    x11vnc \
    xdotool \
    gcc \
    wget \
    unzip \
    git \
    file \
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra using the download script
# Version defaults are defined in download_ghidra.sh (single source of truth)
# Can be overridden via: docker build --build-arg GHIDRA_VERSION=x.y.z --build-arg GHIDRA_BUILD=YYYYMMDD
ARG GHIDRA_VERSION
ARG GHIDRA_BUILD
COPY download_ghidra.sh /tmp/download_ghidra.sh
RUN chmod +x /tmp/download_ghidra.sh && \
    cd /tmp && \
    SKIP_CLEANUP=1 \
    GHIDRA_VERSION="$GHIDRA_VERSION" \
    GHIDRA_DATE="$GHIDRA_BUILD" \
    /tmp/download_ghidra.sh && \
    mkdir -p /opt /workspace/lib && \
    mv /tmp/build/ghidra-download/extracted/ghidra_*_PUBLIC /opt/ghidra && \
    mv /tmp/lib/* /workspace/lib/ && \
    rm -rf /tmp/build /tmp/lib /tmp/download_ghidra.sh

# Set environment variables
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# Set up working directory
WORKDIR /workspace

# Copy Python requirements first (for better caching)
COPY requirements-test.txt /workspace/

# Install Python dependencies (this layer is cached unless requirements change)
RUN pip3 install --no-cache-dir -r requirements-test.txt

# Copy only files needed for building launcher and test binary
COPY test-infrastructure/ghidra-launcher/ /workspace/test-infrastructure/ghidra-launcher/
COPY test-infrastructure/fixtures/ /workspace/test-infrastructure/fixtures/

# Build and install LaunchCodeBrowser launcher
# Install to patch directory so it's on the classpath when launch.sh runs
RUN cd /workspace/test-infrastructure/ghidra-launcher && \
    make GHIDRA_HOME=/opt/ghidra && \
    cp ghidra-launcher.jar /opt/ghidra/Ghidra/patch/

# Build test binary
RUN chmod +x test-infrastructure/fixtures/build_test_binary.sh && \
    test-infrastructure/fixtures/build_test_binary.sh

# Copy the rest of the workspace (code changes most frequently, so this is last)
COPY . /workspace/

# Copy and set up entrypoint script
COPY test-infrastructure/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Default entrypoint builds plugin and runs tests
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["-v"]
