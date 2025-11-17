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

# Download and install Ghidra (this layer is cached unless version changes)
ARG GHIDRA_VERSION=11.4.2
ARG GHIDRA_BUILD=20250826
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip && \
    unzip -q ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip && \
    rm ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip && \
    mv ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra

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
