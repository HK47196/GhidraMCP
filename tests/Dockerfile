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
    xvfb \
    gcc \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /workspace

# Download and install Ghidra
ARG GHIDRA_VERSION=11.4.2
ARG GHIDRA_BUILD=20250317
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip && \
    unzip -q ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip && \
    rm ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip && \
    mv ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra

# Set environment variables
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# Copy project files
COPY . /workspace/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements-test.txt

# Build test binary
RUN chmod +x tests/fixtures/build_test_binary.sh && \
    tests/fixtures/build_test_binary.sh

# Default command runs all tests
CMD ["pytest", "tests/e2e/", "--ghidra-dir=/opt/ghidra", "-v"]
