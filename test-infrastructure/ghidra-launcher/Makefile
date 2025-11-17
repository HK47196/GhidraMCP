# Makefile for Ghidra CodeBrowser Launcher
#
# This builds a standalone launcher that can be used with any Ghidra installation.
#
# Usage:
#   make GHIDRA_HOME=/opt/ghidra        # Compile the launcher
#   make install GHIDRA_HOME=/opt/ghidra   # Install to Ghidra installation
#   make clean                          # Clean build artifacts

# Configuration
GHIDRA_HOME ?= /opt/ghidra
SRC = LaunchCodeBrowser.java
CLASS_FILE = ghidra/LaunchCodeBrowser.class
JAR_FILE = ghidra-launcher.jar
BUILD_DIR = build
CLASSES_DIR = $(BUILD_DIR)/classes

# Ghidra JAR files needed for compilation
GHIDRA_JARS := $(shell find $(GHIDRA_HOME)/Ghidra -name "*.jar" 2>/dev/null)
GHIDRA_CLASSPATH := $(shell echo $(GHIDRA_JARS) | tr ' ' ':')

# Java compiler
JAVAC = javac
JAR = jar

.PHONY: all clean install help

all: $(JAR_FILE)

# Compile the Java class
$(CLASSES_DIR)/$(CLASS_FILE): $(SRC)
	@echo "Compiling LaunchCodeBrowser..."
	@mkdir -p $(CLASSES_DIR)
	$(JAVAC) -cp "$(GHIDRA_CLASSPATH)" -d $(CLASSES_DIR) $(SRC)
	@echo "Compilation successful!"

# Create JAR file
$(JAR_FILE): $(CLASSES_DIR)/$(CLASS_FILE)
	@echo "Creating JAR file..."
	cd $(CLASSES_DIR) && $(JAR) cf ../../$(JAR_FILE) ghidra/
	@echo "JAR file created: $(JAR_FILE)"

# Install to Ghidra installation
install: $(JAR_FILE)
	@echo "Installing to Ghidra..."
	@if [ ! -d "$(GHIDRA_HOME)" ]; then \
		echo "ERROR: GHIDRA_HOME not found: $(GHIDRA_HOME)"; \
		exit 1; \
	fi
	@mkdir -p $(GHIDRA_HOME)/Extensions/ghidra-launcher/lib
	cp $(JAR_FILE) $(GHIDRA_HOME)/Extensions/ghidra-launcher/lib/
	cp launchCodeBrowser.sh $(GHIDRA_HOME)/ 2>/dev/null || echo "Note: launchCodeBrowser.sh not found"
	@echo ""
	@echo "Installation complete!"
	@echo "The launcher is now available in Ghidra's classpath."
	@echo ""
	@echo "Usage:"
	@echo "  cd $(GHIDRA_HOME)"
	@echo "  ./launchCodeBrowser.sh <project.gpr> <program-name>"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f $(JAR_FILE)
	@echo "Clean complete!"

# Help message
help:
	@echo "Ghidra CodeBrowser Launcher Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Compile and create JAR (default)"
	@echo "  install     - Install to Ghidra installation"
	@echo "  clean       - Remove build artifacts"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  GHIDRA_HOME - Path to Ghidra installation (default: /opt/ghidra)"
	@echo ""
	@echo "Examples:"
	@echo "  make GHIDRA_HOME=/opt/ghidra"
	@echo "  make install GHIDRA_HOME=/path/to/ghidra_11.4.2"
