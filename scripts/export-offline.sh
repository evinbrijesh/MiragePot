#!/bin/bash
# Export script for MiragePot offline deployment
# Creates a complete offline bundle with Docker images and Ollama models

set -e  # Exit on error

BUNDLE_NAME="miragepot-offline-bundle.tar.gz"
IMAGES_TAR="miragepot-images.tar"
MODELS_TAR="ollama-models.tar.gz"
TEMP_DIR="miragepot-export-temp"

echo "========================================="
echo " MiragePot Offline Bundle Export Script"
echo "========================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running"
    echo "   Please start Docker and try again"
    exit 1
fi

echo "✓ Docker is running"

# Check if containers are running
cd docker/
if ! docker compose ps | grep -q "Up"; then
    echo ""
    echo "⚠️  Warning: Containers are not running"
    echo "   Starting containers to ensure everything is ready..."
    docker compose up -d
    sleep 10
fi
cd ..

echo "✓ Containers are running"

# Check if Ollama model is downloaded
echo ""
echo "Checking Ollama model..."
if ! docker exec miragepot-ollama ollama list 2>/dev/null | grep -q "phi3"; then
    echo "⚠️  phi3 model not found. Downloading now (~2GB, may take 2-5 minutes)..."
    docker exec miragepot-ollama ollama pull phi3
else
    echo "✓ phi3 model is ready"
fi

# Create temporary directory
echo ""
echo "Creating temporary directory..."
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"

# Step 1: Export Docker images
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 1/4: Exporting Docker images (~4GB)"
echo "This may take 3-5 minutes..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

docker save \
  miragepot-honeypot:latest \
  ollama/ollama:latest \
  prom/prometheus:latest \
  grafana/grafana:latest \
  prom/alertmanager:latest \
  -o "$TEMP_DIR/$IMAGES_TAR"

echo "✓ Docker images exported: $(du -h "$TEMP_DIR/$IMAGES_TAR" | cut -f1)"

# Step 2: Export Ollama models
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 2/4: Exporting Ollama models (~2GB)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

docker run --rm \
  -v ollama:/ollama \
  -v "$(pwd)/$TEMP_DIR":/backup \
  alpine tar czf /backup/"$MODELS_TAR" -C /ollama .

echo "✓ Ollama models exported: $(du -h "$TEMP_DIR/$MODELS_TAR" | cut -f1)"

# Step 3: Copy source files
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 3/4: Copying source files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create directory structure
mkdir -p "$TEMP_DIR/MiragePot"

# Copy essential files and directories
cp -r docker/ "$TEMP_DIR/MiragePot/"
cp -r miragepot/ "$TEMP_DIR/MiragePot/"
cp -r dashboard/ "$TEMP_DIR/MiragePot/"
cp -r grafana/ "$TEMP_DIR/MiragePot/"
cp -r scripts/ "$TEMP_DIR/MiragePot/"
cp -r docs/ "$TEMP_DIR/MiragePot/"
cp -r tests/ "$TEMP_DIR/MiragePot/" 2>/dev/null || true

# Copy data directory structure (but not logs)
mkdir -p "$TEMP_DIR/MiragePot/data/logs"
cp data/cache.json "$TEMP_DIR/MiragePot/data/" 2>/dev/null || echo "{}" > "$TEMP_DIR/MiragePot/data/cache.json"
cp data/system_prompt.txt "$TEMP_DIR/MiragePot/data/" 2>/dev/null || true
touch "$TEMP_DIR/MiragePot/data/logs/.gitkeep"

# Copy root files
cp .env.docker.example "$TEMP_DIR/MiragePot/"
cp requirements.txt "$TEMP_DIR/MiragePot/"
cp pyproject.toml "$TEMP_DIR/MiragePot/"
cp README.md "$TEMP_DIR/MiragePot/"
cp LICENSE "$TEMP_DIR/MiragePot/" 2>/dev/null || true
cp CONTRIBUTING.md "$TEMP_DIR/MiragePot/" 2>/dev/null || true
cp Makefile "$TEMP_DIR/MiragePot/" 2>/dev/null || true
cp .gitignore "$TEMP_DIR/MiragePot/"

# Copy the docker images and models into the source tree
mv "$TEMP_DIR/$IMAGES_TAR" "$TEMP_DIR/MiragePot/"
mv "$TEMP_DIR/$MODELS_TAR" "$TEMP_DIR/MiragePot/"

echo "✓ Source files copied"

# Step 4: Create final bundle
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 4/4: Creating offline bundle"
echo "This may take 2-3 minutes..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd "$TEMP_DIR"
tar czf "../$BUNDLE_NAME" MiragePot/
cd ..

# Clean up temp directory
rm -rf "$TEMP_DIR"

# Generate checksum
echo ""
echo "Generating checksum..."
sha256sum "$BUNDLE_NAME" > "${BUNDLE_NAME}.sha256"

# Display results
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Export Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Bundle created: $BUNDLE_NAME"
echo "Size: $(du -h "$BUNDLE_NAME" | cut -f1)"
echo "Checksum: ${BUNDLE_NAME}.sha256"
echo ""
echo "Contents:"
echo "  • Docker images (5 containers)"
echo "  • Ollama phi3 model"
echo "  • Complete source code"
echo "  • Pre-configured dashboards"
echo "  • Documentation"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Next Steps:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Copy bundle to USB drive:"
echo "   cp $BUNDLE_NAME /path/to/usb/"
echo ""
echo "2. On demo machine, extract:"
echo "   tar xzf $BUNDLE_NAME"
echo "   cd MiragePot/"
echo ""
echo "3. Load Docker images:"
echo "   docker load -i $IMAGES_TAR"
echo ""
echo "4. Restore Ollama models:"
echo "   docker volume create ollama"
echo "   docker run --rm -v ollama:/ollama -v \$(pwd):/backup \\"
echo "     alpine tar xzf /backup/$MODELS_TAR -C /ollama"
echo ""
echo "5. Deploy:"
echo "   cp .env.docker.example .env.docker"
echo "   cd docker/ && docker compose up -d"
echo ""
echo "See docs/OFFLINE_DEPLOYMENT.md for complete instructions."
echo ""
