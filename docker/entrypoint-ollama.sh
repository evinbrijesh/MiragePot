#!/bin/bash
set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 MiragePot AI Engine - Initializing"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

MODEL="${OLLAMA_MODEL:-phi3}"

# Function to ensure model is available (runs in background)
ensure_model() {
    # Wait for server to be ready
    while ! curl -sf http://localhost:11434/ >/dev/null 2>&1; do
        sleep 1
    done
    
    echo "🔍 Checking for AI model: $MODEL"
    
    if ollama list 2>/dev/null | grep -q "$MODEL"; then
        echo "✅ Model '$MODEL' found in cache!"
        # Pre-warm the model by loading it into memory
        echo "🔥 Pre-warming model..."
        curl -sf http://localhost:11434/api/generate -d "{\"model\":\"$MODEL\",\"prompt\":\"hi\",\"stream\":false}" >/dev/null 2>&1 || true
        echo "✅ Model ready!"
    else
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📥 First-Time Setup: Downloading AI Model"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "   Model: $MODEL (~2GB)"
        echo "   ☕ This only happens once!"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if ollama pull "$MODEL"; then
            echo "✅ Model downloaded successfully!"
        else
            echo "❌ Failed to download model!"
        fi
    fi
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ AI Engine Ready"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Start model check in background so server starts immediately
ensure_model &

# Start Ollama server in foreground (this makes container healthy faster)
echo "📡 Starting Ollama server..."
exec ollama serve
