#!/bin/bash
set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 MiragePot AI Engine - Initializing"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Start Ollama server in background
echo "📡 Starting Ollama server..."
ollama serve &
OLLAMA_PID=$!

# Wait for server to be ready
echo "⏳ Waiting for Ollama to initialize..."
sleep 10

# Check if model is already downloaded
MODEL="${OLLAMA_MODEL:-phi3}"
echo "🔍 Checking for AI model: $MODEL"

if ollama list | grep -q "$MODEL"; then
    echo "✅ Model '$MODEL' found in cache - ready to go!"
else
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📥 First-Time Setup: Downloading AI Model"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "   Model: $MODEL (~2GB)"
    echo "   Expected time: 2-5 minutes"
    echo "   ☕ Grab a coffee! This only happens once."
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    if ollama pull "$MODEL"; then
        echo ""
        echo "✅ Model downloaded and cached successfully!"
        echo "   Future starts will be instant."
    else
        echo ""
        echo "❌ Failed to download model!"
        echo "   Check your internet connection and try again."
        exit 1
    fi
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ AI Engine Ready"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Keep Ollama running in foreground
wait $OLLAMA_PID
