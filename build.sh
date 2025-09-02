set -e
VER=0.1.0
podman build -t ollama-proxy:$VER --build-arg VER=$VER .
podman push ollama-proxy:$VER docker.io/glvx/ollama-proxy:$VER
podman push ollama-proxy:$VER docker.io/glvx/ollama-proxy:latest
