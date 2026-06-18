FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep for extra scanning coverage
RUN pip install --no-cache-dir semgrep

# Set work directory
WORKDIR /workspace

# Copy codebase and install
COPY . /app
RUN pip install --no-cache-dir /app

# Set default entrypoint
ENTRYPOINT ["phoenixsec"]
CMD ["--help"]
