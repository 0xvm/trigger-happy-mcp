# Use Python 3.12 slim image
FROM python:3.12-slim

# Workdir inside container
WORKDIR /app

# Optional: system packages if you ever need them (git, bash, etc.)
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     bash curl git && \
#     rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
#COPY requirements.txt .
#RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y --no-install-recommends bash curl git && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir git+https://github.com/mrexodia/zeromcp.git
RUN pip install rich

# Copy server code
COPY server.py .

# Expose MCP HTTP port
EXPOSE 12983

# Run the MCP server
CMD ["python", "server.py"]

