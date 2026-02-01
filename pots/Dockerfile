FROM python:3.11-slim

WORKDIR /app

# Copy project files
COPY pyproject.toml ./
COPY main.py ./

# Install uv and dependencies
RUN pip install uv && \
    uv sync

# Expose Flask port
EXPOSE 3000

# Run the server
CMD ["uv", "run", "main.py"]
