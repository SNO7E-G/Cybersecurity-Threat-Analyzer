FROM python:3.9-slim

LABEL maintainer="Mahmoud Ashraf (SNO7E)"
LABEL version="2.0.0"
LABEL description="Cybersecurity Threat Analyzer - Advanced network security monitoring"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV LANG C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    netcat \
    tcpdump \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create non-root user
RUN groupadd -r cta && useradd -r -g cta cta
RUN chown -R cta:cta /app
USER cta

# Set entrypoint
ENTRYPOINT ["python", "manage.py"]
CMD ["runserver", "0.0.0.0:8000"]

# Expose port
EXPOSE 8000 