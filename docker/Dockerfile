FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    python3 \
    python3-pip \
    sqlmap \
    nmap \
    nikto \
    gobuster \
    apache2 \
    php \
    mysql-client \
    netcat \
    chromium-browser \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install \
    requests \
    beautifulsoup4 \
    selenium \
    lxml

# Create working directory
WORKDIR /app

# Copy application files
COPY . /app/

# Install application dependencies
RUN pip3 install -r requirements.txt

# Create logs directory
RUN mkdir -p logs

# Expose ports
EXPOSE 80 443 8080

# Set default command
CMD ["python3", "main_pipeline.py"]
