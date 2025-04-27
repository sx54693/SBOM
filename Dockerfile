# Use official Python slim image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install all system dependencies, apktool, aapt, curl, syft in one go
RUN apt-get update && apt-get install -y \
    openjdk-17-jre-headless \
    wget \
    unzip \
    p7zip-full \
    git \
    curl \
    aapt \
    && wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool \
    && wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.11.1.jar -O /usr/local/bin/apktool.jar \
    && chmod +x /usr/local/bin/apktool \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY app.py . 
COPY sbom_generator.py .
COPY sbom_parser.py .
COPY sbom_compare.py .
COPY sbom_search.py .
COPY sbom_security.py .
COPY features.py .
COPY platform_utils.py .
COPY sbom_report.py .
COPY sbom_parser.py .
COPY sbom_format_handler.py .

# Expose Streamlit port
EXPOSE 8501

# Default command to run the app
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
