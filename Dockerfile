
FROM mcr.microsoft.com/playwright/python:v1.56.1-jammy

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libgtk-4-1 \
    libavif13 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY . .

# Make startup script executable
RUN chmod +x start.sh

# Install Playwright browsers
RUN python -m playwright install

# Use Render's PORT environment variable
ENV PORT=10000

EXPOSE 10000

# Use the startup script for better error handling
CMD ["./start.sh"]