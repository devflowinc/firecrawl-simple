FROM node:18-slim

# Install system dependencies for Playwright/Chromium (ARM64 compatible)
RUN apt-get update && \
    apt-get install -y \
    chromium \
    fonts-ipafont-gothic \
    fonts-wqy-zenhei \
    fonts-thai-tlwg \
    fonts-kacst \
    fonts-noto \
    fonts-freefont-ttf \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install pnpm globally
RUN npm install -g pnpm

# Copy package files
COPY ./package.json ./pnpm-lock.yaml ./

# Install dependencies
RUN pnpm install --frozen-lockfile

# Copy the rest of the application
COPY . .

# Tell Playwright to use system Chromium instead of downloading
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

# Build the application
RUN pnpm run build

# Set up environment
ARG PORT=3000
ENV PORT=${PORT}

EXPOSE ${PORT}

CMD ["pnpm", "start"]
