FROM node:18-alpine

WORKDIR /app

# Install dependencies
RUN apk add --no-cache \
    git \
    docker \
    nginx

# Install Docker Compose
RUN apk add --no-cache docker-cli-compose

# Copy package files
COPY package*.json ./

# Install Node.js dependencies
RUN npm install --production

# Copy application code
COPY . .

# Create data directories
RUN mkdir -p /data/logs /data/repos /etc/nginx/conf.d

# Expose port
EXPOSE 3000

# Start application
CMD ["npm", "start"]
