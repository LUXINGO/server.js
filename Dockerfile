# Use Node.js LTS
FROM node:20-alpine

WORKDIR /usr/src/app

# Copy package.json and install dependencies
COPY package*.json ./
RUN npm install --production

# Copy all files
COPY . .

# Expose default port
EXPOSE 3000

# Start backend
CMD ["node", "server.js"]
