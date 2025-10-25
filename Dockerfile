# ---- Build a lean, production image ----
FROM node:22-slim

# Set env early so npm respects it
ENV NODE_ENV=production

# Create app dir
WORKDIR /app

# Install only production deps
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy the rest of the app
COPY . .

# (Optional) run as non-root for better security
RUN useradd -m -u 1001 nodeuser && chown -R nodeuser:nodeuser /app
USER nodeuser

# Your server uses PORT (defaults to 5000). Set & expose it here.
ENV PORT=5000
EXPOSE 5000

# Simple container healthcheck against your /api/health endpoint
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||5000)+'/api/health', r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

# Start the app (package.json should have: "start": "node index.js")
CMD ["npm","start"]
