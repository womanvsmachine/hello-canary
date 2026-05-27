FROM node:20-alpine
WORKDIR /app
COPY package.json ./
COPY index.js ./
ENV PORT=8080
CMD ["node", "index.js"]