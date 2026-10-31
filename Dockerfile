FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY server.js ./
COPY public ./public
COPY license.json ./
ENV PORT=7860
EXPOSE 7860
CMD ["node", "server.js"]
