FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY bin ./bin
COPY src ./src
RUN mkdir -p /app/logs /app/config && chown -R node:node /app/logs

USER node
EXPOSE 8080
VOLUME ["/app/logs"]
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["node", "bin/hmac-guard.js"]
CMD ["serve", "--config", "/app/config/guard.config.json"]
