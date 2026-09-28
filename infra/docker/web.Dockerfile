# syntax=docker/dockerfile:1.7
# dfirbench web UI: build with Node, serve static files with unprivileged nginx which also
# reverse-proxies /api to the API service. Build context: frontend/; extra context "infra": infra/docker/

FROM node:24-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.28-alpine AS runtime
COPY --from=infra nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=12 \
  CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
