# synthwerk-studio for the local stack (compose profile "studio"). synthwerk-studio
# publishes no image yet, so this builds a checkout of it: the build context "src"
# is SYNTHWERK_STUDIO_SRC (default ../synthwerk-studio, next to this repo).
#   docker compose --profile studio up --build --wait
FROM node:24-alpine3.24@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS build
WORKDIR /src
RUN corepack enable
COPY --from=src package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY --from=src vendor/ vendor/
# postinstall runs "nuxt prepare", which needs the sources: install without scripts first.
RUN pnpm install --frozen-lockfile --ignore-scripts
# Named directories only: a local checkout may hold node_modules, .nuxt or .env.
COPY --from=src nuxt.config.ts tsconfig.json ./
# tsconfig.json references tests/tsconfig.json; the tests themselves are not copied.
COPY --from=src tests/tsconfig.json tests/
COPY --from=src app/ app/
COPY --from=src assets/ assets/
COPY --from=src server/ server/
COPY --from=src shared/ shared/
RUN pnpm install --frozen-lockfile --offline && pnpm build

FROM node:24-alpine3.24@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85
WORKDIR /app
COPY --from=build /src/.output/ .output/
COPY start.mjs ./
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["node", "/app/start.mjs"]
