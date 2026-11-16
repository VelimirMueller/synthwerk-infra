# synthwerk-waf: Coraza + OWASP CRS v4 as a Traefik forwardAuth check.
# Build context: the repo root (go.mod lives there).
FROM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY waf/ waf/
COPY cmd/waf/ cmd/waf/
# no_fs_access: the container is read-only. Bodies stay in memory (limit = body limit).
RUN CGO_ENABLED=0 go build -tags no_fs_access -trimpath -ldflags="-s -w" -o /out/waf ./cmd/waf

FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087
COPY --from=build /out/waf /waf
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/waf"]
