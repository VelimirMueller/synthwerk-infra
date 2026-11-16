# synthwerk-zitadel-bootstrap: sets up the Zitadel instance as code (one-shot).
# Build context: the repo root (go.mod lives there).
FROM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY zitadel/ zitadel/
COPY cmd/zitadel-bootstrap/ cmd/zitadel-bootstrap/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/zitadel-bootstrap ./cmd/zitadel-bootstrap

FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087
COPY --from=build /out/zitadel-bootstrap /zitadel-bootstrap
USER nonroot:nonroot
ENTRYPOINT ["/zitadel-bootstrap"]
