# synthwerk-zitadel-bootstrap: sets up the Zitadel instance as code (one-shot).
# Build context: the repo root (go.mod lives there).
FROM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
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
