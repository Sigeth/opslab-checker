FROM docker.io/library/golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
COPY pkg pkg
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /checker ./cmd/checker

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /checker /checker
USER 65532:65532
ENTRYPOINT ["/checker"]
