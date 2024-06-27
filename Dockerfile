FROM golang:1.18 as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o server .
FROM gcr.io/distroless/base-debian10
WORKDIR /
COPY --from=builder /app/server /server
EXPOSE 8080
CMD ["/server"]
