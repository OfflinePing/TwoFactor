FROM golang:1.21.1-bookworm

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build .

EXPOSE 2244

# Run the executable
CMD ["./TwoFaktor"]
