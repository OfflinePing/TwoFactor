FROM golang:1.21.1-bookworm

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o main .

EXPOSE 2244

# Run the executable
CMD ["./app/main"]
