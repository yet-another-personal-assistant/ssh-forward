FROM sshforward-dev as builder
RUN mkdir -p /app
WORKDIR /app
COPY . ./
RUN make

FROM debian:buster-slim
RUN apt-get update && apt-get install -y libssh-4
RUN mkdir -p /app
COPY --from=builder /app/sshforward .
COPY server.key .
CMD ["./sshforward"]