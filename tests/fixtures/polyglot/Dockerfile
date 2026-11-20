# build stage
FROM --platform=$BUILDPLATFORM golang:1.23-bookworm AS build
WORKDIR /src
COPY service/ .
RUN go build -o /out/svc .

FROM eclipse-temurin:21-jre \
    AS runtime
COPY --from=build /out/svc /usr/local/bin/svc

FROM runtime AS final
FROM scratch AS empty
