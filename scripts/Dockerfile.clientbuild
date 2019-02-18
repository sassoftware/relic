FROM golang:latest
RUN wget -q https://github.com/golang/dep/releases/download/v0.4.1/dep-linux-amd64 -O /usr/bin/dep && chmod a+rx /usr/bin/dep

WORKDIR $GOPATH/src/github.com/sassoftware/relic
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure -vendor-only

COPY . .
RUN mkdir /out
ARG ldflags
RUN CGO_ENABLED=0 GOOS=linux   GOARCH=amd64   go build -a -installsuffix nocgo -ldflags "$ldflags" -tags clientonly -o /out/relic-client-linux-amd64
RUN CGO_ENABLED=0 GOOS=linux   GOARCH=arm64   go build -a -installsuffix nocgo -ldflags "$ldflags" -tags clientonly -o /out/relic-client-linux-arm64
RUN CGO_ENABLED=0 GOOS=linux   GOARCH=ppc64le go build -a -installsuffix nocgo -ldflags "$ldflags" -tags clientonly -o /out/relic-client-linux-ppc64le
RUN CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64   go build -a -installsuffix nocgo -ldflags "$ldflags" -tags clientonly -o /out/relic-client-darwin-amd64
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64   go build -a -installsuffix nocgo -ldflags "$ldflags" -tags clientonly -o /out/relic-client-windows-amd64.exe
