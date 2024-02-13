GOCC=go

# all: get-deps fmt darwin linux arm windows build coverage
all:
	env GOOS=linux GOARCH=amd64 ${GOCC} build -ldflags="-s -w" -o ../binaries/dm-cmd_linux_amd64 main.go
	env GOOS=linux GOARCH=arm64 ${GOCC} build -ldflags="-s -w" -o ../binaries/dm-cmd_linux_arm64 main.go
	env GOOS=linux GOARCH=386 ${GOCC} build -ldflags="-s -w" -o ../binaries/dm-cmd_linux_386 main.go
	env GOOS=darwin GOARCH=amd64 ${GOCC} build -ldflags="-s -w" -o ../binaries/dm-cmd_darwin_amd64 main.go
	env GOOS=darwin GOARCH=arm64 ${GOCC} build -ldflags="-s -w" -o ../binaries/dm-cm_darwin_arm64 main.go
	env GOOS=windows GOARCH=amd64 ${GOCC} build -ldflags="-s -w" -o ../binaries/dm-cmd_windows_amd64.exe main.go
	env GOOS=windows GOARCH=386 ${GOCC} build -ldflags="-s -w" -o ../binaries/dm-cmd_windows_386.exe main.go

clean:
	rm -rf ../binaries

build:
	${GOCC} build -o ../binaries/dm

