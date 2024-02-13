GOCC=go

# all: get-deps fmt darwin linux arm windows build coverage
all:
	env GOOS=linux GOARCH=amd64 ${GOCC} build -o ../binaries/linux_amd64/dm-cmd main.go
	env GOOS=linux GOARCH=arm64 ${GOCC} build -o ../binaries/linux_arm64/dm-cmd main.go
	env GOOS=linux GOARCH=386 ${GOCC} build -o ../binaries/linux_386/dm-cmd main.go
	env GOOS=darwin GOARCH=amd64 ${GOCC} build -o ../binaries/darwin_amd64/dm-cmd main.go
	env GOOS=darwin GOARCH=arm64 ${GOCC} build -o ../binaries/darwin_arm64/dm-cmd main.go
	env GOOS=windows GOARCH=amd64 ${GOCC} build -o ../binaries/windows_amd64/dm-cmd.exe main.go
	env GOOS=windows GOARCH=386 ${GOCC} build -o ../binaries/windows_386/dm-cmd.exe main.go

clean:
	rm -rf ../binaries

build:
	${GOCC} build -o ../binaries/dm

