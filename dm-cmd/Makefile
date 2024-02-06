GOCC=go

# all: get-deps fmt darwin linux arm windows build coverage
all:
	env GOOS=linux GOARCH=amd64 ${GOCC} build -o ./bin/dm_linux_amd64
	env GOOS=linux GOARCH=arm64 ${GOCC} build -o ./bin/dm_linux_arm64
	env GOOS=linux GOARCH=386 ${GOCC} build -o ./bin/dm_linux_386
	env GOOS=darwin GOARCH=amd64 ${GOCC} build -o ./bin/dm_darwin_amd64
	env GOOS=darwin GOARCH=arm64 ${GOCC} build -o ./bin/dm_darwin_arm64
	env GOOS=windows GOARCH=amd64 ${GOCC} build -o ./bin/dm_windows_amd64.exe
	env GOOS=windows GOARCH=386 ${GOCC} build -o ./bin/dm_windows_386.exe

clean:
	rm -rf ./bin 

build:
	${GOCC} build -o ./bin/dm

