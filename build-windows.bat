set CGO_ENABLE=0
set GOOS=windows
set GOARCH=386
go build -o ss-httpd.exe

set GOOS=linux
set GOARCH=386
go build -o ss-httpd