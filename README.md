# imi

爱密

## 密钥 $ imi-key

```bash
$ imi-key i
imi-key(i) == DB...

$ imi-key "带有 空格"
imi-key(带有 空格) == 81...
```

## 密码 $ imi-pass

```bash
$ imi-pass "abc.net"
imi-pass(abc.net) == Do...

$ imi-pass "带有 空格"
imi-pass(带有 空格) == bY...
```

## 密文 $ imi-text

```bash
$ imi-text "this is a test"
ABC123...
//每次加密各不相同（避免多次重复，痕迹被人追踪）
$ imi-text ABC123...
this is a test

进阶：
$ imi-text ~/原件.jpg > ~/密文.txt
$ imi-text ~/密文.txt > ~/原件.jpg

$ imi-text ~/原件.md > ~/密文.txt
$ imi-text ~/密文.txt > ~/原件.md
```

## 编译

```bash
Mac下编译Mac平台的可执行程序:
$ go build -ldflags "-s -w" imi-key.go
$ go build -ldflags "-s -w" imi-pass.go
$ go build -ldflags "-s -w" imi-text.go

$ mv ./imi-key ./imi-text ./imi-pass bin/Mac
```

#### 交叉编译

GOOS指定系统内核，GOARCH指定CPU架构。

```bash
Mac下编译Linux平台的64位可执行程序:
$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" imi-key.go
$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" imi-pass.go
$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" imi-text.go

$ mv ./imi-key ./imi-text ./imi-pass bin/Linux
```

```bash
Mac下编译Windows平台的64位可执行程序:
$ CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" imi-key.go
$ CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" imi-pass.go
$ CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" imi-text.go

$ mv ./imi-key.exe ./imi-text.exe ./imi-pass.exe bin/Windows
```
