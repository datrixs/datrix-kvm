* 加密密命令

```
zip -q -r -P Datrixinfo$!2023! RCC-PiKVMD-BOX.zip rcc-pikvmd-box-base.tar.gz
```

编译
```
GOOS=linux GOARCH=arm64 GOARM=7 go build -o AutoUpgrade main.go
```
