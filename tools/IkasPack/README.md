# 工具的编译和使用

## 工具编译成二进制文件

```
go build -o DatrixPack main.go
```

## 工具使用

### 压缩(pack)

```
DatrixPack pack -file=filePath -o=RccKVMD.zip
```

* pack 压缩的选项
* -file 待压缩的文件或文件夹路径
* -o 输出文件名称

### 解压(unpack)

```
DatrixPack unpack -file=RccKVMD.zip -o=/root/tmp
```

* unpack 解压的选项
* -file 待解压的文件路径
* -o 解压输出路径
