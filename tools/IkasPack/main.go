package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
)

const (
	unzip_password = "datrix2023"
)

var password string
var filePath string
var outPath string
var excCommand string

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) <= 0 {
		return
	}

	switch args[0] {
	case "pack":
		execCmd := flag.NewFlagSet("pack", flag.ExitOnError)
		execCmd.StringVar(&password, "P", "Datrix@Info!2023#$", "密码")
		execCmd.StringVar(&filePath, "file", "", "待压缩的文件或文件夹路径")
		execCmd.StringVar(&outPath, "o", "RccKVMD.zip", "输出文件名称")
		_ = execCmd.Parse(args[1:])

		log.Printf("Start to pack %s", filePath)
		if len(password) == 0 {
			password = unzip_password
		}
		cmd := exec.Command("zip", "-rP", password, outPath, filePath)
		out, err := cmd.CombinedOutput()
		log.Printf("Pack Output: \n%s\n", string(out))
		if err != nil {
			log.Fatalf("Pack failed with %s", err)
			os.Exit(1)
		}
		log.Printf("Pack %s Successfully, Package name: %s", filePath, outPath)

	case "unpack":
		execCmd := flag.NewFlagSet("unpack", flag.ExitOnError)
		execCmd.StringVar(&password, "P", "Datrix@Info!2023#$", "密码")
		execCmd.StringVar(&filePath, "file", "", "待解压的文件路径")
		execCmd.StringVar(&outPath, "o", "/root", "解压输出路径")
		_ = execCmd.Parse(args[1:])

		if len(filePath) == 0 {
			log.Fatalf("The package path must be specified")
			os.Exit(2)
		}

		log.Printf("Start to unpack %s", filePath)
		if len(password) == 0 {
			password = unzip_password
		}
		if len(outPath) == 0 {
			outPath = "/root"
		}
		cmd := exec.Command("unzip", "-P", password, filePath, "-d", outPath)
		out, err := cmd.CombinedOutput()
		log.Printf("Unpack Out: %s", string(out))
		if err != nil {
			log.Fatalf("\nUnpack %s failed, Error Out: %s", filePath, err)
			os.Exit(1)
		}
		log.Printf("Unpack %s successfully...", filePath)
	}
}
