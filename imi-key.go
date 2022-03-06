//密钥
//只可修复问题 不可更改算法

//$ go build -ldflags "-s -w" imi-key.go

//使用方法及算法前缀校对
//$ imi-key i
//imi-key(i) == DB...

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"strings"
)

func main() {
	user, _ := user.Current()
	path := []byte(user.HomeDir + "/.imi-key")
	saltCiphertext := getUserSaltCiphertext(path)

	if len(saltCiphertext) == 0 {
		saltCiphertext = salt2ciphertext(makeSalt())
		saveUserSaltCiphertext(path, saltCiphertext)
	}

	salt := ciphertext2salt(saltCiphertext)
	//fmt.Printf("%#v\n", hashSha256(string(salt))[0:2])
	//fmt.Printf("%#v\n", saltSha256Two)
	if hashSha256(string(salt))[0:2] != saltSha256Two {
		//可能由于网卡Mac地址变更，造成 salt 不再正确，重新生成一次
		saltCiphertext = salt2ciphertext(makeSalt())
		saveUserSaltCiphertext(path, saltCiphertext)
		salt = ciphertext2salt(saltCiphertext)
	}

	if hashSha256(string(salt))[0:2] == saltSha256Two { //salt正确
		if len(os.Args) == 2 {
			s := string(salt)
			c := os.Args[1]
			if len(c) > 0 {
				r := strings.ToUpper(hashSha256(s + c))
				fmt.Printf("imi-key(%s) == %s\n", c, r)
			}
		}
	}
}

const saltSha256Two = "2c"

//生成盐
func makeSalt() (salt []byte) {
	/**
	 * 九个问题：
	 *
	 * 老太爷四个字？
	 * 你字辈的深意？
	 * 你名字的使命？
	 *
	 * 自悟自觉自醒？
	 * 利国利民利己？
	 * 八字终极奥义？
	 *
	 * 不是这种功夫？
	 * 君子中的君子？
	 * 看了不要后悔？
	 **/

	fmt.Printf("九个问题：\n\n")

	var q1 string //question 1
	fmt.Printf("老太爷四个字？\n")
	scanf(&q1)

	var q2 string
	fmt.Printf("你字辈的深意？\n")
	scanf(&q2)

	var q3 string
	fmt.Printf("你名字的使命？\n")
	scanf(&q3)

	var q4 string
	fmt.Printf("自悟自觉自醒？\n")
	scanf(&q4)

	var q5 string
	fmt.Printf("利国利民利己？\n")
	scanf(&q5)

	var q6 string
	fmt.Printf("八字终极奥义？\n")
	scanf(&q6)

	var q7 string
	fmt.Printf("君子中的君子？\n")
	scanf(&q7)

	var q8 string
	fmt.Printf("不是这种功夫？\n")
	scanf(&q8)

	var q9 string
	fmt.Printf("看了不要后悔？\n")
	scanf(&q9)

	salt = []byte(hashSha256(q1 + q2 + q3 + q4 + q5 + q6 + q7 + q8 + q9))
	//fmt.Printf("saltSha256Two 取值？ %s\n", hashSha256(string(salt))[0:16])

	//不正确
	if hashSha256(string(salt))[0:2] != saltSha256Two {
		salt = nil
	}

	return
}

//获取机器的首个网卡的mac地址
func getMacAddrFirst() (mac []byte) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, netInterface := range netInterfaces {
		mac = []byte(netInterface.HardwareAddr.String())
		if len(mac) != 0 {
			break
		}
	}
	return
}

//从用户文件中获得盐的密文
func getUserSaltCiphertext(path []byte) (text []byte) {
	f, _ := os.OpenFile(string(path), os.O_RDONLY, 0600)
	defer f.Close()

	text, _ = ioutil.ReadAll(f)
	return
}

//将盐的密文保存用户文件中
func saveUserSaltCiphertext(path, text []byte) {
	f, _ := os.OpenFile(string(path), os.O_CREATE|os.O_WRONLY, 0600)
	defer f.Close()

	_, _ = f.Write(text)
	return
}

//加密盐
func salt2ciphertext(salt []byte) (text []byte) {
	hash := []byte(hashSha256(saltSha256Two + string(getMacAddrFirst())))

	key := hash[:32] //AES-256-CBC
	iv := hash[32:48]

	text = aescbcEncrypt(salt, key, iv)
	return
}

//解密盐
func ciphertext2salt(text []byte) (salt []byte) {
	hash := []byte(hashSha256(saltSha256Two + string(getMacAddrFirst())))

	key := hash[:32] //AES-256-CBC
	iv := hash[32:48]

	salt = aescbcDecrypt(text, key, iv)

	//不正确
	if hashSha256(string(salt))[0:2] != saltSha256Two {
		salt = nil
	}
	return
}

//获得整行输入
func scanf(a *string) {
	reader := bufio.NewReader(os.Stdin)
	data, _, _ := reader.ReadLine()
	*a = string(data)
}

//sha256加密
func hashSha256(str string) string {
	hashSha256 := sha256.New()
	hashSha256.Write([]byte(str))
	result := hex.EncodeToString(hashSha256.Sum(nil))

	return result
}

// golang 实现 AES-128-CBC AES-192-CBC AES-256-CBC 加密解密算法
// key 16 位就是 AES-128-CBC ； key 24 位就是 AES-192-CBC ； key 32 位就是 AES-256-CBC
// iv 固定长度 16 位

func aescbcEncrypt(sourced []byte, key []byte, iv []byte) []byte {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	sourced = aescbcPkcs7Padding(sourced, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(sourced))
	blockMode.CryptBlocks(crypted, sourced)
	return []byte(strings.ToUpper(aescbcBin2hex(string(crypted))))
}
func aescbcDecrypt(crypted []byte, key []byte, iv []byte) []byte {
	crypted = []byte(aescbcHex2bin(string(crypted)))
	block, _ := aes.NewCipher(key)
	blockMode := cipher.NewCBCDecrypter(block, iv)
	sourced := make([]byte, len(crypted))
	blockMode.CryptBlocks(sourced, crypted)
	sourced = aescbcPkcs7UnPadding(sourced)
	return sourced
}

func aescbcPkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
func aescbcPkcs7UnPadding(sourced []byte) []byte {
	length := len(sourced)
	unpadding := int(sourced[length-1])
	if length-unpadding < 0 { //避免出错：panic: runtime error: slice bounds out of range
		return []byte{}
	}
	return sourced[:(length - unpadding)]
}

func aescbcBin2hex(raw string) string {
	return hex.EncodeToString([]byte(raw))
}
func aescbcHex2bin(raw string) string {
	result, _ := hex.DecodeString(raw)
	return string(result)
}
