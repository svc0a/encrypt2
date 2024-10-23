package md5

import (
	"crypto/md5"
	"encoding/hex"
)

type Service interface {
	Encode(string) string
}

func New() Service {
	return &impl{}
}

type impl struct{}

func (i impl) Encode(data string) string {
	hash := md5.New()                        // 创建一个新的MD5 hash对象
	hash.Write([]byte(data))                 // 将数据写入hash对象
	return hex.EncodeToString(hash.Sum(nil)) // 获取加密后的字节并编码为十六进制字符串
}
