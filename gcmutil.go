package encryptfileprovider

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

// ConfigCrypto 处理配置文件加密解密的结构体
type ConfigCrypto struct {
	Key                []byte // key
	GcmIV              []byte // 偏移量
	OriginalConfigPath string // 原始配置文件路径
	EncryptConfigPath  string // 加密配置文件路径
	DecryptConfigPath  string // 解密配置文件路径
}

type ConfigParam struct {
	Key                string // key
	GcmIV              string // 偏移量
	OriginalConfigPath string // 原始配置文件路径
	EncryptConfigPath  string // 加密配置文件路径
	DecryptConfigPath  string // 解密配置文件路径
}

var (
	fixedKey   = []byte("qkDvBfQVKgcaePgsjX2hBYOjS8ZZMgRfRR8Llo7E1Sg=") // 固定的密钥 (16, 24 或 32 字节) 这边是 32 字节 (AES-256)
	fixedGcmIV = []byte("GepxAYGKDlOBSpKr")                             // 固定的 IV (GCM 需要 12 字节)
)

// NewConfigCrypto 创建新的 ConfigCrypto 实例
func NewConfigCrypto(config *ConfigParam) *ConfigCrypto {

	key, _ := DecodeBase64(string(fixedKey))
	gcmIV, _ := DecodeBase64(string(fixedGcmIV))

	// 如果配置了key和iv进行替换
	if config.Key != "" && config.GcmIV != "" {
		key, _ = DecodeBase64(config.Key)
		gcmIV, _ = DecodeBase64(config.GcmIV)
	}
	return &ConfigCrypto{
		Key:                key,
		GcmIV:              gcmIV,
		OriginalConfigPath: config.OriginalConfigPath,
		EncryptConfigPath:  config.EncryptConfigPath,
		DecryptConfigPath:  config.DecryptConfigPath,
	}
}

// EncryptWithConfigPath 加密配置文件 文件路径 ===> 加密字符串
func (c *ConfigCrypto) EncryptWithConfigPath(configPath string) (string, error) {
	// 读取配置文件
	plaintext, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("读取配置文件失败: %v", err)
	}

	return c.EncryptWithString(string(plaintext))
}

// EncryptWithConfigPathWriteFile 加密配置文件 文件路径 ===> 写入加密文件
func (c *ConfigCrypto) EncryptWithConfigPathWriteFile(originalConfigPath, encryptConfigPath string) (string, error) {
	if originalConfigPath == "" || encryptConfigPath == "" {
		return "", fmt.Errorf("原始配置文件路径和加密配置文件路径不能为空")
	}
	ciphertext, err := c.EncryptWithConfigPath(originalConfigPath)
	if err != nil {
		return "", fmt.Errorf("加密失败: %v", err)
	}
	// 将加密内容写入文件
	err = os.WriteFile(encryptConfigPath, []byte(ciphertext), 0644)
	if err != nil {
		log.Fatalf("写入加密文件失败: %v", err)
	}
	log.Printf("加密内容已写入: %s", encryptConfigPath)

	return ciphertext, nil
}

// EncryptWithString 加密字符串 明文字符串 ===> 加密字符串
func (c *ConfigCrypto) EncryptWithString(plaintext string) (string, error) {
	encrypted, err := c.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return EncodeBase64(encrypted), nil
}

// EncryptWithByte 加密字符串 明文字节 ===> 加密字节
func (c *ConfigCrypto) EncryptWithByte(plaintext []byte) ([]byte, error) {
	return c.Encrypt(plaintext)
}

// Encrypt 通用加密方法
func (c *ConfigCrypto) Encrypt(plaintext []byte) ([]byte, error) {

	// 创建加密器
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, fmt.Errorf("创建cipher失败: %v", err)
	}

	// 创建GCM加密器
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %v", err)
	}

	// 加密
	ciphertext := gcm.Seal(nil, c.GcmIV, plaintext, nil)

	// 组合IV和密文
	return append(c.GcmIV, ciphertext...), nil
}

// DecryptWithStringDataWriteFile 解密配置文件并保存到文件
func (c *ConfigCrypto) DecryptWithStringDataWriteFile(encryptedData, decryptConfigPath string) (string, error) {
	if decryptConfigPath == "" {
		return "", fmt.Errorf("解密配置文件路径不能为空")
	}
	decodeEncryptedData, err := DecodeBase64(encryptedData)
	if err != nil {
		return "", fmt.Errorf("base64 解码失败: %v", err)
	}
	// 调用通用解密方法
	plaintext, err := c.Decrypt(decodeEncryptedData)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(decryptConfigPath, plaintext, 0600); err != nil {
		return "", fmt.Errorf("写入临时文件失败: %w", err)
	}

	return decryptConfigPath, nil
}

// DecryptWithString 解密 Base64 编码的加密字符串，返回明文字符串
func (c *ConfigCrypto) DecryptWithString(encryptedData string) (string, error) {
	// Base64 解码
	decodedData, err := DecodeBase64(encryptedData)
	if err != nil {
		return "", fmt.Errorf("base64 解码失败: %w", err)
	}

	// 调用通用解密方法
	plaintext, err := c.Decrypt(decodedData)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// DecryptWithByte 解密字节数据
func (c *ConfigCrypto) DecryptWithByte(encryptedData []byte) ([]byte, error) {
	return c.Decrypt(encryptedData)
}

// Decrypt 通用解密方法
func (c *ConfigCrypto) Decrypt(encryptedData []byte) ([]byte, error) {
	// 创建解密器
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}

	// 解析 IV 和密文
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("加密数据长度不足")
	}
	iv, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// 解密
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}

	return plaintext, nil
}

// GenerateRandomBytes 生成指定字节长度的随机数据
func GenerateRandomBytes(length int) []byte {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatalf("生成随机字节失败: %v", err)
	}
	return bytes
}

// EncodeBase64 Base64 编码
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 Base64 解码
func DecodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// GenerateAESKeyAndIV 生成 Base64 编码的 AES 密钥和 IV
func GenerateAESKeyAndIV(keyLength, ivLength int) (string, string) {
	key := EncodeBase64(GenerateRandomBytes(keyLength)) // 32 字节密钥 (AES-256)
	iv := EncodeBase64(GenerateRandomBytes(ivLength))   // 12 字节 IV (GCM)
	return key, iv
}
