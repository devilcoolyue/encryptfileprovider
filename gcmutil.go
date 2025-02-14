package encryptfileprovider

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"time"
)

// ConfigCrypto 处理配置文件加密解密的结构体
type ConfigCrypto struct {
	key     []byte
	gcmIV   []byte
	tempDir string
}

var (
	fixedKey = []byte("qkDvBfQVKgcaePgsjX2hBYOjS8ZZMgRfRR8Llo7E1Sg=") // 固定的密钥 (16, 24 或 32 字节) 这边是 32 字节 (AES-256)
	fixedIV  = []byte("GepxAYGKDlOBSpKr")                             // 固定的 IV (GCM 需要 12 字节)
)

const (
	baseTempDir          = "/Users/tianlanxu/GolandProjects/awesomeProject2/encrypted"
	plaintextConfigName  = "config.yaml"          // 明文文件名
	ciphertextConfigName = "encrypted_config.txt" // 密文文件名
)

// NewConfigCrypto 创建新的 ConfigCrypto 实例
func NewConfigCrypto(fixedKey, fixedIV []byte) (*ConfigCrypto, error) {
	key, err := decodeBase64(string(fixedKey))
	if err != nil {
		return nil, fmt.Errorf("解码密钥失败: %v", err)
	}
	gcmIV, err := decodeBase64(string(fixedIV))
	if err != nil {
		return nil, fmt.Errorf("解码IV失败: %v", err)
	}
	return &ConfigCrypto{
		key:     key,
		gcmIV:   gcmIV,
		tempDir: baseTempDir,
	}, nil
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
func (c *ConfigCrypto) EncryptWithConfigPathWriteFile(configPath string) (string, error) {
	ciphertext, err := c.EncryptWithConfigPath(configPath)
	if err != nil {
		return "", fmt.Errorf("加密失败: %v", err)
	}
	// 将加密内容写入文件
	encryptedFilePath := path.Join(baseTempDir, ciphertextConfigName)
	err = os.WriteFile(encryptedFilePath, []byte(ciphertext), 0644)
	if err != nil {
		log.Fatalf("写入加密文件失败: %v", err)
	}
	log.Printf("加密内容已写入: %s", encryptedFilePath)

	return ciphertext, nil
}

// EncryptWithString 加密字符串 明文字符串 ===> 加密字符串
func (c *ConfigCrypto) EncryptWithString(plaintext string) (string, error) {
	encrypted, err := c.encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return encodeBase64(encrypted), nil
}

// EncryptWithByte 加密字符串 明文字节 ===> 加密字节
func (c *ConfigCrypto) EncryptWithByte(plaintext []byte) ([]byte, error) {
	return c.encrypt(plaintext)
}

// encrypt 通用加密方法
func (c *ConfigCrypto) encrypt(plaintext []byte) ([]byte, error) {

	// 创建加密器
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("创建cipher失败: %v", err)
	}

	// 创建GCM加密器
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %v", err)
	}

	// 加密
	ciphertext := gcm.Seal(nil, c.gcmIV, plaintext, nil)

	// 组合IV和密文
	return append(c.gcmIV, ciphertext...), nil
}

// DecryptWithStringDataWriteFile 解密配置文件并保存到文件
func (c *ConfigCrypto) DecryptWithStringDataWriteFile(encryptedData string) (string, error) {
	decodeEncryptedData, err := decodeBase64(encryptedData)
	if err != nil {
		return "", fmt.Errorf("base64 解码失败: %v", err)
	}
	// 调用通用解密方法
	plaintext, err := c.decrypt(decodeEncryptedData)
	if err != nil {
		return "", err
	}
	// 创建文件
	tempFile := filepath.Join(c.tempDir, fmt.Sprintf("config_%d.yaml", time.Now().UnixNano()))
	if err := os.WriteFile(tempFile, plaintext, 0600); err != nil {
		return "", fmt.Errorf("写入临时文件失败: %w", err)
	}

	return tempFile, nil
}

// DecryptWithString 解密 Base64 编码的加密字符串，返回明文字符串
func (c *ConfigCrypto) DecryptWithString(encryptedData string) (string, error) {
	// Base64 解码
	decodedData, err := decodeBase64(encryptedData)
	if err != nil {
		return "", fmt.Errorf("base64 解码失败: %w", err)
	}

	// 调用通用解密方法
	plaintext, err := c.decrypt(decodedData)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// DecryptWithByte 解密字节数据
func (c *ConfigCrypto) DecryptWithByte(encryptedData []byte) ([]byte, error) {
	return c.decrypt(encryptedData)
}

// 通用解密方法
func (c *ConfigCrypto) decrypt(encryptedData []byte) ([]byte, error) {
	// 创建解密器
	block, err := aes.NewCipher(c.key)
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

// 生成指定字节长度的随机数据
func generateRandomBytes(length int) []byte {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatalf("生成随机字节失败: %v", err)
	}
	return bytes
}

// Base64 编码
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64 解码
func decodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// GenerateAESKeyAndIV 生成 Base64 编码的 AES 密钥和 IV
func GenerateAESKeyAndIV(keyLength, ivLength int) (string, string) {
	key := encodeBase64(generateRandomBytes(keyLength)) // 32 字节密钥 (AES-256)
	iv := encodeBase64(generateRandomBytes(ivLength))   // 12 字节 IV (GCM)
	return key, iv
}
