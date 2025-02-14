package encryptfileprovider

import (
	"encoding/base64"
	"path"
	"testing"
)

// 从 encrypted_config.txt 文件中获取的密文
const ciphertext = "GepxAYGKDlOBSpKr3WENIi2Kxkn8sPq6qckP2Xl5DBIuIWC3BvY5aov2sGEHfv33yD+JyL/rlVCeBOa40YuHVZXiQWPAuo4GuSF6+OdyIZpujxDOrWpQk6hKp+b3v6k7KIfC2G0yTlT7k3tzmgPUfIWn7IZcye5qx6ZIzGw="

// 测试 GenerateAESKeyAndIV 方法
func TestGenerateAESKeyAndIV(t *testing.T) {
	key, iv := GenerateAESKeyAndIV(32, 12)

	// 预期密钥长度 (Base64 编码后的长度通常为 44 字节)
	if len(key) != 44 {
		t.Errorf("密钥长度不正确，预期 44，实际 %d", len(key))
	}

	// 预期 IV 长度 (Base64 编码后的长度通常为 16 字节)
	if len(iv) != 16 {
		t.Errorf("IV 长度不正确，预期 16，实际 %d", len(iv))
	}

	t.Logf("生成的密钥: %s", key)
	t.Logf("生成的 IV: %s", iv)

	decodedKey, _ := base64.StdEncoding.DecodeString(key)
	decodedIV, _ := base64.StdEncoding.DecodeString(iv)

	t.Logf("解码后的密钥长度: %d", len(decodedKey))
	t.Logf("解码后的 IV长度: %d", len(decodedIV))
}

// 测试密文解密成明文
func TestDecryptWithString(t *testing.T) {
	crypto, err := NewConfigCrypto(fixedKey, fixedIV)
	if err != nil {
		t.Errorf("初始化失败: %v", err)
	}
	decryptString, err := crypto.DecryptWithString(ciphertext)
	if err != nil {
		t.Errorf("解密失败: %v", err)
	}
	t.Logf("解密后的字符串: \n%s", decryptString)
}

// 测试全流程 读取原始配置文件 ===> 加密写入文件 ===> 读取加密文件 ===> 解密写入临时文件
func TestAllFlow(t *testing.T) {
	crypto, err := NewConfigCrypto(fixedKey, fixedIV)
	if err != nil {
		t.Errorf("初始化失败: %v", err)
	}
	configContent, err := crypto.EncryptWithConfigPathWriteFile(path.Join(baseTempDir, plaintextConfigName))
	if err != nil {
		t.Errorf("加密失败: %v", err)
	}
	t.Logf("加密后的文件内容: %s", configContent)
	decryptPath, err := crypto.DecryptWithStringDataWriteFile(configContent)
	if err != nil {
		t.Errorf("解密失败: %v", err)
	}
	t.Logf("解密后的临时文件路径: %s", decryptPath)

}
