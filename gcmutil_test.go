package encryptfileprovider

import (
	"encoding/base64"
	"path"
	"testing"
)

const (
	baseTempDir          = "/Users/tianlanxu/Documents/staryea/encryptfileprovider/testdata/gcmutil"
	plaintextConfigName  = "config.yaml"          // 明文文件名
	ciphertextConfigName = "encrypted_config.txt" // 密文文件名
	restoreConfigName    = "config_restore.yaml"  // 还原文件名
)

// 从 encrypted_config.txt 文件中获取的密文
const ciphertext = "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"

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
	crypto := NewConfigCrypto(&ConfigParam{})
	decryptString, err := crypto.DecryptWithString(ciphertext)
	if err != nil {
		t.Errorf("解密失败: %v", err)
	}
	t.Logf("解密后的字符串: \n%s", decryptString)
}

// 测试密文解密成明文
func TestDecryptWithNewKey(t *testing.T) {
	crypto := NewConfigCrypto(&ConfigParam{
		Key:   "fw8S6dnk6zgwCWELyLjxQH0kn5ILDiGkFW30IoRipEY=",
		GcmIV: "vGIodz9R+G2f8nQR",
	})
	encryptString, err := crypto.EncryptWithString("123abc")
	t.Logf("加密后的字符串: \n%s", encryptString) // vGIodz9R+G2f8nQRIRjcLU9ZZ9/HZWKqnYETd67VEPV9kA==
	decryptString, err := crypto.DecryptWithString(encryptString)
	if err != nil {
		t.Errorf("解密失败: %v", err)
	}
	t.Logf("解密后的字符串: \n%s", decryptString)
}

// 测试全流程 读取原始配置文件 ===> 加密写入文件 ===> 读取加密文件 ===> 解密写入临时文件
func TestAllFlow(t *testing.T) {
	crypto := NewConfigCrypto(&ConfigParam{
		OriginalConfigPath: path.Join(baseTempDir, plaintextConfigName),
		EncryptConfigPath:  path.Join(baseTempDir, ciphertextConfigName),
		DecryptConfigPath:  path.Join(baseTempDir, restoreConfigName),
	})
	configContent, err := crypto.EncryptWithConfigPathWriteFile(crypto.OriginalConfigPath, crypto.EncryptConfigPath)
	if err != nil {
		t.Errorf("加密失败: %v", err)
	}
	t.Logf("加密后的文件内容: %s", configContent)
	decryptPath, err := crypto.DecryptWithStringDataWriteFile(configContent, crypto.DecryptConfigPath)
	if err != nil {
		t.Errorf("解密失败: %v", err)
	}
	t.Logf("解密后的临时文件路径: %s", decryptPath)

}
