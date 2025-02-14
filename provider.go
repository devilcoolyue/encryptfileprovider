// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package encryptfileprovider // import "go.opentelemetry.io/collector/confmap/provider/fileprovider"

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/collector/confmap"
)

const schemeName = "encryptfile"

type provider struct{}

// NewFactory returns a factory for a confmap.Provider that reads the configuration from a file.
//
// This Provider supports "encryptfile" scheme, and can be called with a "uri" that follows:
//
//	file-uri		= "encryptfile:" local-path
//	local-path		= [ drive-letter ] file-path
//	drive-letter	= ALPHA ":"
//
// The "file-path" can be relative or absolute, and it can be any OS supported format.
//
// Examples:
// `encryptfile:path/to/file` - relative path (unix, windows)
// `encryptfile:/path/to/file` - absolute path (unix, windows)
// `encryptfile:c:/path/to/file` - absolute path including drive-letter (windows)
// `encryptfile:c:\path\to\file` - absolute path including drive-letter (windows)
func NewFactory() confmap.ProviderFactory {
	return confmap.NewProviderFactory(newProvider)
}

func newProvider(confmap.ProviderSettings) confmap.Provider {
	return &provider{}
}

func (fmp *provider) Retrieve(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if !strings.HasPrefix(uri, schemeName+":") {
		return nil, fmt.Errorf("%q uri is not supported by %q provider", uri, schemeName)
	}

	// Clean the path before using it.
	content, err := os.ReadFile(filepath.Clean(uri[len(schemeName)+1:]))
	if err != nil {
		return nil, fmt.Errorf("unable to read the file %v: %w", uri, err)
	}

	// 解码器初始化
	crypto, err := NewConfigCrypto(fixedKey, fixedIV)
	if err != nil {
		return nil, fmt.Errorf("解码解析器初始化失败: %v", err)
	}
	// 解码密文 密文字节  ===>  明文字节
	decrypt, err := crypto.decrypt(content)

	if err != nil {
		return nil, fmt.Errorf("解码失败: %v", err)
	}

	return confmap.NewRetrievedFromYAML(decrypt)
}

func (*provider) Scheme() string {
	return schemeName
}

func (*provider) Shutdown(context.Context) error {
	return nil
}
