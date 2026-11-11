package edge

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// api/ 下的契约文件必须是合法 YAML；OpenAPI 文件须声明 openapi、info.title、info.version 与 paths。
// （曾因流式映射中未加引号的描述含 "[" 导致 edge-admin.yaml 无法解析，而无任何检查发现。）
func TestContractYAMLParses(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "api", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no contract files found: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Errorf("%s: invalid YAML: %v", f, err)
			continue
		}
		if _, isOpenAPI := doc["openapi"]; !isOpenAPI {
			continue
		}
		info, _ := doc["info"].(map[string]any)
		if info["title"] == nil || info["version"] == nil {
			t.Errorf("%s: info.title and info.version are required", f)
		}
		if _, ok := doc["paths"].(map[string]any); !ok {
			t.Errorf("%s: paths missing", f)
		}
	}
}
