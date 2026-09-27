package executor

import (
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/models"
)

func TestLegacyNginxCustomTaskIsDisabledOnOLS(t *testing.T) {
	result := executeSaveNginxCustom(&Task{Payload: &SaveNginxCustomPayload{
		Site:       &models.Website{ID: 1, Domain: "example.com"},
		PreContent: "server_tokens off;",
		Content:    "location /private { deny all; }",
	}})
	if result.Success || !strings.Contains(result.Message, "OpenLiteSpeed") {
		t.Fatalf("result = %+v", result)
	}
}

func TestLegacyNginxCustomTaskRejectsWrongPayload(t *testing.T) {
	result := executeSaveNginxCustom(&Task{Payload: "invalid"})
	if result.Success || result.Message != "任务参数类型错误" {
		t.Fatalf("result = %+v", result)
	}
}
