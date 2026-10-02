package handlers

import (
	"strings"
	"testing"
)

func TestPHPBatchValidatesFinalRelatedSizes(t *testing.T) {
	base := "post_max_size = 64M\nupload_max_filesize = 64M\nmemory_limit = 256M\n"
	next, err := buildPHPBatchConfig(base, map[string]string{"post_max_size": "128M", "upload_max_filesize": "128M"})
	if err != nil || !strings.Contains(next, "upload_max_filesize = 128M") {
		t.Fatalf("valid simultaneous change: %v", err)
	}
	for _, values := range []map[string]string{{"upload_max_filesize": "128M"}, {"post_max_size": "999999999999999999999G"}, {"evil": "1"}, {"memory_limit": "256M\ninjected = 1"}} {
		if _, err := buildPHPBatchConfig(base, values); err == nil {
			t.Fatalf("accepted invalid batch: %#v", values)
		}
	}
}
