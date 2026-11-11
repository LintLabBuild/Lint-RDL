package winsec

import (
	"strings"
	"testing"
)

func TestZoneIdentifier(t *testing.T) {
	z := ZoneIdentifier("https://user:pw@huggingface.co/a/resolve/main/x?token=s#f", "https://cdn.example/x?X-Amz-Signature=secret")
	if !strings.Contains(z, "ZoneId=3") || !strings.Contains(z, "ReferrerUrl=https://huggingface.co/a/resolve/main/x\r\n") {
		t.Fatal(z)
	}
	if strings.Contains(z, "secret") || strings.Contains(z, "pw") || strings.Contains(z, "token") {
		t.Fatal("secrets leaked into Zone.Identifier: " + z)
	}
}
