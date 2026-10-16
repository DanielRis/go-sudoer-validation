package sudoers

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkValidate(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("Defaults env_reset, secure_path=\"/usr/sbin:/usr/bin\"\n")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&sb, "Cmnd_Alias C%d = /usr/bin/cmd%d -x, /bin/ls *\n", i, i)
		fmt.Fprintf(&sb, "user%d ALL = (root) NOPASSWD: C%d, /usr/bin/kill -9 *\n", i, i)
	}
	content := []byte(sb.String())
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Validate(content, Options{})
	}
}
