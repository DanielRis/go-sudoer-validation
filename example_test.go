package sudoers_test

import (
	"encoding/json"
	"fmt"
	"net/http"

	sudoers "github.com/DanielRis/go-sudoer-validation"
)

func ExampleValidate() {
	content := []byte(`Cmnd_Alias SHUTDOWN = /sbin/shutdown, /sbin/reboot
Defaults passwd_tries=three
%admin ALL = (root) NOPASSWD: SHUTDOWN
bob ALL = vim
`)
	res := sudoers.Validate(content, sudoers.Options{Filename: "/etc/sudoers"})
	fmt.Println("valid:", res.Valid())
	for _, d := range res.Diagnostics {
		fmt.Println(d.Severity, d)
	}
	// Output:
	// valid: false
	// error /etc/sudoers:4:11: expected a fully-qualified path name
}

func ExampleValidate_strict() {
	content := []byte("root ALL = (ALL) ADMIN_CMDS\n")

	res := sudoers.Validate(content, sudoers.Options{})
	fmt.Println("valid:", res.Valid(), res.Warnings())

	res = sudoers.Validate(content, sudoers.Options{Strict: true})
	fmt.Println("valid:", res.Valid(), res.Errors())
	// Output:
	// valid: true [sudoers:1:28: Cmnd_Alias "ADMIN_CMDS" referenced but not defined]
	// valid: false [sudoers:1:28: Cmnd_Alias "ADMIN_CMDS" referenced but not defined]
}

func ExampleValidateString() {
	res := sudoers.ValidateString("Defaults lecture=sometimes\n", sudoers.Options{Filename: "upload"})
	fmt.Println(res.Errors())
	// Output:
	// [upload:1:18: value "sometimes" is invalid for option "lecture"]
}

// A handler that validates a sudoers file posted as the request body and
// replies with {"valid": ..., "diagnostics": [...]}.
func ExampleValidateReader() {
	http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		body := http.MaxBytesReader(w, r.Body, 1<<20) // limit untrusted input
		res, err := sudoers.ValidateReader(body, sudoers.Options{
			Filename: "sudoers",
			Strict:   r.URL.Query().Has("strict"),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	})
}
