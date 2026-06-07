package engine

import (
	"strings"

	"github.com/syedkarim/snare/internal/model"
)

// InspectSignal statically scans hook scripts and the files they reference for
// high-signal malicious patterns.
type InspectSignal struct{}

func (InspectSignal) Name() string { return "inspect" }

type pattern struct {
	needle string
	label  string
}

// credentialReads are accesses to secret material.
var credentialReads = []pattern{
	{"AWS_SECRET_ACCESS_KEY", "reads AWS secret key"},
	{"AWS_SESSION_TOKEN", "reads AWS session token"},
	{".aws/credentials", "reads AWS credentials file"},
	{".npmrc", "reads npm credentials"},
	{"VAULT_TOKEN", "reads Vault token"},
	{"id_rsa", "reads SSH private key"},
	{".ssh/", "reads SSH directory"},
	{"GITHUB_TOKEN", "reads GitHub token"},
}

// exfilOrExec are egress / remote-exec indicators.
var exfilOrExec = []pattern{
	{"curl ", "shells out to curl"},
	{"| sh", "pipes downloaded content to a shell"},
	{"|sh", "pipes downloaded content to a shell"},
	{"child_process", "spawns a child process"},
	{"http.get", "makes an outbound HTTP request"},
	{"https.get", "makes an outbound HTTPS request"},
	{"fetch(", "makes an outbound fetch request"},
	{"Buffer.from(", "decodes an embedded blob"},
	{"eval(", "evaluates dynamic code"},
}

// hookReferenced returns the hook script bodies plus any referenced .js file
// bodies present in Files.
func hookReferenced(p model.PackageData) []string {
	var bodies []string
	for _, body := range p.Scripts {
		bodies = append(bodies, body)
		for _, tok := range strings.Fields(body) {
			tok = strings.Trim(tok, "'\"")
			if strings.HasSuffix(tok, ".js") {
				if f, ok := p.Files[tok]; ok {
					bodies = append(bodies, f)
				}
			}
		}
	}
	return bodies
}

func (InspectSignal) Evaluate(p model.PackageData) []model.Evidence {
	if len(p.Scripts) == 0 {
		return nil
	}
	corpus := strings.Join(hookReferenced(p), "\n")
	readsCred, reason := firstMatch(corpus, credentialReads)
	egress, egressReason := firstMatch(corpus, exfilOrExec)

	var ev []model.Evidence
	switch {
	case readsCred && egress:
		ev = append(ev, model.Evidence{
			Signal:      "inspect.exfil",
			Tier:        model.Critical,
			Explanation: "install hook " + reason + " and " + egressReason,
			Locator:     "install script",
		})
	case readsCred:
		ev = append(ev, model.Evidence{
			Signal:      "inspect.credread",
			Tier:        model.High,
			Explanation: "install hook " + reason,
			Locator:     "install script",
		})
	case egress:
		ev = append(ev, model.Evidence{
			Signal:      "inspect.egress",
			Tier:        model.Medium,
			Explanation: "install hook " + egressReason,
			Locator:     "install script",
		})
	}
	return ev
}

func firstMatch(corpus string, pats []pattern) (bool, string) {
	for _, p := range pats {
		if strings.Contains(corpus, p.needle) {
			return true, p.label
		}
	}
	return false, ""
}
