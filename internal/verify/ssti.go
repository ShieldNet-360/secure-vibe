package verify

import (
	"net/http"
	"regexp"
	"strings"
)

// SSTI oracle: ask the template engine to evaluate an arithmetic expression
// whose product is distinctive enough not to occur by chance. If the PRODUCT
// comes back but the raw EXPRESSION does not, the server evaluated our input —
// server-side template injection. If the raw expression is echoed, it was only
// reflected (refuted, and would be an XSS lead instead).
const (
	sstiFactorA  = "73108"
	sstiFactorB  = "92"
	sstiExprBody = sstiFactorA + "*" + sstiFactorB
	sstiProduct  = "6725936" // 73108 * 92
)

// sstiProductRe matches the product only as a standalone number — not as a
// substring of a longer digit run (an id, price, timestamp, or asset path like
// /img/6725936.jpg) — which would otherwise confirm SSTI on a non-vulnerable app.
var sstiProductRe = regexp.MustCompile(`(?:\D|^)` + regexp.QuoteMeta(sstiProduct) + `(?:\D|$)`)

// sstiPayloads wrap the arithmetic in the delimiters of the common engines
// (Jinja2/Twig, ERB, Freemarker/Thymeleaf, Velocity/Razor, Smarty, JSP EL).
func sstiPayloads() []string {
	return []string{
		"{{" + sstiExprBody + "}}",    // Jinja2, Twig, Nunjucks, Angular
		"${" + sstiExprBody + "}",     // Freemarker, Thymeleaf, JSP EL, Spring
		"#{" + sstiExprBody + "}",     // Ruby, Thymeleaf
		"<%= " + sstiExprBody + " %>", // ERB, EJS
		"{" + sstiExprBody + "}",      // Smarty-ish
		"*{" + sstiExprBody + "}",     // Thymeleaf selection
	}
}

// SSTIProbe verifies server-side template injection.
type SSTIProbe struct{}

func (SSTIProbe) Kind() string { return "ssti" }

func (p SSTIProbe) Plan(f Finding, _ string) Plan {
	u, _ := buildURL(f, f.Param, sstiPayloads()[0])
	return Plan{Summary: methodOf(f) + " " + u +
		"   [" + f.Param + " = template arithmetic " + sstiExprBody + " → expect " + sstiProduct + " if evaluated]"}
}

func (p SSTIProbe) Execute(f Finding, env *Env) Result {
	r := Result{}
	var reflectedOnly bool
	for _, payload := range sstiPayloads() {
		u, err := buildURL(f, f.Param, payload)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(methodOf(f), u, nil)
		if err != nil {
			continue
		}
		applyHeaders(req, f)
		_, body, err := env.do(req)
		if err != nil {
			continue
		}
		// Evaluated: product present as a standalone number AND the raw expression is gone.
		if sstiProductRe.MatchString(body) && !strings.Contains(body, sstiExprBody) {
			r.Confirmed = true
			r.Evidence = "evaluated: " + sstiExprBody + " rendered as " + sstiProduct + " via " + payload + " — template injection"
			return r
		}
		if strings.Contains(body, sstiExprBody) {
			reflectedOnly = true
		}
	}
	r.Refuted = true
	if reflectedOnly {
		r.Evidence = "expression reflected verbatim but not evaluated (output encoding / not a template sink)"
	} else {
		r.Evidence = "no payload produced the evaluated product " + sstiProduct
	}
	return r
}

func init() { Register(SSTIProbe{}) }
