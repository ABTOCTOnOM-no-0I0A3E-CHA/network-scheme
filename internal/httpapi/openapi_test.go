package httpapi_test

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/beekamai/network-scheme/internal/httpapi"
)

/*
TestOpenAPICoversRoutes checks that api/openapi.yaml is valid and documents
exactly the registered routes, each with its policy: public routes have
"security: []", the others name their permission in x-permission and mark
step-up with "x-step-up: true".
*/
func TestOpenAPICoversRoutes(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("openapi.yaml is invalid: %v", err)
	}
	spec := map[string]*openapi3.Operation{}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			spec[method+" "+path] = op
		}
	}
	for _, r := range httpapi.Routes() {
		k := r.Method + " " + r.Pattern
		op, ok := spec[k]
		if !ok {
			t.Errorf("route %s is not documented in api/openapi.yaml", k)
			continue
		}
		delete(spec, k)
		public := op.Security != nil && len(*op.Security) == 0
		perm, _ := op.Extensions["x-permission"].(string)
		stepUp, _ := op.Extensions["x-step-up"].(bool)
		if public != r.Policy.Public || perm != string(r.Policy.Perm) || stepUp != r.Policy.StepUp {
			t.Errorf("%s: documented public=%v x-permission=%q x-step-up=%v, registered %+v", k, public, perm, stepUp, r.Policy)
		}
	}
	for k := range spec {
		t.Errorf("api/openapi.yaml documents %s, which is not registered", k)
	}
}
