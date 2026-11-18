package authority

import (
	"context"

	"github.com/smallstep/certificates/webhook"
)

type webhookController interface {
	Enrich(context.Context, *webhook.RequestBody) error
	Authorize(context.Context, *webhook.RequestBody) error
}

// hasAuthorizingWebhook reports whether ctl will call an authorizing webhook.
// Every provisioner passes a controller, so a non-nil one is not enough.
func hasAuthorizingWebhook(ctl webhookController) bool {
	if ctl == nil {
		return false
	}
	h, ok := ctl.(interface{ HasAuthorizing() bool })
	return !ok || h.HasAuthorizing()
}
