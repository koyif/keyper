package commands

import (
	"fmt"

	"github.com/koyif/keyper/internal/client/session"
)

// requireAuth checks if the session is authenticated and returns an error if not.
func requireAuth(sess *session.Session) error {
	if !sess.IsAuthenticated() {
		return fmt.Errorf("not logged in. Please run 'keyper auth login' first")
	}

	return nil
}
