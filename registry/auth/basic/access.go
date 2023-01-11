// Package basic provides a simple authentication scheme that checks for the
// user credential hash
//
// This authentication method MUST be used under TLS, as simple token-replay attack is possible.
package basic

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/registry/auth"
)

type accessController struct {
	realm    string
	user     string
	password string
}

var _ auth.AccessController = &accessController{}

func newAccessController(options map[string]interface{}) (auth.AccessController, error) {

	realm, present := options["realm"]
	if _, ok := realm.(string); !present || !ok {
		return nil, fmt.Errorf(`"realm" must be set for basic access controller`)
	}

	user, present := options["user"]
	if _, ok := user.(string); !present || !ok {
		return nil, fmt.Errorf(`"user" must be set for basic access controller`)
	}

	password, present := options["password"]
	if _, ok := password.(string); !present || !ok {
		return nil, fmt.Errorf(`"password" must be set for basic access controller`)
	}

	return &accessController{realm: realm.(string), user: user.(string), password: password.(string)}, nil
}

func (ac *accessController) Authorized(ctx context.Context, accessRecords ...auth.Access) (context.Context, error) {
	req, err := dcontext.GetRequest(ctx)
	if err != nil {
		return nil, err
	}

	username, password, ok := req.BasicAuth()
	if !ok {
		return nil, &challenge{
			realm: ac.realm,
			err:   auth.ErrInvalidCredential,
		}
	}

	if strings.Compare(username, ac.user) != 0 || strings.Compare(password, ac.password) != 0 {
		dcontext.GetLogger(ctx).Errorf("error authenticating user %q: %v", username, err)
		return nil, &challenge{
			realm: ac.realm,
			err:   auth.ErrAuthenticationFailure,
		}
	}

	return auth.WithUser(ctx, auth.UserInfo{Name: username}), nil
}

// challenge implements the auth.Challenge interface.
type challenge struct {
	realm string
	err   error
}

var _ auth.Challenge = challenge{}

// SetHeaders sets the basic challenge header on the response.
func (ch challenge) SetHeaders(r *http.Request, w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", ch.realm))
}

func (ch challenge) Error() string {
	return fmt.Sprintf("basic authentication challenge for realm %q: %s", ch.realm, ch.err)
}

func init() {
	auth.Register("basic", auth.InitFunc(newAccessController))
}
