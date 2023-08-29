package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOauth2_Configure(t *testing.T) {
	var oa2a Oauth2Authenticator

	err := oa2a.Configure(map[string]interface{}{
		"client_id":     "myclient",
		"client_secret": "deadbeef",
		"username":      "user1",
		"password":      "Passw0rd!",
		"token_url":     "http://example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "user1", oa2a.Username)
	assert.Equal(t, "Passw0rd!", oa2a.Password)
	assert.Equal(t, "myclient", oa2a.ClientID)
	assert.Equal(t, "deadbeef", oa2a.ClientSecret)
	assert.Equal(t, "http://example.com", oa2a.TokenURL)

	err = oa2a.Configure(map[string]interface{}{
		"client_id":     "myclient",
		"client_secret": "deadbeef",
		"username":      "user1",
		"token_url":     "http://example.com",
	})
	assert.EqualError(t, err, "missing password")

	err = oa2a.Configure(map[string]interface{}{
		"client_id":     "myclient",
		"client_secret": "deadbeef",
		"token_url":     "http://example.com",
		"password":      "Passw0rd!",
	})
	assert.EqualError(t, err, "missing username")

	err = oa2a.Configure(map[string]interface{}{
		"client_id":     "myclient",
		"client_secret": "deadbeef",
		"username":      "user1",
		"password":      "Passw0rd!",
		"token_url":     "http://example.com",
		"full name":     "User One",
	})
	assert.EqualError(t, err, "unexpected fields in config: full name")
}
