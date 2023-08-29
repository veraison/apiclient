package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasic_Configure(t *testing.T) {
	var ba BasicAuthenticator

	err := ba.Configure(map[string]interface{}{
		"username": "user1",
		"password": "Passw0rd!",
	})
	require.NoError(t, err)
	assert.Equal(t, "user1", ba.Username)
	assert.Equal(t, "Passw0rd!", ba.Password)

	err = ba.Configure(map[string]interface{}{
		"username": "user1",
	})
	assert.EqualError(t, err, "missing password")

	err = ba.Configure(map[string]interface{}{
		"password": "Passw0rd!",
	})
	assert.EqualError(t, err, "missing username")

	err = ba.Configure(map[string]interface{}{
		"username":  "user1",
		"password":  "Passw0rd!",
		"full name": "User One",
	})
	assert.EqualError(t, err, "unexpected fields in config: full name")
}

func TestBasic_EncodeHeader(t *testing.T) {
	var ba BasicAuthenticator

	_, err := ba.EncodeHeader()
	assert.EqualError(t, err, "missing username")

	err = ba.Configure(map[string]interface{}{
		"username": "user1",
		"password": "Passw0rd!",
	})
	require.NoError(t, err)

	header, err := ba.EncodeHeader()
	require.NoError(t, err)
	assert.Equal(t, "Basic dXNlcjE6UGFzc3cwcmQh", header)
}
