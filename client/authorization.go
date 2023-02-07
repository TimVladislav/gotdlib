package client

import (
	"errors"
	"time"
)

var ErrNotSupportedAuthorizationState = errors.New("not supported state")

type TypeAuthorizationStateUnknown struct{}

func (state TypeAuthorizationStateUnknown) AuthorizationStateType() string {
	return "unknown"
}

type AuthorizationStateHandler interface {
	Handle(client *Client) (AuthorizationState, error)
}

func Authorize(client *Client, authorizationStateHandler AuthorizationStateHandler) (AuthorizationState, error) {
	state, err := client.GetAuthorizationState()
	if err != nil {
		return TypeAuthorizationStateUnknown{}, err
	}

	if state.AuthorizationStateType() == TypeAuthorizationStateClosed {
		return state, nil
	}

	if state.AuthorizationStateType() == TypeAuthorizationStateReady {
		// dirty hack for db flush after authorization
		time.Sleep(1 * time.Second)
		return state, nil
	}

	state, err = authorizationStateHandler.Handle(client)
	return state, err
}

type ClientAuthorizer struct {
	TdlibParameters *TdlibParameters
}

func NewClientAuthorizer(params *TdlibParameters) *ClientAuthorizer {
	return &ClientAuthorizer{
		TdlibParameters: params,
	}
}

func (stateHandler *ClientAuthorizer) Handle(client *Client) (AuthorizationState, error) {
	state, err := client.GetAuthorizationState()
	if err != nil {
		return TypeAuthorizationStateUnknown{}, err
	}

	switch state.AuthorizationStateType() {
	case TypeAuthorizationStateWaitTdlibParameters:
		_, err = client.SetTdlibParameters(&SetTdlibParametersRequest{
			Parameters: stateHandler.TdlibParameters,
		})
		if err != nil {
			return TypeAuthorizationStateUnknown{}, err
		}
		state, err = client.GetAuthorizationState()
		if err != nil {
			return TypeAuthorizationStateUnknown{}, err
		}
	case TypeAuthorizationStateWaitEncryptionKey:
		_, err = client.CheckDatabaseEncryptionKey(&CheckDatabaseEncryptionKeyRequest{})
		if err != nil {
			return TypeAuthorizationStateUnknown{}, err
		}
		state, err = client.GetAuthorizationState()
		if err != nil {
			return TypeAuthorizationStateUnknown{}, err
		}
	}

	return state, nil
}

func (stateHandler *ClientAuthorizer) SendPhoneNumber(client *Client, phone string) error {
	_, err := client.SetAuthenticationPhoneNumber(&SetAuthenticationPhoneNumberRequest{
		PhoneNumber: phone,
		Settings: &PhoneNumberAuthenticationSettings{
			AllowFlashCall:       false,
			IsCurrentPhoneNumber: false,
			AllowSmsRetrieverApi: false,
		},
	})
	return err
}

func (stateHandler *ClientAuthorizer) SendAuthenticationCode(client *Client, code string) error {
	_, err := client.CheckAuthenticationCode(&CheckAuthenticationCodeRequest{
		Code: code,
	})
	return err
}

func (stateHandler *ClientAuthorizer) SendPassword(client *Client, password string) error {
	_, err := client.CheckAuthenticationPassword(&CheckAuthenticationPasswordRequest{
		Password: password,
	})
	return err
}
