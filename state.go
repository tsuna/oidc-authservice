// Copyright © 2019 Arrikto Inc.  All Rights Reserved.
//
// Utils related to handling the OIDC state parameter
// for CSRF.

package main

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/pkg/errors"
)

const (
	oauthStateCookie = "oidc_state_csrf"
)

var secureCookie = securecookie.New(
	// Hash Key
	securecookie.GenerateRandomKey(64),
	// Encryption Key
	securecookie.GenerateRandomKey(32),
)

type State struct {
	// FirstVisitedURL is the URL that the user visited when we redirected them
	// to login.
	FirstVisitedURL string
}

func newState(firstVisitedURL string) *State {
	return &State{
		FirstVisitedURL: firstVisitedURL,
	}
}

func initState(r *http.Request, w http.ResponseWriter) (string, error) {
	state := newState(r.URL.String())
	encoded, err := secureCookie.Encode(oauthStateCookie, state)
	if err != nil {
		return "", errors.Wrap(err, "Failed to save state in encrypted cookie.")
	}
	cookie := &http.Cookie{
		Name:     oauthStateCookie,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(20 * time.Minute),
	}
	http.SetCookie(w, cookie)
	return encoded, nil
}

func verifyState(r *http.Request) (*State, error) {
	// Get state from cookie and http param and:
	// 1. Confirm the two values match.
	// 2. Confirm we issued the state value by decoding it.
	// 2. Get the original URL associated with the state value.
	var stateParam = r.FormValue("state")
	if len(stateParam) == 0 {
		return nil, errors.New("Missing url parameter: state")
	}

	// If state is loaded, then it's correct, as it is saved by its id.
	stateCookie, err := r.Cookie(oauthStateCookie)
	if err != nil {
		return nil, errors.Errorf("Missing cookie: '%s'", oauthStateCookie)
	}
	if stateParam != stateCookie.Value {
		return nil, errors.New("State value from http params doesn't match value in cookie. Possible CSRF attack.")
	}

	var state *State
	err = secureCookie.Decode(oauthStateCookie, stateParam, &state)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to decode oauth state parameter.")
	}
	return state, nil
}
