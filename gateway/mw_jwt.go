package gateway

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	cache "github.com/pmylund/go-cache"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/user"
)

type JWTMiddleware struct {
	BaseMiddleware
}

const (
	KID       = "kid"
	SUB       = "sub"
	HMACSign  = "hmac"
	RSASign   = "rsa"
	ECDSASign = "ecdsa"
)

func (k *JWTMiddleware) Name() string {
	return "JWTMiddleware"
}

func (k *JWTMiddleware) EnabledForSpec() bool {
	return k.Spec.EnableJWT
}

var JWKCache *cache.Cache

type JWK struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	KID string   `json:"kid"`
	X5t string   `json:"x5t"`
}

type JWKs struct {
	Keys []JWK `json:"keys"`
}

func (k *JWTMiddleware) getSecretFromURL(url, kid, keyType string) ([]byte, error) {
	// Implement a cache
	if JWKCache == nil {
		k.Logger().Debug("Creating JWK Cache")
		JWKCache = cache.New(240*time.Second, 30*time.Second)
	}

	var jwkSet JWKs
	cachedJWK, found := JWKCache.Get(k.Spec.APIID)
	if !found {
		// Get the JWK
		k.Logger().Debug("Pulling JWK")
		resp, err := http.Get(url)
		if err != nil {
			k.Logger().WithError(err).Error("Failed to get resource URL")
			return nil, err
		}
		defer resp.Body.Close()

		// Decode it
		if err := json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
			k.Logger().WithError(err).Error("Failed to decode body JWK")
			return nil, err
		}

		// Cache it
		k.Logger().Debug("Caching JWK")
		JWKCache.Set(k.Spec.APIID, jwkSet, cache.DefaultExpiration)
	} else {
		jwkSet = cachedJWK.(JWKs)
	}

	k.Logger().Debug("Checking JWKs...")
	for _, val := range jwkSet.Keys {
		if val.KID != kid || strings.ToLower(val.Kty) != strings.ToLower(keyType) {
			continue
		}
		if len(val.X5c) > 0 {
			// Use the first cert only
			decodedCert, err := base64.StdEncoding.DecodeString(val.X5c[0])
			if err != nil {
				return nil, err
			}
			k.Logger().Debug("Found cert! Replying...")
			k.Logger().Debug("Cert was: ", string(decodedCert))
			return decodedCert, nil
		}
		return nil, errors.New("no certificates in JWK")
	}

	return nil, errors.New("No matching KID could be found")
}

func (k *JWTMiddleware) getIdentityFromToken(token *jwt.Token) (string, error) {
	// Check which claim is used for the id - kid or sub header
	// If is not supposed to ignore KID - will use this as ID if not empty
	if !k.Spec.APIDefinition.JWTSkipKid {
		if tykId, idFound := token.Header[KID].(string); idFound {
			k.Logger().Debug("Found: ", tykId)
			return tykId, nil
		}
	}
	// In case KID was empty or was set to ignore KID ==> Will try to get the Id from JWTIdentityBaseField or fallback to 'sub'
	tykId, err := k.getUserIdFromClaim(token.Claims.(jwt.MapClaims))
	return tykId, err
}

func (k *JWTMiddleware) getSecretToVerifySignature(r *http.Request, token *jwt.Token) ([]byte, error) {
	config := k.Spec.APIDefinition
	// Check for central JWT source
	if config.JWTSource != "" {
		// Is it a URL?
		if httpScheme.MatchString(config.JWTSource) {
			secret, err := k.getSecretFromURL(config.JWTSource, token.Header[KID].(string), k.Spec.JWTSigningMethod)
			if err != nil {
				return nil, err
			}

			return secret, nil
		}

		// If not, return the actual value
		decodedCert, err := base64.StdEncoding.DecodeString(config.JWTSource)
		if err != nil {
			return nil, err
		}

		// Is decoded url too?
		if httpScheme.MatchString(string(decodedCert)) {
			secret, err := k.getSecretFromURL(string(decodedCert), token.Header[KID].(string), k.Spec.JWTSigningMethod)
			if err != nil {
				return nil, err
			}

			return secret, nil
		}

		return decodedCert, nil // Returns the decoded secret
	}

	// If we are here, there's no central JWT source

	// Get the ID from the token (in KID header or configured claim or SUB claim)
	tykId, err := k.getIdentityFromToken(token)
	if err != nil {
		return nil, err
	}

	// Couldn't base64 decode the kid, so lets try it raw
	k.Logger().Debug("Getting key: ", tykId)
	session, rawKeyExists := k.CheckSessionAndIdentityForValidKey(&tykId, r)
	if !rawKeyExists {
		//Cisco change to try search "sitekey-<kid>"
		sitekey := "sitekey-" + tykId
		session, siteKeyExists := k.CheckSessionAndIdentityForValidKey(&sitekey, r)
		if !siteKeyExists {
			return nil, errors.New("token invalid, key not found")
		} else {
			return []byte(session.JWTData.Secret), nil
		}
	}
	return []byte(session.JWTData.Secret), nil
}

func (k *JWTMiddleware) getPolicyIDFromToken(claims jwt.MapClaims) (string, bool) {
	policyID, foundPolicy := claims[k.Spec.JWTPolicyFieldName].(string)
	if !foundPolicy {
		k.Logger().Debugf("Could not identify a policy to apply to this token from field: %s", k.Spec.JWTPolicyFieldName)
		return "", false
	}

	if policyID == "" {
		k.Logger().Errorf("Policy field %s has empty value", k.Spec.JWTPolicyFieldName)
		return "", false
	}

	return policyID, true
}

func (k *JWTMiddleware) getBasePolicyID(r *http.Request, claims jwt.MapClaims) (policyID string, found bool) {
	if k.Spec.JWTPolicyFieldName != "" {
		policyID, found = k.getPolicyIDFromToken(claims)
		return
	} else if k.Spec.JWTClientIDBaseField != "" {
		clientID, clientIDFound := claims[k.Spec.JWTClientIDBaseField].(string)
		if !clientIDFound {
			k.Logger().Debug("Could not identify a policy to apply to this token from field")
			return
		}

		// Check for a regular token that matches this client ID
		clientSession, exists := k.CheckSessionAndIdentityForValidKey(&clientID, r)
		if !exists {
			return
		}

		pols := clientSession.GetPolicyIDs()
		if len(pols) < 1 {
			return
		}

		// Use the policy from the client ID
		return pols[0], true
	}

	return
}

func (k *JWTMiddleware) getUserIdFromClaim(claims jwt.MapClaims) (string, error) {
	var userId string
	var found = false

	if k.Spec.JWTIdentityBaseField != "" {
		if userId, found = claims[k.Spec.JWTIdentityBaseField].(string); found {
			if len(userId) > 0 {
				k.Logger().WithField("userId", userId).Debug("Found User Id in Base Field")
				return userId, nil
			}
			message := "found an empty user ID in predefined base field claim " + k.Spec.JWTIdentityBaseField
			k.Logger().Error(message)
			return "", errors.New(message)
		}

		if !found {
			k.Logger().WithField("Base Field", k.Spec.JWTIdentityBaseField).Warning("Base Field claim not found, trying to find user ID in 'sub' claim.")
		}
	}

	if userId, found = claims[SUB].(string); found {
		if len(userId) > 0 {
			k.Logger().WithField("userId", userId).Debug("Found User Id in 'sub' claim")
			return userId, nil
		}
		message := "found an empty user ID in sub claim"
		k.Logger().Error(message)
		return "", errors.New(message)
	}

	message := "no suitable claims for user ID were found"
	k.Logger().Error(message)
	return "", errors.New(message)
}

func getScopeFromClaim(claims jwt.MapClaims, scopeClaimName string) []string {
	// get claim with scopes and turn it into slice of strings
	if scope, found := claims[scopeClaimName].(string); found {
		return strings.Split(scope, " ") // by standard is space separated list of values
	}

	// claim with scopes is optional so return nothing if it is not present
	return nil
}

func mapScopeToPolicies(mapping map[string]string, scope []string) []string {
	polIDs := []string{}

	// add all policies matched from scope-policy mapping
	policiesToApply := map[string]bool{}
	for _, scopeItem := range scope {
		if policyID, ok := mapping[scopeItem]; ok {
			policiesToApply[policyID] = true
			log.Debugf("Found a matching policy for scope item: %s", scopeItem)
		} else {
			log.Errorf("Couldn't find a matching policy for scope item: %s", scopeItem)
		}
	}
	for id := range policiesToApply {
		polIDs = append(polIDs, id)
	}

	return polIDs
}

// processCentralisedJWT Will check a JWT token centrally against the secret stored in the API Definition.
func (k *JWTMiddleware) processCentralisedJWT(r *http.Request, token *jwt.Token) (error, int) {
	k.Logger().Debug("JWT authority is centralised")

	claims := token.Claims.(jwt.MapClaims)
	baseFieldData, err := k.getUserIdFromClaim(claims)
	if err != nil {
		k.reportLoginFailure("[NOT FOUND]", r)
		return err, http.StatusForbidden
	}

	// Generate a virtual token
	data := []byte(baseFieldData)
	keyID := fmt.Sprintf("%x", md5.Sum(data))
	sessionID := generateToken(k.Spec.OrgID, keyID)
	updateSession := false

	k.Logger().Debug("JWT Temporary session ID is: ", sessionID)

	session, exists := k.CheckSessionAndIdentityForValidKey(&sessionID, r)
	isDefaultPol := false
	basePolicyID := ""
	foundPolicy := false
	if !exists {
		// Create it
		k.Logger().Debug("Key does not exist, creating")

		// We need a base policy as a template, either get it from the token itself OR a proxy client ID within Tyk
		basePolicyID, foundPolicy = k.getBasePolicyID(r, claims)
		if !foundPolicy {
			if len(k.Spec.JWTDefaultPolicies) == 0 {
				k.reportLoginFailure(baseFieldData, r)
				return errors.New("key not authorized: no matching policy found"), http.StatusForbidden
			} else {
				isDefaultPol = true
				basePolicyID = k.Spec.JWTDefaultPolicies[0]
			}
		}

		session, err = generateSessionFromPolicy(basePolicyID,
			k.Spec.OrgID,
			true)

		// If base policy is one of the defaults, apply other ones as well
		if isDefaultPol {
			for _, pol := range k.Spec.JWTDefaultPolicies {
				if !contains(session.ApplyPolicies, pol) {
					session.ApplyPolicies = append(session.ApplyPolicies, pol)
				}
			}
		}

		if err := k.ApplyPolicies(&session); err != nil {
			return errors.New("failed to create key: " + err.Error()), http.StatusInternalServerError
		}

		if err != nil {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("Could not find a valid policy to apply to this token!")
			return errors.New("key not authorized: no matching policy"), http.StatusForbidden
		}

		//override session expiry with JWT if longer lived
		if f, ok := claims["exp"].(float64); ok {
			if int64(f)-session.Expires > 0 {
				session.Expires = int64(f)
			}
		}

		session.SetMetaData(map[string]interface{}{"TykJWTSessionID": sessionID})
		session.Alias = baseFieldData

		// Update the session in the session manager in case it gets called again
		updateSession = true
		k.Logger().Debug("Policy applied to key")
	} else {
		// extract policy ID from JWT token
		basePolicyID, foundPolicy = k.getBasePolicyID(r, claims)
		if !foundPolicy {
			if len(k.Spec.JWTDefaultPolicies) == 0 {
				k.reportLoginFailure(baseFieldData, r)
				return errors.New("key not authorized: no matching policy found"), http.StatusForbidden
			} else {
				isDefaultPol = true
				basePolicyID = k.Spec.JWTDefaultPolicies[0]
			}
		}
		// check if we received a valid policy ID in claim
		policiesMu.RLock()
		policy, ok := policiesByID[basePolicyID]
		policiesMu.RUnlock()
		if !ok {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("Policy ID found is invalid!")
			return errors.New("key not authorized: no matching policy"), http.StatusForbidden
		}
		// check if token for this session was switched to another valid policy
		pols := session.GetPolicyIDs()
		if len(pols) == 0 {
			k.reportLoginFailure(baseFieldData, r)
			k.Logger().Error("No policies for the found session. Failing Request.")
			return errors.New("key not authorized: no matching policy found"), http.StatusForbidden
		}

		defaultPolicyListChanged := false

		if isDefaultPol {
			// check a policy is removed/added from/to default policies

			for _, pol := range session.GetPolicyIDs() {
				if !contains(k.Spec.JWTDefaultPolicies, pol) && basePolicyID != pol {
					defaultPolicyListChanged = true
				}
			}

			for _, defPol := range k.Spec.JWTDefaultPolicies {
				if !contains(session.GetPolicyIDs(), defPol) {
					defaultPolicyListChanged = true
				}
			}
		}

		if !contains(pols, basePolicyID) || defaultPolicyListChanged {
			if policy.OrgID != k.Spec.OrgID {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().Error("Policy ID found is invalid (wrong ownership)!")
				return errors.New("key not authorized: no matching policy"), http.StatusForbidden
			}
			// apply new policy to session and update session
			updateSession = true
			session.SetPolicies(basePolicyID)

			if isDefaultPol {
				for _, pol := range k.Spec.JWTDefaultPolicies {
					if !contains(session.ApplyPolicies, pol) {
						session.ApplyPolicies = append(session.ApplyPolicies, pol)
					}
				}
			}

			if err := k.ApplyPolicies(&session); err != nil {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().WithError(err).Error("Could not apply new policy to session")
				return errors.New("key not authorized: could not apply new policy"), http.StatusForbidden
			}
		}

		//override session expiry with JWT if longer lived
		if f, ok := claims["exp"].(float64); ok {
			if int64(f)-session.Expires > 0 {
				session.Expires = int64(f)
				updateSession = true
			}
		}
	}

	// apply policies from scope if scope-to-policy mapping is specified for this API
	if len(k.Spec.JWTScopeToPolicyMapping) != 0 {
		scopeClaimName := k.Spec.JWTScopeClaimName
		if scopeClaimName == "" {
			scopeClaimName = "scope"
		}

		if scope := getScopeFromClaim(claims, scopeClaimName); scope != nil {
			polIDs := []string{
				basePolicyID, // add base policy as a first one
			}

			// // If specified, scopes should not use default policy
			if isDefaultPol {
				polIDs = []string{}
			}

			// add all policies matched from scope-policy mapping
			mappedPolIDs := mapScopeToPolicies(k.Spec.JWTScopeToPolicyMapping, scope)
			if len(mappedPolIDs) > 0 {
				k.Logger().Debugf("Identified policy(s) to apply to this token from scope claim: %s", scopeClaimName)
			} else {
				k.Logger().Errorf("Couldn't identify policy(s) to apply to this token from scope claim: %s", scopeClaimName)
			}

			polIDs = append(polIDs, mappedPolIDs...)
			if len(polIDs) == 0 {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().Error("no matching policy found in scope claim")
				return errors.New("key not authorized: no matching policy found in scope claim"), http.StatusForbidden
			}

			// check if we need to update session
			if !updateSession {
				updateSession = !session.PoliciesEqualTo(polIDs)
			}

			session.SetPolicies(polIDs...)

			// multiple policies assigned to a key, check if it is applicable
			if err := k.ApplyPolicies(&session); err != nil {
				k.reportLoginFailure(baseFieldData, r)
				k.Logger().WithError(err).Error("Could not several policies from scope-claim mapping to JWT to session")
				return errors.New("key not authorized: could not apply several policies"), http.StatusForbidden
			}
		}
	}

	k.Logger().Debug("Key found")
	switch k.Spec.BaseIdentityProvidedBy {
	case apidef.JWTClaim, apidef.UnsetAuth:
		ctxSetSession(r, &session, sessionID, updateSession)

		if updateSession {
			clone := session.Clone()
			SessionCache.Set(session.GetKeyHash(), &clone, cache.DefaultExpiration)
		}
	}
	ctxSetJWTContextVars(k.Spec, r, token)

	return nil, http.StatusOK
}

func (k *JWTMiddleware) reportLoginFailure(tykId string, r *http.Request) {
	// Fire Authfailed Event
	AuthFailed(k, r, tykId)

	// Report in health check
	reportHealthValue(k.Spec, KeyFailure, "1")
}

func (k *JWTMiddleware) processOneToOneTokenMap(r *http.Request, token *jwt.Token) (error, int) {
	// Get the ID from the token
	tykId, err := k.getIdentityFromToken(token)
	if err != nil {
		k.reportLoginFailure(tykId, r)
		return err, http.StatusNotFound
	}

	k.Logger().Debug("Using raw key ID: ", tykId)
	session, exists := k.CheckSessionAndIdentityForValidKey(&tykId, r)
	if !exists {
		//Cisco change to try search "sitekey-<kid>"
		sitekey := "sitekey-" + tykId
		k.Logger().Debug("Using sitekey ID: ", sitekey)
		session, siteKeyExists := k.CheckSessionAndIdentityForValidKey(&sitekey, r)
		if !siteKeyExists {
			k.reportLoginFailure(tykId, r)
			return errors.New("Key not authorized"), http.StatusForbidden
		} else {
			k.Logger().Debug("sitekey ID found.")
			ctxSetSession(r, &session, sitekey, false)
			ctxSetJWTContextVars(k.Spec, r, token)
			return nil, http.StatusOK
		}
	}

	k.Logger().Debug("Raw key ID found.")
	ctxSetSession(r, &session, tykId, false)
	ctxSetJWTContextVars(k.Spec, r, token)
	return nil, http.StatusOK
}

// getAuthType overrides BaseMiddleware.getAuthType.
func (k *JWTMiddleware) getAuthType() string {
	return jwtType
}

func (k *JWTMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if ctxGetRequestStatus(r) == StatusOkAndIgnore {
		return nil, http.StatusOK
	}

	logger := k.Logger()
	var tykId string

	//Added default JWT lookup
	rawJWT, config := k.getAuthToken(k.getAuthType(), r)
	if rawJWT == "" {
		//Check is its API key request
		rawJWT = k.getJWTFromAPIKey(r)
		//set rawJWT as Authorization header and also as AuthCookie
		if rawJWT != "" {
			r.Header.Set("Authorization", rawJWT)
			cookie := http.Cookie{
				Name:   "AuthCookie",
				Value:  rawJWT,
				MaxAge: 300,
			}
			r.AddCookie(&cookie)
		}
	}

	if rawJWT == "" {
		// No header value, fail
		logger.Info("Attempted access with malformed header, no JWT auth header found.")

		log.Debug("Looked in: ", config.AuthHeaderName)
		log.Debug("Raw data was: ", rawJWT)
		log.Debug("Headers are: ", r.Header)

		k.reportLoginFailure(tykId, r)
		return errors.New("Authorization field missing"), http.StatusUnauthorized
	}

	// enable bearer token format
	rawJWT = stripBearer(rawJWT)

	// Use own validation logic, see below
	parser := &jwt.Parser{SkipClaimsValidation: true}

	// Verify the token
	token, err := parser.Parse(rawJWT, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		switch k.Spec.JWTSigningMethod {
		case HMACSign:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v and not HMAC signature", token.Header["alg"])
			}
		case RSASign:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v and not RSA signature", token.Header["alg"])
			}
		case ECDSASign:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v and not ECDSA signature", token.Header["alg"])
			}
		default:
			logger.Warning("No signing method found in API Definition, defaulting to HMAC signature")
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		}

		val, err := k.getSecretToVerifySignature(r, token)
		if err != nil {
			k.Logger().WithError(err).Error("Couldn't get token")
			return nil, err
		}
		switch k.Spec.JWTSigningMethod {
		case RSASign, ECDSASign:
			//key, err := ParseRSAPublicKey(val)
			key, err := jwt.ParseRSAPublicKeyFromPEM(val)
			if err != nil {
				logger.WithError(err).Error("Failed to decode JWT key")
				return nil, errors.New("Failed to decode JWT key")
			}
			return key, nil
		default:
			return val, nil
		}
	})

	if err == nil && token.Valid {
		if jwtErr := k.timeValidateJWTClaims(token.Claims.(jwt.MapClaims)); jwtErr != nil {
			return errors.New("Key not authorized: " + jwtErr.Error()), http.StatusUnauthorized
		}

		//Enforce CSRF Check only if ui-login claim is set
		uiClaim, found := token.Claims.(jwt.MapClaims)["ui-login"]
		if found {
			isUILogin := uiClaim.(bool)
			if k.Spec.Auth.UseCSRFHeader && isUILogin {
				csrfHeader := textproto.CanonicalMIMEHeaderKey(k.Spec.Auth.CSRFHeaderName)
				logger.Debug("proxy reauest with csrfHeader ", csrfHeader, "header")
				csrfToken := r.Header.Get(csrfHeader)
				if csrfToken != "" {
					if err := k.validateCSRFHeader(token.Claims.(jwt.MapClaims), csrfToken); err != nil {
						//Add NDProxyRequest header to request to skip tyk.io header injection for error response
						header := textproto.CanonicalMIMEHeaderKey(k.BaseMiddleware.Spec.Proxy.NDProxyRequest)
						r.Header.Set(header, "localhost")
						return errors.New(err.Error()), http.StatusUnauthorized
					}
				} else {
					//Error - could not find CSRF Header
					return errors.New("missing csrf token"), http.StatusUnauthorized
				}
			}
		}

		//Cisco change - do not proxy local user request
		//Check if update host header is set
		header := textproto.CanonicalMIMEHeaderKey(k.Spec.Proxy.UpdateHostHeader)
		logger.Debug("proxy reauest with localuser ", header, "header")
		ok := r.Header.Get(header)
		if ok != "" {
			if err := k.validateLocaluserProxyRequest(token.Claims.(jwt.MapClaims)); err != nil {
				//Add NDProxyRequest header to request to skip tyk.io header injection for error response
				header := textproto.CanonicalMIMEHeaderKey(k.BaseMiddleware.Spec.Proxy.NDProxyRequest)
				r.Header.Set(header, "localhost")
				return errors.New(err.Error()), http.StatusUnauthorized
			}
		}

		// Token is valid - let's move on

		// Are we mapping to a central JWT Secret?
		if k.Spec.JWTSource != "" {
			return k.processCentralisedJWT(r, token)
		}

		// No, let's try one-to-one mapping
		return k.processOneToOneTokenMap(r, token)
	}

	logger.Info("Attempted JWT access with non-existent key.")
	k.reportLoginFailure(tykId, r)
	if err != nil {
		logger.WithError(err).Error("JWT validation error")
		return errors.New("Key not authorized:" + err.Error()), http.StatusUnauthorized
	}
	return errors.New("Key not authorized"), http.StatusUnauthorized
}

type TokenResponse struct {
	JWTToken string `json:"jwttoken,omitempty"`
}

func (k *JWTMiddleware) getJWTFromAPIKey(r *http.Request) string {
	//check if x-nd-apikey and x-nd-username is set
	var apikey, username, secret string
	var httpReq *http.Request
	var tokenResp TokenResponse

	tokenEndpoint, ok := os.LookupEnv("APIKEY_TOKEN_ENDPOINT")
	if !ok {
		tokenEndpoint = "https://127.0.0.1/token"
	}

	logger := k.Logger()

	apikeys, ok := r.Header[k.Spec.Proxy.NDAPIKeyHeader]
	if ok {
		apikey = apikeys[0]
	}

	usernames, ok := r.Header[k.Spec.Proxy.NDAPIKeyUsernameHeader]
	if ok {
		username = usernames[0]
	}

	secret = config.Global().Secret

	if apikey == "" || username == "" || secret == "" {
		//Return empty token for tyk to reject the request
		logger.Error("apikey - invalid param")
		return ""
	}

	//Make HTTP call to /token endpoint to get the user token
	timeout := 10 * time.Second
	httpReq, err := http.NewRequest("GET", tokenEndpoint, nil)
	if err != nil {
		return ""
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(k.Spec.Proxy.NDAPIKeyUsernameHeader, username)
	httpReq.Header.Set(k.Spec.Proxy.NDAPIKeyHeader, apikey)
	httpReq.Header.Set(k.Spec.Proxy.NDAPIKeySecretHeader, secret)

	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Timeout: timeout, Transport: tr}
	resp, err := client.Do(httpReq)
	if err != nil {
		logger.WithError(err).Error("could not create transport")
		return ""
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.WithError(err).Error("could not read response body")
		return ""
	}

	err = json.Unmarshal(b, &tokenResp)

	if err != nil {
		logger.WithError(err).Error("could not unmarshal response body")
		return ""
	}

	return tokenResp.JWTToken
}

func ParseRSAPublicKey(data []byte) (interface{}, error) {
	input := data
	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}
	var pub interface{}
	var err error
	pub, err = x509.ParsePKIXPublicKey(input)
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(input)
		if err != nil {
			cert, err0 := x509.ParseCertificate(input)
			if err0 != nil {
				return nil, err0
			}
			pub = cert.PublicKey
			err = nil
		}
	}
	return pub, err
}

func (k *JWTMiddleware) timeValidateJWTClaims(c jwt.MapClaims) *jwt.ValidationError {
	vErr := new(jwt.ValidationError)
	now := time.Now().Unix()
	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if !c.VerifyExpiresAt(now-int64(k.Spec.JWTExpiresAtValidationSkew), false) {
		vErr.Inner = errors.New("token has expired")
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if c.VerifyIssuedAt(now+int64(k.Spec.JWTIssuedAtValidationSkew), false) == false {
		vErr.Inner = errors.New("token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if c.VerifyNotBefore(now+int64(k.Spec.JWTNotBeforeValidationSkew), false) == false {
		vErr.Inner = errors.New("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

func (k *JWTMiddleware) validateLocaluserProxyRequest(c jwt.MapClaims) error {
	var err error
	logger := k.Logger()
	logger.Info("Found %s header", k.Spec.Proxy.NDProxyRequest)
	usertype, ok := c["usertype"]
	if ok && usertype == "local" {
		err = errors.New("could not proxy localuser request")
	}

	return err
}

// validateCSRFHeader validates csrf token claim in jwt with csrf token in request header
// request header csrf token is plain 64 character string
// csrf token claim in jwt is a sha 256 hashed value of the plain 64 character string
func (k *JWTMiddleware) validateCSRFHeader(c jwt.MapClaims, csrfToken string) error {
	logger := k.Logger()
	logger.Info("Found %s header", k.Spec.Auth.CSRFHeaderName)
	csrfCookie, ok := c["csrf-token"]
	if !ok {
		return errors.New("could not find csrf token in cookie")
	}
	hashedCsrfToken := sha256.Sum256([]byte(csrfToken))
	if fmt.Sprintf("%x", hashedCsrfToken) != fmt.Sprintf("%v", csrfCookie) {
		return errors.New("csrf token validation failed")
	}

	return nil
}

func ctxSetJWTContextVars(s *APISpec, r *http.Request, token *jwt.Token) {
	// Flatten claims and add to context
	if !s.EnableContextVars {
		return
	}
	if cnt := ctxGetData(r); cnt != nil {
		claimPrefix := "jwt_claims_"

		for claimName, claimValue := range token.Header {
			claim := claimPrefix + claimName
			cnt[claim] = claimValue
		}

		for claimName, claimValue := range token.Claims.(jwt.MapClaims) {
			claim := claimPrefix + claimName
			cnt[claim] = claimValue
		}

		// Key data
		cnt["token"] = ctxGetAuthToken(r)

		ctxSetData(r, cnt)
	}
}

func generateSessionFromPolicy(policyID, orgID string, enforceOrg bool) (user.SessionState, error) {
	policiesMu.RLock()
	policy, ok := policiesByID[policyID]
	policiesMu.RUnlock()
	session := user.NewSessionState()
	if !ok {
		return session.Clone(), errors.New("Policy not found")
	}
	// Check ownership, policy org owner must be the same as API,
	// otherwise youcould overwrite a session key with a policy from a different org!

	if enforceOrg {
		if policy.OrgID != orgID {
			log.Error("Attempting to apply policy from different organisation to key, skipping")
			return session.Clone(), errors.New("Key not authorized: no matching policy")
		}
	} else {
		// Org isn;t enforced, so lets use the policy baseline
		orgID = policy.OrgID
	}

	session.SetPolicies(policyID)
	session.OrgID = orgID
	session.Allowance = policy.Rate // This is a legacy thing, merely to make sure output is consistent. Needs to be purged
	session.Rate = policy.Rate
	session.Per = policy.Per
	session.ThrottleInterval = policy.ThrottleInterval
	session.ThrottleRetryLimit = policy.ThrottleRetryLimit
	session.MaxQueryDepth = policy.MaxQueryDepth
	session.QuotaMax = policy.QuotaMax
	session.QuotaRenewalRate = policy.QuotaRenewalRate
	session.AccessRights = make(map[string]user.AccessDefinition)
	for apiID, access := range policy.AccessRights {
		session.AccessRights[apiID] = access
	}
	session.HMACEnabled = policy.HMACEnabled
	session.EnableHTTPSignatureValidation = policy.EnableHTTPSignatureValidation
	session.IsInactive = policy.IsInactive
	session.Tags = policy.Tags

	if policy.KeyExpiresIn > 0 {
		session.Expires = time.Now().Unix() + policy.KeyExpiresIn
	}

	return session.Clone(), nil
}
