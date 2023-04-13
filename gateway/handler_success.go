package gateway

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/tyk-pump/analytics"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/header"
	"github.com/TykTechnologies/tyk/request"
	"github.com/TykTechnologies/tyk/user"
)

const (
	keyDataDeveloperID    = "tyk_developer_id"
	keyDataDeveloperEmail = "tyk_developer_email"
)

type ProxyResponse struct {
	Response *http.Response
	// UpstreamLatency the time it takes to do roundtrip to upstream. Total time
	// taken for the gateway to receive response from upstream host.
	UpstreamLatency time.Duration
}

type ReturningHttpHandler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) ProxyResponse
	ServeHTTPForCache(http.ResponseWriter, *http.Request) ProxyResponse
	CopyResponse(io.Writer, io.Reader, time.Duration)
}

// SuccessHandler represents the final ServeHTTP() request for a proxied API request
type SuccessHandler struct {
	BaseMiddleware
}

func tagHeaders(r *http.Request, th []string, tags []string) []string {
	for k, v := range r.Header {
		cleanK := strings.ToLower(k)
		ok := false
		for _, hname := range th {
			if hname == cleanK {
				ok = true
				break
			}
		}

		if ok {
			for _, val := range v {
				tagName := cleanK + "-" + val
				tags = append(tags, tagName)
			}
		}
	}

	return tags
}

func addVersionHeader(w http.ResponseWriter, r *http.Request, globalConf config.Config) {
	if ctxGetDefaultVersion(r) {
		if vinfo := ctxGetVersionInfo(r); vinfo != nil {
			if globalConf.VersionHeader != "" {
				w.Header().Set(globalConf.VersionHeader, vinfo.Name)
			}
		}
	}
}

func estimateTagsCapacity(session *user.SessionState, apiSpec *APISpec) int {
	size := 5 // that number of tags expected to be added at least before we record hit
	if session != nil {
		size += len(session.Tags)

		size += len(session.ApplyPolicies)

		if session.MetaData != nil {
			if _, ok := session.MetaData[keyDataDeveloperID]; ok {
				size += 1
			}
		}
	}

	if apiSpec.GlobalConfig.DBAppConfOptions.NodeIsSegmented {
		size += len(apiSpec.GlobalConfig.DBAppConfOptions.Tags)
	}

	size += len(apiSpec.TagHeaders)

	return size
}

func getSessionTags(session *user.SessionState) []string {
	tags := make([]string, 0, len(session.Tags)+len(session.ApplyPolicies)+1)

	// add policy IDs
	for _, polID := range session.ApplyPolicies {
		tags = append(tags, "pol-"+polID)
	}

	if session.MetaData != nil {
		if developerID, ok := session.MetaData[keyDataDeveloperID].(string); ok {
			tags = append(tags, "dev-"+developerID)
		}
	}

	tags = append(tags, session.Tags...)

	return tags
}

func (s *SuccessHandler) RecordHit(r *http.Request, timing analytics.Latency, code int, responseCopy *http.Response) {

	if s.Spec.DoNotTrack || ctxGetDoNotTrack(r) {
		return
	}

	ip := request.RealIP(r)
	if s.Spec.GlobalConfig.StoreAnalytics(ip) {

		t := time.Now()

		// Track the key ID if it exists
		token := ctxGetAuthToken(r)

		// Track version data
		version := s.Spec.getVersionFromRequest(r)
		if version == "" {
			version = "Non Versioned"
		}

		// If OAuth, we need to grab it from the session, which may or may not exist
		oauthClientID := ""
		var alias string
		session := ctxGetSession(r)
		tags := make([]string, 0, estimateTagsCapacity(session, s.Spec))
		if session != nil {
			oauthClientID = session.OauthClientID
			tags = append(tags, getSessionTags(session)...)
			alias = session.Alias
		}

		if len(s.Spec.TagHeaders) > 0 {
			tags = tagHeaders(r, s.Spec.TagHeaders, tags)
		}

		if len(s.Spec.Tags) > 0 {
			tags = append(tags, s.Spec.Tags...)
		}

		rawRequest := ""
		rawResponse := ""

		if recordDetail(r, s.Spec) {
			// Get the wire format representation
			var wireFormatReq bytes.Buffer
			r.Write(&wireFormatReq)
			rawRequest = base64.StdEncoding.EncodeToString(wireFormatReq.Bytes())
			// responseCopy, unlike requestCopy, can be nil
			// here - if the response was cached in
			// mw_redis_cache, RecordHit gets passed a nil
			// response copy.
			// TODO: pass a copy of the cached response in
			// mw_redis_cache instead? is there a reason not
			// to include that in the analytics?
			if responseCopy != nil {
				contents, err := ioutil.ReadAll(responseCopy.Body)
				if err != nil {
					log.Error("Couldn't read response body", err)
				}

				responseCopy.Body = respBodyReader(r, responseCopy)

				// Get the wire format representation
				var wireFormatRes bytes.Buffer
				responseCopy.Write(&wireFormatRes)
				responseCopy.Body = ioutil.NopCloser(bytes.NewBuffer(contents))
				rawResponse = base64.StdEncoding.EncodeToString(wireFormatRes.Bytes())
			}
		}

		trackEP := false
		trackedPath := r.URL.Path
		if p := ctxGetTrackedPath(r); p != "" {
			trackEP = true
			trackedPath = p
		}

		host := r.URL.Host
		if host == "" && s.Spec.target != nil {
			host = s.Spec.target.Host
		}

		record := analytics.AnalyticsRecord{
			Method:        r.Method,
			Host:          host,
			Path:          trackedPath,
			RawPath:       r.URL.Path,
			ContentLength: r.ContentLength,
			UserAgent:     r.Header.Get(header.UserAgent),
			Day:           t.Day(),
			Month:         t.Month(),
			Year:          t.Year(),
			Hour:          t.Hour(),
			ResponseCode:  code,
			APIKey:        token,
			TimeStamp:     t,
			APIVersion:    version,
			APIName:       s.Spec.Name,
			APIID:         s.Spec.APIID,
			OrgID:         s.Spec.OrgID,
			OauthID:       oauthClientID,
			RequestTime:   timing.Total,
			RawRequest:    rawRequest,
			RawResponse:   rawResponse,
			IPAddress:     ip,
			Geo:           analytics.GeoData{},
			Network:       analytics.NetworkStats{},
			Latency:       timing,
			Tags:          tags,
			Alias:         alias,
			TrackPath:     trackEP,
			ExpireAt:      t,
		}

		if s.Spec.GlobalConfig.AnalyticsConfig.EnableGeoIP {
			record.GetGeo(ip, s.Gw.Analytics.GeoIPDB)
		}

		// skip tagging subgraph requests for graphpump, it only handles generated supergraph requests
		if s.Spec.GraphQL.Enabled && s.Spec.GraphQL.ExecutionMode != apidef.GraphQLExecutionModeSubgraph {
			record.Tags = append(record.Tags, "tyk-graph-analytics")
			record.ApiSchema = base64.StdEncoding.EncodeToString([]byte(s.Spec.GraphQL.Schema))
		}

		expiresAfter := s.Spec.ExpireAnalyticsAfter

		if s.Spec.GlobalConfig.EnforceOrgDataAge {
			orgExpireDataTime := s.OrgSessionExpiry(s.Spec.OrgID)

			if orgExpireDataTime > 0 {
				expiresAfter = orgExpireDataTime
			}
		}

		record.SetExpiry(expiresAfter)

		if s.Spec.GlobalConfig.AnalyticsConfig.NormaliseUrls.Enabled {
			NormalisePath(&record, &s.Spec.GlobalConfig)
		}

		if s.Spec.AnalyticsPlugin.Enabled {

			//send to plugin
			_ = s.Spec.AnalyticsPluginConfig.processRecord(&record)

		}

		err := s.Gw.Analytics.RecordHit(&record)

		if err != nil {
			log.WithError(err).Error("could not store analytic record")
		}
	}

	// Report in health check
	reportHealthValue(s.Spec, RequestLog, strconv.FormatInt(timing.Total, 10))

	if memProfFile != nil {
		pprof.WriteHeapProfile(memProfFile)
	}
}

func recordDetail(r *http.Request, spec *APISpec) bool {
	// when streaming in grpc, we do not record the request
	if IsGrpcStreaming(r) {
		return false
	}

	if spec.EnableDetailedRecording {
		return true
	}

	if session := ctxGetSession(r); session != nil {
		if session.EnableDetailedRecording || session.EnableDetailRecording { // nolint:staticcheck // Deprecated DetailRecording
			return true
		}
	}

	// Are we even checking?
	if !spec.GlobalConfig.EnforceOrgDataDetailLogging {
		return spec.GlobalConfig.AnalyticsConfig.EnableDetailedRecording
	}

	// We are, so get session data
	session, ok := r.Context().Value(ctx.OrgSessionContext).(*user.SessionState)
	if ok && session != nil {
		return session.EnableDetailedRecording || session.EnableDetailRecording // nolint:staticcheck // Deprecated DetailRecording
	}

	// no session found, use global config
	return spec.GlobalConfig.AnalyticsConfig.EnableDetailedRecording
}

// ServeHTTP will store the request details in the analytics store if necessary and proxy the request to it's
// final destination, this is invoked by the ProxyHandler or right at the start of a request chain if the URL
// Spec states the path is Ignored
func (s *SuccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) *http.Response {
	log.Debug("Started proxy")
	defer s.Base().UpdateRequestSession(r)

	log.Debug("Check update_host_header")
	if len(s.Spec.Proxy.UpdateHostHeader) > 0 {
		//Normalize header
		log.Debug("Handler_success - Detected UpdateHostHeader ", s.Spec.Proxy.UpdateHostHeader)
		header := textproto.CanonicalMIMEHeaderKey(s.Spec.Proxy.UpdateHostHeader)
		log.Debug("Handler_success - CanonicalMIMEHeaderKey form ", s.Spec.Proxy.UpdateHostHeader)
		updateHost, ok := r.Header[header]
		if ok {
			//Create Reverse proxy
			director := func(req *http.Request) {
				//Delete UpdateHostHeader
				req.Header.Del(header)

				//Add NDProxyHost header
				proxyHeader := textproto.CanonicalMIMEHeaderKey(s.Spec.Proxy.NDProxyRequest)
				req.Header.Set(proxyHeader, "1")

				//Reset the rawquery assuming URLRewrite may have reset the path
				if origURL := ctxGetOrigRequestURL(req); origURL != nil {
					log.Debug("Handler_success - Original Request URL", origURL.String())
					req.URL = origURL
				}

				//Set host
				req.URL.Host = updateHost[0]

				//set scheme
				req.URL.Scheme = "https"

				log.Debug("Handler_success - request scheme", req.URL.Scheme)
				log.Debug("Handler_success - request Host ", req.URL.Host)
				log.Debug("Handler_success - request URL ", req.URL)
			}

			proxy := &httputil.ReverseProxy{Director: director}

			//Get timeout value from X-Nd-Proxy-Timeout
			proxyTimeoutHeaderName := textproto.CanonicalMIMEHeaderKey(s.Spec.Proxy.NDProxyTimeoutHeader)
			proxyTimeout, ok := r.Header[proxyTimeoutHeaderName]
			if ok {
				timeout, err := strconv.ParseInt(proxyTimeout[0], 10, 32)
				if err != nil {
					log.Debug("setting default proxy timeout value")
					//Set proxy connect timeout to default 30 seconds
					timeout = 30
				}
				log.Debug("setting proxy timeout value to ", timeout, " seconds")
				proxy.Transport = s.defaultProxyTransport(float64(timeout))
			} else {
				log.Debug("setting proxy timeout value to 30 seconds")
				proxy.Transport = s.defaultProxyTransport(30)
			}
			log.Debug("Start update_host_header proxy")
			proxy.ServeHTTP(w, r)
			log.Debug("Done update_host_header proxy")
			return nil
		} else {
			log.Debug("update_host_header header not found")
		}
	}

	versionDef := s.Spec.VersionDefinition
	if !s.Spec.VersionData.NotVersioned && versionDef.Location == "url" && versionDef.StripPath {
		part := s.Spec.getVersionFromRequest(r)

		log.Info("Stripping version from url: ", part)

		r.URL.Path = strings.Replace(r.URL.Path, part+"/", "", 1)
		r.URL.RawPath = strings.Replace(r.URL.RawPath, part+"/", "", 1)
	}

	// Make sure we get the correct target URL
	s.Spec.SanitizeProxyPaths(r)

	addVersionHeader(w, r, s.Spec.GlobalConfig)

	t1 := time.Now()
	resp := s.Proxy.ServeHTTP(w, r)

	millisec := DurationToMillisecond(time.Since(t1))
	log.Debug("Upstream request took (ms): ", millisec)

	if resp.Response != nil {
		latency := analytics.Latency{
			Total:    int64(millisec),
			Upstream: int64(DurationToMillisecond(resp.UpstreamLatency)),
		}
		s.RecordHit(r, latency, resp.Response.StatusCode, resp.Response)
	}
	log.Debug("Done proxy")
	return nil
}

func (s *SuccessHandler) defaultProxyTransport(dialerTimeout float64) http.RoundTripper {
	log.Debug("defaultProxyTransport dialerTimeout: ", dialerTimeout)
	timeout := 30.0
	if dialerTimeout > 0 {
		log.Debug("Setting timeout for outbound request to: ", dialerTimeout)
		timeout = dialerTimeout
	}

	dialer := &net.Dialer{
		Timeout:   time.Duration(float64(timeout) * float64(time.Second)),
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	dialContextFunc := dialer.DialContext
	if s.Gw.dnsCacheManager.IsCacheEnabled() {
		dialContextFunc = s.Gw.dnsCacheManager.WrapDialer(dialer)
	}

	return &http.Transport{
		DialContext:           dialContextFunc,
		MaxIdleConns:          config.Global().MaxIdleConns,
		MaxIdleConnsPerHost:   config.Global().MaxIdleConnsPerHost, // default is 100
		ResponseHeaderTimeout: time.Duration(0) * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
}

// ServeHTTPWithCache will store the request details in the analytics store if necessary and proxy the request to it's
// final destination, this is invoked by the ProxyHandler or right at the start of a request chain if the URL
// Spec states the path is Ignored Itwill also return a response object for the cache
func (s *SuccessHandler) ServeHTTPWithCache(w http.ResponseWriter, r *http.Request) ProxyResponse {

	// Make sure we get the correct target URL
	s.Spec.SanitizeProxyPaths(r)

	t1 := time.Now()
	inRes := s.Proxy.ServeHTTPForCache(w, r)
	millisec := DurationToMillisecond(time.Since(t1))

	addVersionHeader(w, r, s.Spec.GlobalConfig)

	log.Debug("Upstream request took (ms): ", millisec)

	if inRes.Response != nil {
		latency := analytics.Latency{
			Total:    int64(millisec),
			Upstream: int64(DurationToMillisecond(inRes.UpstreamLatency)),
		}
		s.RecordHit(r, latency, inRes.Response.StatusCode, inRes.Response)
	}

	return inRes
}
