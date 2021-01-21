package pkg

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/solo-io/ext-auth-plugins/api"
	"github.com/solo-io/go-utils/contextutils"
	"go.uber.org/zap"
)

var (
	UnexpectedConfigError = func(typ interface{}) error {
		return errors.New(fmt.Sprintf("unexpected config type %T", typ))
	}
	_ api.ExtAuthPlugin = new(Mtls)
)

type Mtls struct{}

type Config struct {
	HeaderName string
	Whitelist  []string
}

func (p *Mtls) NewConfigInstance(ctx context.Context) (interface{}, error) {
	return &Config{}, nil
}

func (p *Mtls) GetAuthService(ctx context.Context, configInstance interface{}) (api.AuthService, error) {
	config, ok := configInstance.(*Config)
	if !ok {
		return nil, UnexpectedConfigError(configInstance)
	}

	logger(ctx).Infow("Parsed MtlsAuthService config",
		zap.Any("HeaderName", config.HeaderName),
		zap.Any("Whitelist", config.Whitelist),
	)

	valueMap := map[string]bool{}
	for _, v := range config.Whitelist {
		valueMap[v] = true
	}

	return &MtlsAuthService{
		HeaderName: config.HeaderName,
		Whitelist:  valueMap,
	}, nil
}

type MtlsAuthService struct {
	HeaderName string
	Whitelist  map[string]bool
}

// You can use the provided context to perform operations that are bound to the services lifecycle.
func (c *MtlsAuthService) Start(context.Context) error {
	// no-op
	return nil
}

func (c *MtlsAuthService) Authorize(ctx context.Context, request *api.AuthorizationRequest) (*api.AuthorizationResponse, error) {
	// picking up the CN from the request's "Principal" attribute is an option.
	// but that would not help if we want to verify other attributes from the certificate, like its serial or hash.
	//request.CheckRequest.GetAttributes().GetSource().GetPrincipal()
	for key, value := range request.CheckRequest.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		if key == c.HeaderName {
			logger(ctx).Infow("Found required header, checking value.", "header", key, "value", value)

			cn := ""
			var cnRegexp = regexp.MustCompile(`.*Subject=(.*CN=(?P<CN>[a-zA-Z0-9:-_*.]+).*).*`)
			stringSubmatch := cnRegexp.FindStringSubmatch(value)
			for i, name := range cnRegexp.SubexpNames() {
				if name == "CN" {
					cn = stringSubmatch[i]
				}
			}

			if _, ok := c.Whitelist[cn]; ok {
				logger(ctx).Infow("Header value match. Allowing request.")
				response := api.AuthorizedResponse()

				// Append extra header
				response.CheckResponse.HttpResponse = &envoy_service_auth_v3.CheckResponse_OkResponse{
					OkResponse: &envoy_service_auth_v3.OkHttpResponse{
						Headers: []*envoy_config_core_v3.HeaderValueOption{{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:   "matched-allowed-headers",
								Value: "true",
							},
						}},
					},
				}
				return response, nil
			}
			logger(ctx).Infow("Header value does not match allowed values, denying access.")
			return api.UnauthorizedResponse(), nil
		}
	}
	logger(ctx).Infow("Required header not found, denying access")
	return api.UnauthorizedResponse(), nil
}

func logger(ctx context.Context) *zap.SugaredLogger {
	return contextutils.LoggerFrom(contextutils.WithLogger(ctx, "header_value_plugin"))
}
