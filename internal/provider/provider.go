package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/2tvenom/terraform-provider-keycloakwebhook/internal/keycloak"
)

type (
	webhookProvider struct {
		version string
	}

	providerModel struct {
		ClientId              types.String `tfsdk:"client_id"`
		ClientSecret          types.String `tfsdk:"client_secret"`
		Username              types.String `tfsdk:"username"`
		Password              types.String `tfsdk:"password"`
		Realm                 types.String `tfsdk:"realm"`
		Url                   types.String `tfsdk:"url"`
		BasePath              types.String `tfsdk:"base_path"`
		InitialLogin          types.Bool   `tfsdk:"initial_login"`
		ClientTimeout         types.Int64  `tfsdk:"client_timeout"`
		RootCACertificate     types.String `tfsdk:"root_ca_certificate"`
		TlsInsecureSkipVerify types.Bool   `tfsdk:"tls_insecure_skip_verify"`
		RedHatSSO             types.Bool   `tfsdk:"red_hat_sso"`
		AdditionalHeaders     types.Map    `tfsdk:"additional_headers"`
	}
)

var _ provider.Provider = &webhookProvider{}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &webhookProvider{
			version: version,
		}
	}
}

func (w webhookProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "keycloakwebhook"
	resp.Version = w.version
}

func (w webhookProvider) Schema(ctx context.Context, request provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provider for keycloak webhooks https://github.com/p2-inc/keycloak-events. Provider configuration fully compatibly with keycloak provider https://github.com/mrparkers/terraform-provider-keycloak",
		Attributes: map[string]schema.Attribute{
			"client_id": schema.StringAttribute{
				Required: true,
				//DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_CLIENT_ID", nil),
			},
			"client_secret": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				//DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_CLIENT_SECRET", nil),
			},
			"username": schema.StringAttribute{
				Optional: true,
				//DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_USER", nil),
			},
			"password": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				//DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_PASSWORD", nil),
			},
			"realm": schema.StringAttribute{
				Optional: true,
				//DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_REALM", "master"),
			},
			"url": schema.StringAttribute{
				Optional:    true,
				Description: "The base URL of the Keycloak instance, before `/auth`",
				//DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_URL", nil),
			},
			"initial_login": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether or not to login to Keycloak instance on provider initialization",
				//Default:     true,
			},
			"client_timeout": schema.Int64Attribute{
				Optional:    true,
				Description: "Timeout (in seconds) of the Keycloak client",
				//DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_CLIENT_TIMEOUT", 15),
			},
			"root_ca_certificate": schema.StringAttribute{
				Optional:    true,
				Description: "Allows x509 calls using an unknown CA certificate (for development purposes)",
			},
			"tls_insecure_skip_verify": schema.BoolAttribute{
				Optional:    true,
				Description: "Allows ignoring insecure certificates when set to true. Defaults to false. Disabling security check is dangerous and should be avoided.",
				//Default:     false,
			},
			"red_hat_sso": schema.BoolAttribute{
				Optional:    true,
				Description: "When true, the provider will treat the Keycloak instance as a Red Hat SSO server, specifically when parsing the version returned from the /serverinfo API endpoint.",
				//Default:     false,
			},
			"base_path": schema.StringAttribute{
				Optional: true,
				//DefaultFunc: schema.EnvDefaultFunc("KEYCLOAK_BASE_PATH", ""),
			},
			"additional_headers": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (w webhookProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewWebhookDataSource,
	}
}

func (w webhookProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewWebhookResource,
	}
}

func (w webhookProvider) Configure(
	ctx context.Context,
	req provider.ConfigureRequest,
	resp *provider.ConfigureResponse,
) {
	var (
		config providerModel
		diags  = req.Config.Get(ctx, &config)
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		url string
		ok  bool
	)
	if url, ok = getConfigEnv(config.Url, "KEYCLOAK_URL", ""); !ok {
		resp.Diagnostics.AddAttributeError(
			path.Root("url"),
			"Missing Keycloak url",
			"The provider cannot create the Keycloak API client as there is a missing or empty value for the "+
				"KEYCLOAK API host. Set the host value in the configuration or use the KEYCLOAK_URL environment "+
				"variable. If either is already set, ensure the value is not empty.",
		)
	}

	var clientID string
	if clientID, ok = getConfigEnv(config.ClientId, "KEYCLOAK_CLIENT_ID", ""); !ok {
		resp.Diagnostics.AddAttributeError(
			path.Root("client_id"),
			"Missing Keycloak client_id",
			"The provider cannot create the Keycloak API client as there is a missing or empty value for the "+
				"KEYCLOAK API host. Set the host value in the configuration or use the KEYCLOAK_CLIENT_ID environment "+
				"variable. If either is already set, ensure the value is not empty.",
		)
	}

	ctx = tflog.SetField(ctx, "client_id", clientID)
	ctx = tflog.SetField(ctx, "ENV", os.Getenv("KEYCLOAK_CLIENT_ID"))
	ctx = tflog.SetField(ctx, "val", config.ClientId.ValueString())
	ctx = tflog.SetField(ctx, "val_is_null", config.ClientId.IsNull())
	tflog.Debug(ctx, "keycloak client id")

	var (
		realm, _        = getConfigEnv(config.Realm, "KEYCLOAK_REALM", "master")
		basePath, _     = getConfigEnv(config.BasePath, "KEYCLOAK_BASE_PATH", "")
		clientSecret, _ = getConfigEnv(config.ClientSecret, "KEYCLOAK_CLIENT_SECRET", "")
		username, _     = getConfigEnv(config.Username, "KEYCLOAK_USER", "")
		password, _     = getConfigEnv(config.Password, "KEYCLOAK_PASSWORD", "")

		rootCaCertificate     = config.RootCACertificate.ValueString()
		initialLogin          = getBoolConfig(config.InitialLogin, true)
		tlsInsecureSkipVerify = config.TlsInsecureSkipVerify.ValueBool()
		redHatSSO             = config.RedHatSSO.ValueBool()
		clientTimeout         = getIntConfig(config.ClientTimeout, 15)

		additionalHeaders = map[string]string{}
	)

	for k, v := range config.AdditionalHeaders.Elements() {
		additionalHeaders[k] = v.String()
	}

	userAgent := fmt.Sprintf(
		"HashiCorp Terraform/%s (+https://www.terraform.io) Terraform Framework/v1.4.2",
		req.TerraformVersion,
	)

	var (
		keycloakClient *keycloak.KeycloakClient
		err            error
	)

	keycloakClient, err = keycloak.NewKeycloakClient(
		ctx,
		url,
		basePath,
		clientID,
		clientSecret,
		realm,
		username,
		password,
		initialLogin,
		int(clientTimeout),
		rootCaCertificate,
		tlsInsecureSkipVerify,
		userAgent,
		redHatSSO,
		additionalHeaders,
	)
	if err != nil {
		resp.Diagnostics.AddError("error initializing keycloak provider", err.Error())
	}

	resp.ResourceData = keycloakClient
	resp.DataSourceData = keycloakClient
}

func getIntConfig(v types.Int64, fallback int64) int64 {
	if !v.IsNull() {
		return v.ValueInt64()
	}

	return fallback
}
func getBoolConfig(v types.Bool, fallback bool) bool {
	if !v.IsNull() {
		return v.ValueBool()
	}

	return fallback
}

func getConfigEnv(v types.String, key, fallback string) (value string, _ bool) {
	value = os.Getenv(key)
	switch {
	case value != "":
	case !v.IsNull():
		value = v.ValueString()
	default:
		value = fallback
	}

	return value, value != ""
}

func getEnv(key, fallback string) string {
	var value, exists = os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}
