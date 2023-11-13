package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/2tvenom/terraform-provider-keycloakwebhook/internal/keycloak"
)

type (
	webhookDataSource struct {
		client *keycloak.KeycloakClient
	}

	webhooksDataSourceModel struct {
		Realm    types.String       `tfsdk:"realm"`
		Webhooks []webhookDataModel `tfsdk:"webhooks"`
	}

	webhookDataModel struct {
		ID         types.String   `tfsdk:"id"`
		Enabled    types.Bool     `tfsdk:"enabled"`
		Url        types.String   `tfsdk:"url"`
		CreatedBy  types.String   `tfsdk:"created_by"`
		CreatedAt  types.String   `tfsdk:"created_at"`
		EventTypes []types.String `tfsdk:"event_types"`
	}
)

var (
	_ datasource.DataSource              = &webhookDataSource{}
	_ datasource.DataSourceWithConfigure = &webhookDataSource{}
)

func NewWebhookDataSource() datasource.DataSource {
	return &webhookDataSource{}
}

func (d *webhookDataSource) Configure(
	ctx context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	var ok bool
	if d.client, ok = req.ProviderData.(*keycloak.KeycloakClient); !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected *keycloak.KeycloakClient, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}
}

func (d *webhookDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Datasource for receiving webhook list",
		Attributes: map[string]schema.Attribute{
			"realm": schema.StringAttribute{
				Required: true,
			},
			"webhooks": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Webhook internal ID",
						},
						"enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Enable/disable webhook",
						},
						"url": schema.StringAttribute{
							Computed:    true,
							Description: "Destination URL",
						},
						"created_by": schema.StringAttribute{
							Computed:    true,
							Description: "Creator ID",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Creation date",
						},
						"event_types": schema.ListAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "List of events. [Source](https://phasetwo.io/docs/audit-logs/admin/#resource-types)",
						},
					},
				},
			},
		},
	}
}

func (d *webhookDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_webhooks"
}

func (d *webhookDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var (
		state    webhooksDataSourceModel
		webhooks []keycloak.WebHook
		diags    = req.Config.Get(ctx, &state)
		err      error
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if webhooks, err = d.client.GetWebhooks(ctx, state.Realm.ValueString()); err != nil {
		resp.Diagnostics.AddError("Unable to Read Webooks", err.Error())
		return
	}

	// Map response body to model
	for _, w := range webhooks {
		var ws = webhookDataModel{
			ID:         types.StringValue(w.Id),
			Enabled:    types.BoolValue(w.Enabled),
			Url:        types.StringValue(w.Url),
			CreatedBy:  types.StringValue(w.CreatedBy),
			CreatedAt:  types.StringValue(time.Unix(w.CreatedAt, 0).Format(time.RFC3339)),
			EventTypes: make([]types.String, 0, len(w.EventTypes)),
		}

		for _, e := range w.EventTypes {
			ws.EventTypes = append(ws.EventTypes, types.StringValue(e))
		}

		state.Webhooks = append(state.Webhooks, ws)
	}

	// Set state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}
