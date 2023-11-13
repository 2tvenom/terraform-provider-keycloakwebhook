package provider

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/2tvenom/terraform-provider-keycloakwebhook/internal/keycloak"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &webhookResource{}
	_ resource.ResourceWithConfigure = &webhookResource{}
)

type (
	// webhookResource is the resource implementation.
	webhookResource struct {
		client *keycloak.KeycloakClient
	}

	webhookModel struct {
		ID         types.String   `tfsdk:"id"`
		Enabled    types.Bool     `tfsdk:"enabled"`
		Url        types.String   `tfsdk:"url"`
		Secret     types.String   `tfsdk:"secret"`
		CreatedBy  types.String   `tfsdk:"created_by"`
		CreatedAt  types.String   `tfsdk:"created_at"`
		EventTypes []types.String `tfsdk:"event_types"`
	}

	webhooksResourceModel struct {
		Realm types.String   `tfsdk:"realm"`
		Items []webhookModel `tfsdk:"items"`
	}
)

// NewWebhookResource is a helper function to simplify the provider implementation.
func NewWebhookResource() resource.Resource {
	return &webhookResource{}
}

func (r *webhookResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	var ok bool
	if r.client, ok = req.ProviderData.(*keycloak.KeycloakClient); !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected *keycloak.KeycloakClient, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}
}

// Metadata returns the resource type name.
func (r *webhookResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_webhook"
}

// Schema defines the schema for the resource.
func (r *webhookResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Create webhook",
		Attributes: map[string]schema.Attribute{
			"realm": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Realm name",
			},
			"items": schema.ListNestedAttribute{
				Required: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
							Description: "Webhook internal ID",
						},
						"secret": schema.StringAttribute{
							Required:    true,
							Sensitive:   true,
							Description: "Secret for generating webhook signature. [Source code](https://github.com/p2-inc/keycloak-events/blob/777425be8fe8f9f072b620917f6036f0242d5641/src/main/java/io/phasetwo/keycloak/events/HttpSenderEventListenerProvider.java#L108)",
						},
						"enabled": schema.BoolAttribute{
							Required:    true,
							Description: "Enable/disable webhook",
						},
						"url": schema.StringAttribute{
							Required:    true,
							Description: "Destination URL",
						},
						"event_types": schema.ListAttribute{
							Required:    true,
							ElementType: types.StringType,
							Description: "List of events. [Source](https://phasetwo.io/docs/audit-logs/admin/#resource-types)",
						},
						"created_by": schema.StringAttribute{
							Computed:    true,
							Description: "Creator ID",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Creation date",
						},
					},
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *webhookResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var (
		plan  webhooksResourceModel
		diags = req.Plan.Get(ctx, &plan)
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		w   []keycloak.WebHook
		err error
	)
	if w, err = r.resourceModelToWebhook(plan); err != nil {
		resp.Diagnostics.AddError(
			"Error convert webhook from plan",
			"Could not create webhook, unexpected error: "+err.Error(),
		)
		return
	}

	for i := range w {
		// Creates new webhook
		if err = r.client.CreateWebhooks(ctx, plan.Realm.ValueString(), &w[i]); err != nil {
			resp.Diagnostics.AddError(
				"Error creating webhook",
				"Could not create webhook, unexpected error: "+err.Error(),
			)
			return
		}
	}

	if err = r.webhookToResourceModel(w, &plan); err != nil {
		resp.Diagnostics.AddError(
			"Error converting webhook to resource model",
			"Could not convert webhook to resource model, unexpected error: "+err.Error(),
		)
		return
	}

	// Set state to fully populated data
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *webhookResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Retrieve values from plan
	var (
		state webhooksResourceModel
		diags = req.State.Get(ctx, &state)
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		w   []keycloak.WebHook
		err error
	)
	if w, err = r.client.GetWebhooks(ctx, state.Realm.ValueString()); err != nil {
		if errors.Is(err, keycloak.ErrNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error Reading webhook",
			"Could not read webhooks: "+err.Error(),
		)
		return
	}

	if err = r.webhookToResourceModel(w, &state); err != nil {
		resp.Diagnostics.AddError(
			"Error converting webhook to resource model",
			"Could not convert webhook to resource model, unexpected error: "+err.Error(),
		)
	}

	// Set refreshed state
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *webhookResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve values from plan
	var plan, state webhooksResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		ws, wsd []keycloak.WebHook
		err     error
	)

	// actualize plan
	if ws, err = r.resourceModelToWebhook(plan); err != nil {
		resp.Diagnostics.AddError(
			"Error convert resource model to webhook",
			"Could not update webhook, unexpected error: "+err.Error(),
		)
		return
	}

	for i := range ws {
		var j = slices.IndexFunc(state.Items, func(model webhookModel) bool {
			return model.ID.ValueString() == ws[i].Id
		})

		// new entity, need to create
		if j < 0 {
			if err = r.client.CreateWebhooks(ctx, plan.Realm.ValueString(), &ws[i]); err != nil {
				resp.Diagnostics.AddError(
					"Error creating webhook",
					"Could not create webhook, unexpected error: "+err.Error(),
				)
				return
			}
			continue
		}

		if err = r.client.UpdateWebhooks(ctx, plan.Realm.ValueString(), &ws[i]); err != nil {
			resp.Diagnostics.AddError(
				"Error Updating webhook",
				"Could not update webhook, unexpected error: "+err.Error(),
			)
			return
		}
	}

	// actualize state
	if wsd, err = r.resourceModelToWebhook(state); err != nil {
		resp.Diagnostics.AddError(
			"Error convert resource model to webhook",
			"Could not update webhook, unexpected error: "+err.Error(),
		)
		return
	}

	for i := range wsd {
		var j = slices.IndexFunc(plan.Items, func(model webhookModel) bool {
			return model.ID.ValueString() == wsd[i].Id
		})

		// have in state, skip
		if j >= 0 {
			continue
		}

		if wsd[i].Id != "" {
			// not have in state, need deleting
			if err = r.client.DeleteWebhooks(ctx, plan.Realm.ValueString(), &wsd[i]); err != nil {
				resp.Diagnostics.AddError(
					"Error Deleting webhook",
					"Could not delete webhook, unexpected error: "+err.Error(),
				)
				return
			}
		}
	}

	if ws, err = r.client.GetWebhooks(ctx, plan.Realm.ValueString()); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading webhooks",
			"Could not read webhooks: "+err.Error(),
		)
		return
	}

	if err = r.webhookToResourceModel(ws, &plan); err != nil {
		resp.Diagnostics.AddError(
			"Error converting webhook to resource model",
			"Could not convert webhook to resource model, unexpected error: "+err.Error(),
		)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *webhookResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Retrieve values from state
	var (
		plan  webhooksResourceModel
		diags = req.State.Get(ctx, &plan)
	)

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var (
		ws  []keycloak.WebHook
		err error
	)
	if ws, err = r.resourceModelToWebhook(plan); err != nil {
		resp.Diagnostics.AddError(
			"Error convert resource model to webhook",
			"Could not update webhook, unexpected error: "+err.Error(),
		)
		return
	}

	for i := range ws {
		if err = r.client.DeleteWebhooks(ctx, plan.Realm.ValueString(), &ws[i]); err != nil {
			resp.Diagnostics.AddError(
				"Error Deleting webhook",
				"Could not delete webhook, unexpected error: "+err.Error(),
			)
			return
		}
	}
}

func (r *webhookResource) resourceModelToWebhook(m webhooksResourceModel) (_ []keycloak.WebHook, err error) {
	var (
		ws    = make([]keycloak.WebHook, 0, len(m.Items))
		w     keycloak.WebHook
		u     = map[string]struct{}{}
		realm = m.Realm.ValueString()
	)
	for _, i := range m.Items {
		w = r.modelToWebhook(realm, i)

		if _, ok := u[w.Url]; ok {
			return nil, errors.New("webhooks must contains only unique urls")
		}

		u[w.Url] = struct{}{}

		ws = append(ws, w)
	}

	return ws, nil
}

func (r *webhookResource) modelToWebhook(realm string, m webhookModel) (w keycloak.WebHook) {
	w = keycloak.WebHook{
		Id:     m.ID.ValueString(),
		Realm:  realm,
		Secret: m.Secret.ValueString(),
		//CreatedBy:  m.CreatedBy.ValueString(),
		Enabled:    m.Enabled.ValueBool(),
		Url:        m.Url.ValueString(),
		EventTypes: make([]string, 0, len(m.EventTypes)),
	}
	for _, e := range m.EventTypes {
		w.EventTypes = append(w.EventTypes, e.ValueString())
	}

	return w
}

func (r *webhookResource) webhookToResourceModel(ws []keycloak.WebHook, m *webhooksResourceModel) error {
	for _, i := range ws {
		var j = slices.IndexFunc(m.Items, func(model webhookModel) bool {
			return model.Url.ValueString() == i.Url
		})

		if j == -1 {
			if i.Realm != m.Realm.ValueString() {
				return fmt.Errorf("invalid webhook realm, expected %s, got %s", m.Realm.ValueString(), i.Realm)
			}

			var w = webhookModel{
				ID:         types.StringValue(i.Id),
				Url:        types.StringValue(i.Url),
				Enabled:    types.BoolValue(i.Enabled),
				CreatedBy:  types.StringValue(i.CreatedBy),
				CreatedAt:  types.StringValue(time.UnixMilli(i.CreatedAt).Format(time.RFC3339)),
				EventTypes: make([]types.String, 0, len(i.EventTypes)),
			}

			for _, e := range i.EventTypes {
				w.EventTypes = append(w.EventTypes, types.StringValue(e))
			}

			m.Items = append(m.Items, w)
			continue
		}

		m.Items[j].ID = types.StringValue(i.Id)
		m.Items[j].Url = types.StringValue(i.Url)
		m.Items[j].Enabled = types.BoolValue(i.Enabled)
		m.Items[j].CreatedBy = types.StringValue(i.CreatedBy)
		m.Items[j].CreatedAt = types.StringValue(time.UnixMilli(i.CreatedAt).Format(time.RFC3339))

		if len(m.Items[j].EventTypes) == 0 {
			m.Items[j].EventTypes = make([]types.String, 0, len(i.EventTypes))
			for _, e := range i.EventTypes {
				m.Items[j].EventTypes = append(m.Items[j].EventTypes, types.StringValue(e))
			}
			return nil
		}

		// delete all event types what not contain updated webhook
		slices.DeleteFunc(m.Items[j].EventTypes, func(t types.String) bool {
			for _, e := range i.EventTypes {
				if e == t.ValueString() {
					return false
				}
			}

			return true
		})

		// add to state event types, what contain in webhook, but not contain in state
		var ok bool
		for _, e := range i.EventTypes {
			ok = slices.ContainsFunc(m.Items[j].EventTypes, func(t types.String) bool {
				return t.ValueString() == e
			})

			if !ok {
				m.Items[j].EventTypes = append(m.Items[j].EventTypes, types.StringValue(e))
			}
		}
	}

	return nil
}
