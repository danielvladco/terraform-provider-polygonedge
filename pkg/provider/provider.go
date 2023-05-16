package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/danielvladco/terraform-provider-polygon-edge/pkg/secrets"
)

// Ensure the implementation satisfies the expected interfaces
var (
	_ provider.Provider = &polygonEdgeProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New() provider.Provider {
	return &polygonEdgeProvider{}
}

// polygonEdgeProvider is the provider implementation.
type polygonEdgeProvider struct{}

// Metadata returns the provider type name.
func (p *polygonEdgeProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "polygonedge"
}

// Schema defines the provider-level schema for configuration data.
func (p *polygonEdgeProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
}

// Configure prepares common configs for data sources and resources.
func (p *polygonEdgeProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

// DataSources defines the data sources implemented in the provider.
func (p *polygonEdgeProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// Resources defines the resources implemented in the provider.
func (p *polygonEdgeProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		secrets.NewSecretsResource,
	}
}
