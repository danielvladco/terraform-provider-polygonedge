package secrets

import (
	"context"

	"github.com/0xPolygon/polygon-edge/crypto"
	"github.com/0xPolygon/polygon-edge/network"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/libp2p/go-libp2p/core/peer"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource = &secretsResource{}
)

// secretsDataSourceModel maps the data source schema data.
type secretsDataSourceModel struct {
	ValidatorKeyEncoded    types.String `tfsdk:"validator_key_encoded"`
	ValidatorBLSKeyEncoded types.String `tfsdk:"validator_bls_key_encoded"`
	NetworkKeyEncoded      types.String `tfsdk:"network_key_encoded"`

	Address   types.String `tfsdk:"address"`
	BLSPubkey types.String `tfsdk:"bls_pubkey"`
	NodeID    types.String `tfsdk:"node_id"`
}

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource = &secretsResource{}
)

// NewSecretsResource is a helper function to simplify the provider implementation.
func NewSecretsResource() resource.Resource {
	return &secretsResource{}
}

// secretsResource is the data source implementation.
type secretsResource struct {
}

// Metadata returns the data source type name.
func (d *secretsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secrets"
}

// Schema defines the schema for the data source.
func (d *secretsResource) Schema(_ context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version: 1,
		Attributes: map[string]schema.Attribute{
			"validator_key_encoded": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Encoded validator key. Must be stored in a polygon-edge supported secrets manager.",
			},
			"validator_bls_key_encoded": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Encoded validator BLS key. Must be stored in a polygon-edge supported secrets manager.",
			},
			"network_key_encoded": schema.StringAttribute{
				Computed:    true,
				Sensitive:   true,
				Description: "Encoded network key. Must be stored in a polygon-edge supported secrets manager.",
			},
			"address": schema.StringAttribute{
				Computed:    true,
				Description: "Validator address.",
			},
			"bls_pubkey": schema.StringAttribute{
				Computed:    true,
				Description: "Validator public key.",
			},
			"node_id": schema.StringAttribute{
				Computed:    true,
				Description: "Node ID.",
			},
		},
	}
}

func (d *secretsResource) Create(ctx context.Context, _ resource.CreateRequest, resp *resource.CreateResponse) {
	// Validator Key
	validatorKey, validatorKeyEncoded, err := crypto.GenerateAndEncodeECDSAPrivateKey()
	if err != nil {
		resp.Diagnostics.AddError("Unable to generate ECDSA key", err.Error())
		return
	}
	// Validator BLS key
	blsSecretKey, blsSecretKeyEncoded, err := crypto.GenerateAndEncodeBLSSecretKey()
	if err != nil {
		resp.Diagnostics.AddError("Unable to create generate BLS ket", err.Error())
		return
	}

	pubkeyBytes, err := crypto.BLSSecretKeyToPubkeyBytes(blsSecretKey)
	if err != nil {
		resp.Diagnostics.AddError("Unable to get BLS public key", err.Error())
		return
	}

	// Network key
	libp2pKey, libp2pKeyEncoded, err := network.GenerateAndEncodeLibp2pKey()
	if err != nil {
		resp.Diagnostics.AddError("Unable to generate network key", err.Error())
		return
	}

	nodeID, err := peer.IDFromPrivateKey(libp2pKey)
	if err != nil {
		resp.Diagnostics.AddError("Unable to get nodeID", err.Error())
		return
	}
	diags := resp.State.Set(ctx, &secretsDataSourceModel{
		ValidatorKeyEncoded:    types.StringValue(string(validatorKeyEncoded)),
		Address:                types.StringValue(crypto.PubKeyToAddress(&validatorKey.PublicKey).String()),
		ValidatorBLSKeyEncoded: types.StringValue(string(blsSecretKeyEncoded)),
		BLSPubkey:              types.StringValue(string(pubkeyBytes)),
		NetworkKeyEncoded:      types.StringValue(string(libp2pKeyEncoded)),
		NodeID:                 types.StringValue(nodeID.String()),
	})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *secretsResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	// NO-OP: all there is to read is in the State, and response is already populated with that.
	tflog.Debug(ctx, "Reading secrets from state")
}

func (d *secretsResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	// NO-OP: since this resource cannot change
}

func (d *secretsResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	tflog.Debug(ctx, "Removing secrets from state")
}
