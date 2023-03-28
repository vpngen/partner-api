package embapi

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/vpngen/partner-api/gen/models"
	"github.com/vpngen/partner-api/gen/restapi/operations"
	"golang.org/x/crypto/ssh"

	"github.com/go-openapi/runtime/middleware"
)

type grantPkg struct {
	fullname string
	person   string
	desc     string
	wiki     string
	mnemo    string
	keydesk  string
	filename string
	wgconf   string
}

var DebugAdminUserName = "Вован"

// AddAdmin - create user.
func AddAdmin(params operations.PostAdminParams, principal interface{}, sshConfig *ssh.ClientConfig, addr netip.AddrPort) middleware.Responder {
	auth, ok := principal.(*AuthEntry)
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown principal: %#v\n", principal)

		return operations.NewPostAdminForbidden()
	}

	fmt.Fprintf(os.Stderr, "Token: %s\n", auth.TokenDgst)

	if !addr.IsValid() {
		fmt.Fprintln(os.Stderr, "DEBUG CALL: PostAdmin")

		admin, err := genGrants()
		if err != nil {
			fmt.Fprintf(os.Stderr, "DEBUG CALL: gen grants: %s\n", err)

			return operations.NewPostAdminDefault(500)
		}

		return operations.NewPostAdminCreated().WithPayload(admin.toModel())
	}

	fmt.Fprintf(os.Stderr, "Call: PostAdmin: %s\n", addr)

	admin, err := callMinistry(auth.TokenDgst, sshConfig, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Call: PostAdmin: call ministry: %s\n", err)

		return operations.NewPostAdminDefault(500)
	}

	return operations.NewPostAdminCreated().WithPayload(admin.toModel())
}

func (pkg *grantPkg) toModel() *models.Admin {
	return &models.Admin{
		UserName:            &pkg.fullname,
		SeedMnemo:           &pkg.mnemo,
		WireGuardConfig:     &pkg.wgconf,
		WireGuardConfigName: &pkg.filename,
		KeydeskIPV6Address:  &pkg.keydesk,
		PersonName:          &pkg.person,
		PersonDesc:          &pkg.desc,
		PersonDescLink:      &pkg.wiki,
	}
}
