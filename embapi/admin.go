package embapi

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/vpngen/ministry"
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

	admin, err := callMinistry(auth.TokenDgst, sshConfig, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Call: PostAdmin: call ministry: %s\n", err)

		return operations.NewPostAdminDefault(500)
	}

	return operations.NewPostAdminCreated().WithPayload(admin.toModel())
}

func AddAdminV2(params operations.PostV2AdminParams, principal interface{}, sshConfig *ssh.ClientConfig, addr netip.AddrPort) middleware.Responder {
	auth, ok := principal.(*AuthEntry)
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown principal: %#v\n", principal)

		return operations.NewPostV2AdminForbidden()
	}

	fmt.Fprintf(os.Stderr, "Token: %s\n", auth.TokenDgst)

	if !addr.IsValid() {
		fmt.Fprintln(os.Stderr, "DEBUG CALL: PostV2Admin")

		answer, err := genGrantsV2()
		if err != nil {
			fmt.Fprintf(os.Stderr, "DEBUG CALL: gen grants: %s\n", err)

			return operations.NewPostV2AdminDefault(500)
		}

		return operations.NewPostV2AdminCreated().WithPayload(answerToModel(answer))
	}

	answer, err := callMinistryV2(auth.TokenDgst, sshConfig, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Call: PostV2Admin: call ministry: %s\n", err)

		return operations.NewPostV2AdminDefault(500)
	}

	return operations.NewPostV2AdminCreated().WithPayload(answerToModel(answer))
}

func answerToModel(answer *ministry.Answer) *models.Newadmin {
	keydesk := answer.KeydeskIPv6.String()
	personGender := int32(answer.Person.Gender)

	admin := &models.Newadmin{
		Name:        &answer.Name,
		Mnemo:       &answer.Mnemo,
		KeydeskIPV6: &keydesk,
		Person: &models.Person{
			Name:   &answer.Person.Name,
			Desc:   &answer.Person.Desc,
			URL:    &answer.Person.URL,
			Gender: &personGender,
		},
		Configs: &models.Newuser{},
	}

	if answer.Configs.UserName != nil {
		admin.Configs.UserName = answer.Configs.UserName
	}

	if answer.Configs.WireguardConfig != nil &&
		answer.Configs.WireguardConfig.FileContent != nil &&
		answer.Configs.WireguardConfig.FileName != nil &&
		answer.Configs.WireguardConfig.TonnelName != nil {
		admin.Configs.WireguardConfig = &models.NewuserWireguardConfig{
			FileName:    answer.Configs.WireguardConfig.FileName,
			FileContent: answer.Configs.WireguardConfig.FileContent,
			TonnelName:  answer.Configs.WireguardConfig.TonnelName,
		}
	}

	if answer.Configs.AmnzOvcConfig != nil &&
		answer.Configs.AmnzOvcConfig.FileContent != nil &&
		answer.Configs.AmnzOvcConfig.FileName != nil &&
		answer.Configs.AmnzOvcConfig.TonnelName != nil {
		admin.Configs.AmnzOvcConfig = &models.NewuserAmnzOvcConfig{
			FileName:    answer.Configs.AmnzOvcConfig.FileName,
			FileContent: answer.Configs.AmnzOvcConfig.FileContent,
			TonnelName:  answer.Configs.AmnzOvcConfig.TonnelName,
		}
	}

	if answer.Configs.OutlineConfig != nil &&
		answer.Configs.OutlineConfig.AccessKey != nil {
		admin.Configs.OutlineConfig = &models.NewuserOutlineConfig{
			AccessKey: answer.Configs.OutlineConfig.AccessKey,
		}
	}

	if answer.Configs.IPSecL2TPManualConfig != nil &&
		answer.Configs.IPSecL2TPManualConfig.Username != nil &&
		answer.Configs.IPSecL2TPManualConfig.Password != nil &&
		answer.Configs.IPSecL2TPManualConfig.PSK != nil &&
		answer.Configs.IPSecL2TPManualConfig.Server != nil {
		admin.Configs.IPSecL2TPManualConfig = &models.NewuserIPSecL2TPManualConfig{
			Username: answer.Configs.IPSecL2TPManualConfig.Username,
			Password: answer.Configs.IPSecL2TPManualConfig.Password,
			PSK:      answer.Configs.IPSecL2TPManualConfig.PSK,
			Server:   answer.Configs.IPSecL2TPManualConfig.Server,
		}
	}

	return admin
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

func Longping(params operations.PostLongpingParams) middleware.Responder {
	time.Sleep(20 * time.Second)

	fmt.Fprintf(os.Stderr, "DEBUG CALL: PostLongping\n")

	return operations.NewPostLongpingOK().WithPayload(&operations.PostLongpingOKBody{Message: "pong"})
}
