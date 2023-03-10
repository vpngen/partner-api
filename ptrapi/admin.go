package ptrapi

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http/httputil"
	"net/netip"
	"os"
	"strings"

	"github.com/vpngen/keydesk/kdlib"
	"github.com/vpngen/partner-api/gen/models"
	"github.com/vpngen/partner-api/gen/restapi/operations"
	"github.com/vpngen/wordsgens/namesgenerator"
	"github.com/vpngen/wordsgens/seedgenerator"
	"golang.org/x/crypto/ssh"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/go-openapi/runtime/middleware"
)

const (
	fakeSeedPrefix    = "етитьколотить"
	fakeKeydeskPrefix = "fc00::beaf:0/112"
	fakeEndpointNet   = "182.31.10.0/24"
	fakeCGNAT         = "100.64.0.0/10"
	fakeULA           = "fd00::/8"
	testPrefix        = "DoNotUse "
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
func AddAdmin(params operations.PostAdminParams, principal interface{}, addr netip.AddrPort) middleware.Responder {
	auth, ok := principal.(AuthEntry)
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown principal: %#v\n", principal)

		return operations.NewPostAdminForbidden()
	}

	fmt.Fprintf(os.Stderr, "Token: %s\n", auth.TokenDigest)

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

	admin, err := callMinistry(auth.SSHConfig, addr)
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

func callMinistry(conf *ssh.ClientConfig, addr netip.AddrPort) (*grantPkg, error) {
	var opts = &grantPkg{}

	cmd := "-ch"

	fmt.Fprintf(os.Stderr, "%s#%s -> %s\n", conf.User, addr, cmd)

	client, err := ssh.Dial("tcp", addr.String(), conf)
	if err != nil {
		return nil, fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	var b, e bytes.Buffer

	session.Stdout = &b
	session.Stderr = &e

	if err := session.Run(cmd); err != nil {
		fmt.Fprintf(os.Stderr, "session errors:\n%s\n", e.String())

		return nil, fmt.Errorf("ssh run: %w", err)
	}

	r := bufio.NewReader(httputil.NewChunkedReader(&b))

	fullname, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("fullname read: %w", err)
	}

	opts.fullname = strings.Trim(fullname, "\r\n\t ")

	person, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("person read: %w", err)
	}

	opts.person = strings.Trim(person, "\r\n\t ")

	desc64, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("desc64 read: %w", err)
	}

	desc, err := base64.StdEncoding.DecodeString(desc64)
	if err != nil {
		return nil, fmt.Errorf("desc64 decoding: %w", err)
	}

	opts.desc = string(desc)

	url64, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("url64 read: %w", err)
	}

	wiki, err := base64.StdEncoding.DecodeString(url64)
	if err != nil {
		return nil, fmt.Errorf("url64 decoding: %w", err)
	}

	opts.wiki = string(wiki)

	mnemo, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("mnemo read: %w", err)
	}

	opts.mnemo = strings.Trim(mnemo, "\r\n\t ")

	keydesk, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("keydesk read: %w", err)
	}

	opts.keydesk = strings.Trim(keydesk, "\r\n\t ")

	filename, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("filename read: %w", err)
	}

	opts.filename = strings.Trim(filename, "\r\n\t ")

	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("chunk read: %w", err)
	}

	opts.wgconf = string(buf)

	return opts, nil
}

func genGrants() (*grantPkg, error) {
	var opts = &grantPkg{}

	fullname, person, err := namesgenerator.PhysicsAwardeeShort()
	if err != nil {
		return nil, fmt.Errorf("physics gen: %w", err)
	}

	opts.fullname = testPrefix + fullname
	opts.person = person.Name
	opts.desc = person.Desc
	opts.wiki = person.URL

	opts.mnemo, _, _, err = seedgenerator.Seed(seedgenerator.ENT64, fakeSeedPrefix)
	if err != nil {
		return nil, fmt.Errorf("gen seed6: %w", err)
	}

	opts.keydesk = kdlib.RandomAddrIPv6(netip.MustParsePrefix(fakeKeydeskPrefix)).String()

	numbered := fmt.Sprintf("%03d %s", rand.Int31n(256), fullname)
	opts.filename = kdlib.SanitizeFilename(numbered)

	wgkey, err := wgtypes.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("gen wg psk: %w", err)
	}

	wgpriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("gen wg psk: %w", err)
	}

	wgpub := wgpriv.PublicKey()

	tmpl := `[Interface]
Address = %s
PrivateKey = %s
DNS = %s

[Peer]
Endpoint = %s:51820
PublicKey = %s
PresharedKey = %s
AllowedIPs = 0.0.0.0/0,::/0
`

	ipv4 := kdlib.RandomAddrIPv4(netip.MustParsePrefix(fakeCGNAT))
	ipv6 := kdlib.RandomAddrIPv6(netip.MustParsePrefix(fakeULA))
	ep := kdlib.RandomAddrIPv4(netip.MustParsePrefix(fakeEndpointNet))

	opts.wgconf = fmt.Sprintf(
		tmpl,
		netip.PrefixFrom(ipv4, 32).String()+","+netip.PrefixFrom(ipv6, 128).String(),
		base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(wgpriv[:]),
		ipv4.String()+","+ipv6.String(),
		ep.String(),
		base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(wgpub[:]),
		base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(wgkey[:]),
	)

	return opts, nil
}
