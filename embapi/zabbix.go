package embapi

import (
	"fmt"
	"net/http"
	"strings"
)

func ZabbixCounterHandler(w http.ResponseWriter, r *http.Request, auth AuthMap) {
	if r.URL.Query().Get("format") != "zabbix" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid request"))
		return
	}

	switch r.URL.Query().Get("action") {
	case "request_count":
		token := r.URL.Query().Get("token")
		if token == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid request"))
			return
		}

		for _, a := range auth {
			if a.TokenName == token {
				zabbixResponse := fmt.Sprintf("%d\n", a.HourRequsetsNum)

				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(zabbixResponse))

				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not found"))
	case "list":
		var zabbixResponse strings.Builder
		first := true

		zabbixResponse.WriteString("[")
		for _, a := range auth {
			if !first {
				zabbixResponse.WriteString(",")
			}

			first = false

			zabbixResponse.WriteString(
				fmt.Sprintf(
					"{\"{#VPNGEN_PARTNER_NAME}\": \"%s\", \"{#VPNGEN_PARTNER_ID}\": \"%s\"}",
					a.TokenDesc,
					a.TokenName,
				),
			)
		}

		zabbixResponse.WriteString("]")

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(zabbixResponse.String()))
	default:
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid request"))
	}
}
