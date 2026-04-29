// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"fmt"
	"strings"
)

type AuthFamily string

const (
	AuthFamilyOIDC   AuthFamily = "oidc"
	AuthFamilySPIFFE AuthFamily = "spiffe"
	principalParts              = 2
)

type IdentityPrincipal string

type Identity struct {
	AuthFamily AuthFamily
	Principal  string
}

func ParsePrincipal(p IdentityPrincipal) (Identity, error) {
	raw := strings.TrimSpace(string(p))
	if raw == "" {
		return Identity{}, fmt.Errorf("principal is empty")
	}

	parts := strings.SplitN(raw, ":", principalParts)
	if len(parts) != principalParts {
		return Identity{}, fmt.Errorf("principal %q must be <auth-family>:<principal>", raw)
	}

	id := Identity{
		AuthFamily: AuthFamily(parts[0]),
		Principal:  parts[1],
	}

	if err := id.Validate(); err != nil {
		return Identity{}, err
	}

	return id, nil
}

func (i Identity) PrincipalString() IdentityPrincipal {
	return IdentityPrincipal(fmt.Sprintf("%s:%s", i.AuthFamily, i.Principal))
}

func (i Identity) Validate() error {
	switch i.AuthFamily {
	case AuthFamilyOIDC:
		if strings.TrimSpace(i.Principal) == "" {
			return fmt.Errorf("oidc principal is empty")
		}

		if !strings.Contains(i.Principal, ":") {
			return fmt.Errorf("oidc principal %q must contain provider key and principal value", i.Principal)
		}
	case AuthFamilySPIFFE:
		if strings.TrimSpace(i.Principal) == "" {
			return fmt.Errorf("spiffe principal is empty")
		}

		if !strings.HasPrefix(i.Principal, "spiffe://") {
			return fmt.Errorf("spiffe principal %q must start with spiffe://", i.Principal)
		}
	default:
		return fmt.Errorf("unsupported auth family %q", i.AuthFamily)
	}

	return nil
}
