package vault

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sso"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	ssoClientName       = "aws-vault"
	ssoClientType       = "public"
	oAuthTokenGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// CachedSSORoleProvider uses the keyring to cache SSO Role sessions.
type CachedSSORoleProvider struct {
	CredentialsName string
	Provider        *SSORoleProvider
	ExpiryWindow    time.Duration
	credentials.Expiry
}

// Retrieve the cached credentials or generate new ones.
func (p *CachedSSORoleProvider) Retrieve() (credentials.Value, error) {
	sessions := p.Provider.Keyring.Sessions()

	session, err := sessions.Retrieve(p.CredentialsName, "")
	if err != nil {
		// session lookup missed, we need to create a new one.
		session, err = p.Provider.getRoleCredentials()
		if err != nil {
			return credentials.Value{}, err
		}

		err = sessions.Store(p.CredentialsName, "", session)
		if err != nil {
			return credentials.Value{}, err
		}
	} else {
		log.Printf("Re-using cached credentials %s generated from GetRoleCredentials, expires in %s", FormatKeyForDisplay(*session.AccessKeyId), time.Until(*session.Expiration).String())
	}

	p.SetExpiration(*session.Expiration, p.ExpiryWindow)

	return credentials.Value{
		AccessKeyID:     *session.AccessKeyId,
		SecretAccessKey: *session.SecretAccessKey,
		SessionToken:    *session.SessionToken,
	}, nil
}

// SSORoleProvider creates temporary credentials for an SSO Role.
type SSORoleProvider struct {
	Keyring      *CredentialKeyring
	SSOClient    *sso.SSO
	OIDCClient   *ssooidc.SSOOIDC
	AccountID    string
	RoleName     string
	StartURL     string
	Duration     time.Duration
	ExpiryWindow time.Duration
	credentials.Expiry
}

// Retrieve generates a new set of temporary credentials using SSO GetRoleCredentials.
func (p *SSORoleProvider) Retrieve() (credentials.Value, error) {
	creds, err := p.getRoleCredentials()
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(*creds.Expiration, p.ExpiryWindow)
	return credentials.Value{
		AccessKeyID:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
	}, nil
}

func (p *SSORoleProvider) getRoleCredentials() (*sts.Credentials, error) {
	accessToken, err := p.GetSSOAccessToken()
	if err != nil {
		return nil, err
	}

	resp, err := p.SSOClient.GetRoleCredentials(&sso.GetRoleCredentialsInput{
		AccessToken: aws.String(accessToken),
		AccountId:   aws.String(p.AccountID),
		RoleName:    aws.String(p.RoleName),
	})
	if err != nil {
		return nil, err
	}

	expiration := aws.MillisecondsTimeValue(resp.RoleCredentials.Expiration)

	// This is needed because sessions.Store expects a sts.Credentials object.
	creds := &sts.Credentials{
		AccessKeyId:     resp.RoleCredentials.AccessKeyId,
		SecretAccessKey: resp.RoleCredentials.SecretAccessKey,
		SessionToken:    resp.RoleCredentials.SessionToken,
		Expiration:      aws.Time(expiration),
	}

	log.Printf("Got credentials %s for SSO role %s (account: %s), expires in %s", FormatKeyForDisplay(*resp.RoleCredentials.AccessKeyId), p.RoleName, p.AccountID, time.Until(expiration).String())

	return creds, nil
}

func (p *SSORoleProvider) GetSSOAccessToken() (string, error) {
	hasClientCredentials, err := p.Keyring.Has(p.StartURL)
	if err != nil {
		return "", err
	}

	if !hasClientCredentials {
		return "", nil
	}

	item, err := p.Keyring.Keyring.Get(p.StartURL)
	if err != nil {
		return "", err
	}

	var creds *ssoClientCredentials
	if err = json.Unmarshal(item.Data, &creds); err != nil {
		return "", fmt.Errorf("Invalid data in keyring: %v", err)
	}

	return creds, nil
}

func (p *SSORoleProvider) setClientCredentials(creds *ssoClientCredentials) error {
	bytes, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	return p.Keyring.Keyring.Set(keyring.Item{
		Key:   p.StartURL,
		Label: fmt.Sprintf("aws-vault (%s)", p.StartURL),
		Data:  bytes,

		// specific Keychain settings
		KeychainNotTrustApplication: true,
	})
}

type ssoClientCredentials struct {
	ID                    string
	Secret                string
	Expiration            time.Time
	AccessToken           string
	AccessTokenExpiration time.Time
}

func (p *SSORoleProvider) populateClientCredentials(creds *ssoClientCredentials) (*ssoClientCredentials, error) {
	if creds.Expiration.Before(time.Now()) {
		client, err := p.OIDCClient.RegisterClient(&ssooidc.RegisterClientInput{
			ClientName: aws.String(ssoClientName),
			ClientType: aws.String(ssoClientType),
		})
		if err != nil {
			return nil, err
		}
		creds = &ssoClientCredentials{
			ID:         aws.StringValue(client.ClientId),
			Secret:     aws.StringValue(client.ClientSecret),
			Expiration: aws.MillisecondsTimeValue(client.ClientSecretExpiresAt),
		}
	}

	if creds.AccessTokenExpiration.Before(time.Now()) {
		auth, err := p.OIDCClient.StartDeviceAuthorization(&ssooidc.StartDeviceAuthorizationInput{
			ClientId:     aws.String(creds.ID),
			ClientSecret: aws.String(creds.Secret),
			StartUrl:     aws.String(p.StartURL),
		})
		if err != nil {
			return nil, err
		}

		// Open browswer for user to complete login flow
		var browserCmd string

		switch runtime.GOOS {
		case "darwin":
			browserCmd = "open"
		case "linux":
			browserCmd = "xdg-open"
		case "windows":
			browserCmd = "start"
		default:
			return nil, fmt.Errorf("unable to open browser: unknown operating system: %s", runtime.GOOS)
		}
		if err := exec.Command(browserCmd, aws.StringValue(auth.VerificationUriComplete)).Run(); err != nil {
			return nil, err
		}

		var userToken *ssooidc.CreateTokenOutput

	Loop:
		for {
			// Sleep to allow login flow complete
			time.Sleep(3 * time.Second)

			token, err := p.OIDCClient.CreateToken(&ssooidc.CreateTokenInput{
				ClientId:     aws.String(creds.ID),
				ClientSecret: aws.String(creds.Secret),
				DeviceCode:   auth.DeviceCode,
				GrantType:    aws.String(oAuthTokenGrantType),
			})
			if err != nil {
				e, ok := err.(awserr.Error)
				if !ok || e.Code() != ssooidc.ErrCodeAuthorizationPendingException {
					return nil, err
				}
				continue Loop
			}
			userToken = token
			break Loop
		}

		creds.AccessToken = aws.StringValue(userToken.AccessToken)
		creds.AccessTokenExpiration = aws.MillisecondsTimeValue(userToken.ExpiresIn)
	}

	return creds, nil
}
