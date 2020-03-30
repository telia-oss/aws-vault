package vault

import (
	"log"
	"os/exec"
	"runtime"
	"time"

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
	Keyring         *CredentialKeyring
	ExpiryWindow    time.Duration
	credentials.Expiry
}

// Retrieve the cached credentials or generate new ones.
func (p *CachedSSORoleProvider) Retrieve() (credentials.Value, error) {
	sessions := p.Keyring.Sessions()

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
	client, err := p.OIDCClient.RegisterClient(&ssooidc.RegisterClientInput{
		ClientName: aws.String(ssoClientName),
		ClientType: aws.String(ssoClientType),
	})
	if err != nil {
		return nil, err
	}

	auth, err := p.OIDCClient.StartDeviceAuthorization(&ssooidc.StartDeviceAuthorizationInput{
		ClientId:     client.ClientId,
		ClientSecret: client.ClientSecret,
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
			ClientId:     client.ClientId,
			ClientSecret: client.ClientSecret,
			DeviceCode:   auth.DeviceCode,
			GrantType:    aws.String(oAuthTokenGrantType),
		})
		if err != nil {
			e, ok := err.(awserr.Error)
			if !ok || e.Code() != ssooidc.ErrCodeAuthorizationPendingException {
				panic(err)
			}
			continue Loop
		}
		userToken = token
		break Loop
	}

	resp, err := p.SSOClient.GetRoleCredentials(&sso.GetRoleCredentialsInput{
		AccessToken: userToken.AccessToken,
		AccountId:   aws.String(p.AccountID),
		RoleName:    aws.String(p.RoleName),
	})
	if err != nil {
		return nil, err
	}
	expiration := time.Unix(aws.Int64Value(resp.RoleCredentials.Expiration)/int64(time.Second/time.Millisecond), 0)

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
