package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	vault "github.com/hashicorp/vault/api"
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type vaultLogin struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          interface{} `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          struct {
		ClientToken   string   `json:"client_token"`
		Accessor      string   `json:"accessor"`
		Policies      []string `json:"policies"`
		TokenPolicies []string `json:"token_policies"`
		Metadata      struct {
			Username string `json:"username"`
		} `json:"metadata"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
		EntityID      string `json:"entity_id"`
		TokenType     string `json:"token_type"`
		Orphan        bool   `json:"orphan"`
	} `json:"auth"`
}

var (
	vaultAddr      = os.Getenv("VAULT_ADDR")
	authPath       = os.Getenv("VAULT_AUTH_PATH")
	authRole       = os.Getenv("VAULT_AUTH_ROLE")
	vaultNamespace = os.Getenv("VAULT_NAMESPACE")
	appRolePath    = os.Getenv("VAULT_APP_ROLE_PATH")
	appRoleName    = os.Getenv("VAULT_APP_ROLE_NAME")
	secretIdSecret = os.Getenv("SECRET_ID_SECRET")
)

func getSaToken() string {
	var expiration time.Time
	nowTime := time.Now().Unix()
	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	tokenString := string(saToken)

	if err != nil {
		log.Fatalf("%v", err)
	}

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})

	if err != nil {
		log.Fatalf("error parsing service account token: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		switch exp := claims["exp"].(type) {
		case float64:
			expiration = time.Unix(int64(exp), 0)
		case json.Number:
			v, _ := exp.Int64()
			expiration = time.Unix(v, 0)
		}
		if nowTime-expiration.Unix() > 0 {
			log.Println("token expired")
		}
	} else {
		log.Fatalf("error unmarshalling jwt claims: %v", err)
	}

	return tokenString
}

func vaultJwtLogin(tokenString string) string {

	payload := map[string]string{
		"role": authRole,
		"jwt":  tokenString,
	}

	json_data, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("error marshalling payload for jwt login: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 2 * time.Second,
	}

	req, err := http.NewRequest("POST", vaultAddr+"/v1/auth/"+authPath+"/login", bytes.NewReader(json_data))
	if err != nil {
		log.Fatalf("error building jwt authentication request: %v", err)
	}
	if vaultNamespace != "" {
		req.Header.Add("X-VAULT-NAMESPACE", vaultNamespace)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("error authenticating with jwt token: %v", err)
	}

	var result vaultLogin
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		log.Fatalf("error parsing Vault login response: %v", err)
	}

	return result.Auth.ClientToken
}

func getSecretId(clientToken string) (secretID string, renewTimer int64) {
	config := vault.DefaultConfig()
	config.Address = vaultAddr
	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("unable to initialize Vault client: %v", err)
	}

	if vaultNamespace != "" {
		client.SetNamespace(vaultNamespace)
	}
	client.SetToken(clientToken)

	path := "/auth/" + appRolePath + "/role/" + appRoleName + "/secret-id"

	resp, err := client.Logical().Write(path, nil)
	if err != nil {
		log.Fatalf("error generating new secret-id: %v", err)
	}

	secretID = resp.Data["secret_id"].(string)
	secretIdTtl, _ := resp.Data["secret_id_ttl"].(json.Number).Float64()
	renewTimer = int64(math.Round(secretIdTtl * .6667))

	return secretID, renewTimer
}

func createK8sSecret(secretID string) {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("error initializing kubernetes client config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("error initializing kubernetes client: %v", err)
	}

	namespace, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")

	secret := &v1.Secret{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      secretIdSecret,
			Namespace: string(namespace),
		},
		StringData: map[string]string{
			"secretId": secretID,
		},
	}

	if err != nil {
		log.Fatalf("error retrieving namespace: %v", err)
	}
	secretsClient := clientset.CoreV1().Secrets(string(namespace))
	_, err = secretsClient.Create(context.TODO(), secret, metaV1.CreateOptions{})

	if err != nil {
		_, err = secretsClient.Update(context.TODO(), secret, metaV1.UpdateOptions{})
		if err != nil {
			log.Fatalf("error updating kubernetes secret: %v", err)
		}
	}
}

func main() {
	for {
		tokenString := getSaToken()
		clientToken := vaultJwtLogin(tokenString)
		secretID, renewTimer := getSecretId(clientToken)
		log.Println("Renewed secret-id")
		createK8sSecret(secretID)
		log.Printf("Synchronized to k8s secret. %v seconds until next renewal", renewTimer)
		time.Sleep(time.Duration(renewTimer) * time.Second)
	}
}
