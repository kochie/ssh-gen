package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

type sshHostConfig struct {
	serviceName  string
	hostName     string
	user         string
	identityFile string
}

func main() {
	// TODO: write script for each source control
	// TODO: generate a key
	// TODO: generate or append config file
	// TODO: read command line arguments
	updateConfig(sshHostConfig{
		serviceName:  "GitHub",
		hostName:     "github.com",
		user:         "git",
		identityFile: "~/.ssh/",
	})

	servicesPtr := flag.String("services", "github,bitbucket,gitlab", "services to connect")
	flag.Parse()
	services := strings.Split(*servicesPtr, ",")

	for _, service := range services {
		switch service {
		case "github":
			fmt.Println("GitHub")
		case "bitbucket":
			fmt.Println("BitBucket")
		case "gitlab":
			fmt.Println("GitLab")
		default:
			fmt.Println("DEFAULT")
		}
	}
}

func handleError(err error) {
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func createKey(serviceName string, bitSize int) (publicKey []byte) {
	hostname, err := os.Hostname()
	handleError(err)
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	handleError(err)
	bytevalue := x509.MarshalPKCS1PrivateKey(privateKey)

	privateBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: bytevalue,
	})

	err = os.MkdirAll(fmt.Sprintf("~/.ssh/%s", serviceName), 755)
	keyName := fmt.Sprintf("%s-%s.rsa", strings.ToLower(serviceName), hostname)

	handleError(err)

	if _, err = os.Stat(keyName); os.IsExist(err) {
		fmt.Printf("File %s already exists. exiting...\n", keyName)
		os.Exit(1)
	}

	ioutil.WriteFile(keyName, privateBytes, 0644)

	publicByteValue, err := ssh.NewPublicKey(&privateKey.PublicKey)
	handleError(err)
	publicKey = ssh.MarshalAuthorizedKey(publicByteValue)
	return
}

func updateConfig(config sshHostConfig) {
	fmt.Println(config.identityFile)

	configName := "~/.ssh"

	if _, err := os.Stat(configName); os.IsExist(err) {
		fmt.Printf("Appending %s to config\n", config.serviceName)
	} else {
		fmt.Printf("No config file detected, making one for %s\n", config.serviceName)
	}

	configFile, err := os.OpenFile(configName, os.O_APPEND|os.O_CREATE, 0755)
	handleError(err)
	defer func() {
		err = configFile.Close()
		handleError(err)
	}()

	configData := fmt.Sprintf("Host %s\n\tIdentityFile %s\n\tUser %s\n", config.hostName, config.identityFile, config.user)

	_, err = configFile.WriteString(configData)
	handleError(err)
}

func sendSSHKey(config sshHostConfig, sshKey string) {

}
