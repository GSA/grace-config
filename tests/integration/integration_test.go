package testing

import (
	"fmt"
	"os"
	"testing"

	"github.com/GSA/grace-tftest/aws/config"
	"github.com/GSA/grace-tftest/aws/iam"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

func TestIntegration(t *testing.T) {
	port := os.Getenv("MOTO_PORT")
	if len(port) == 0 {
		t.Skipf("skipping testing, MOTO_PORT not set in environment variables")
	}

	url := "http://localhost:" + port
	fmt.Printf("connecting to: %s\n", url)
	sess, err := session.NewSession(&aws.Config{
		Endpoint:   aws.String(url),
		DisableSSL: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("failed to connect to moto: %s -> %v", url, err)
	}

	role := iam.New(sess).
		Role.
		Name("config-service").
		Assert(t, nil)

	role.
		Statement(t).
		Action("sts:AssumeRole").
		Principal("Service", "config.amazonaws.com").
		Effect("Allow").
		Assert(t)

	role.
		Attached().
		Arn("arn:aws:iam::aws:policy/service-role/AWSConfigRole").
		Assert(t, nil)

	recorder := config.New(sess)
	recorder.
		Recorder.
		Name("config-service").
		RoleArn(aws.StringValue(role.Selected().Arn)).
		AllSupported(true).
		IncludeGlobalResourceTypes(true).
		Assert(t, nil)

}
