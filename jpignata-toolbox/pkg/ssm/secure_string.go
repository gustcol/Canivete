package ssm

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
)

// GetSecureString returns a decrypted secure string value from AWS System Manager Parameter Store.
func GetSecureString(name string) (string, error) {
	sess := session.New()
	svc := ssm.New(sess)

	output, err := svc.GetParameter(
		&ssm.GetParameterInput{
			Name:           aws.String(name),
			WithDecryption: aws.Bool(true),
		},
	)

	if err != nil {
		return "", err
	}

	return aws.StringValue(output.Parameter.Value), nil
}
