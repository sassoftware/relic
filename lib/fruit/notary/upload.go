package notary

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/logging"
)

func (c *Client) Upload(ctx context.Context, attr *UploadAttributes, f io.ReadSeeker) error {
	if err := attr.Validate(); err != nil {
		return fmt.Errorf("invalid submission attributes: %w", err)
	}
	options := s3.Options{
		ClientLogMode: aws.LogRetries | aws.LogDeprecatedUsage,
		Credentials: credentials.NewStaticCredentialsProvider(
			attr.AWSAccessKeyID,
			attr.AWSSecretAccessKey,
			attr.AWSSessionToken,
		),
		Logger: logging.StandardLogger{
			Logger: c.Logger,
		},
		Region:        c.region,
		UseAccelerate: true,
	}
	uploader := s3.New(options)
	params := &s3.PutObjectInput{
		Bucket: aws.String(attr.Bucket),
		Key:    aws.String(attr.Object),
		Body:   f,
	}
	if _, err := uploader.PutObject(ctx, params); err != nil {
		return fmt.Errorf("uploading submission: %w", err)
	}
	return nil
}
