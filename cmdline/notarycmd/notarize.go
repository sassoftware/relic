package notarycmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/sassoftware/relic/v8/cmdline/shared"
	"github.com/sassoftware/relic/v8/config"
	"github.com/sassoftware/relic/v8/lib/fruit/notary"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	argKeyID, argKey, argIssuer string
	argNoWait, argJSON          bool
	argTimeout                  time.Duration
)

func init() {
	notaryCmd := &cobra.Command{
		Use:   "notary",
		Short: "Commands related to App Store Connect notarization",
	}
	shared.RootCmd.AddCommand(notaryCmd)

	cliFlags := pflag.NewFlagSet("buh", pflag.ExitOnError)
	cliFlags.StringVarP(&argKeyID, "key-id", "D", "", "API Key ID for App Store Connect")
	cliFlags.StringVarP(&argKey, "key", "k", "", "Path to API Key for App Store Connect")
	cliFlags.StringVarP(&argIssuer, "issuer", "i", "", "API Issuer ID for App Store Connect")
	cliFlags.BoolVar(&argJSON, "json", false, "Output in JSON format")

	infoCmd := &cobra.Command{
		Use:   "info <submission-id>",
		Short: "Get status of a previously-initiated submission",
		Args:  cobra.ExactArgs(1),
		RunE:  runInfo,
	}
	infoCmd.Flags().AddFlagSet(cliFlags)
	notaryCmd.AddCommand(infoCmd)

	submitCmd := &cobra.Command{
		Use:   "submit file.zip|file.pkg|file.dmg",
		Short: "Submit a bundle to App Store Connect for notarization",
		Args:  cobra.ExactArgs(1),
		RunE:  runSubmit,
	}
	submitCmd.Flags().AddFlagSet(cliFlags)
	submitCmd.Flags().BoolVar(&argNoWait, "no-wait", false, "Exit after submission without waiting for results")
	submitCmd.Flags().DurationVar(&argTimeout, "timeout", 0, "Maximum wait time before exiting without a result")
	notaryCmd.AddCommand(submitCmd)
}

func makeClient() (*notary.Client, error) {
	// Parse configuration
	if err := shared.InitConfigIfExists(); err != nil {
		return nil, err
	}
	var notaryCfg *config.NotaryConfig
	if shared.CurrentConfig != nil {
		notaryCfg = shared.CurrentConfig.Notary
	}
	if notaryCfg == nil {
		notaryCfg = new(config.NotaryConfig)
	}
	// Apply settings from cmdline
	if argKeyID != "" {
		notaryCfg.APIKeyID = argKeyID
	}
	if argKey != "" {
		notaryCfg.APIKeyPath = argKey
	}
	if argIssuer != "" {
		notaryCfg.APIIssuerID = argIssuer
	}
	// Validate and build the client
	return notary.NewClient(notaryCfg)
}

func printStatus(status *notary.SubmissionStatus) {
	if argJSON {
		blob, _ := json.Marshal(status)
		fmt.Println(string(blob))
	} else if status == nil {
		fmt.Println("unknown")
	} else {
		fmt.Println("ID:     ", status.ID)
		fmt.Println("Name:   ", status.Attributes.Name)
		fmt.Println("Created:", status.Attributes.CreatedDate)
		fmt.Println("Status: ", status.Attributes.Status)
	}
}

func runInfo(cmd *cobra.Command, args []string) error {
	cli, err := makeClient()
	if err != nil {
		return err
	}
	status, err := cli.GetSubmissionStatus(context.Background(), args[0])
	if err != nil {
		return err
	}
	printStatus(status)
	return nil
}

func runSubmit(cmd *cobra.Command, args []string) error {
	// Parse and setup
	cli, err := makeClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if argTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, argTimeout)
		defer cancel()
	}
	// Submit file
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	submissionID, err := cli.SubmitFile(ctx, path.Base(args[0]), f)
	if err != nil {
		log.Fatalln("error:", err)
	}
	if argNoWait {
		status, err := cli.GetSubmissionStatus(ctx, submissionID)
		if err != nil {
			log.Fatalln("error:", err)
		}
		printStatus(status)
		return nil
	} else if !argJSON {
		log.Println("Submission initiated:", submissionID)
	}
	// Poll status
	var lastStatus *notary.SubmissionStatus
	var failures int
	sleep := 5 * time.Second
	const maxSleep = time.Minute
	for {
		// Start with a short interval and increase it up to the maximum
		ctx2, cancel := context.WithTimeout(ctx, sleep)
		<-ctx2.Done()
		cancel()
		if ctx.Err() != nil {
			// Timeout reached
			break
		}
		sleep = sleep * 5 / 3
		if sleep > maxSleep {
			sleep = maxSleep
		}
		status, err := cli.GetSubmissionStatus(ctx, submissionID)
		if err != nil {
			if ctx.Err() != nil {
				// Timeout reached
				break
			}
			// Tolerate a few failures before giving up
			failures++
			if failures > 3 {
				log.Println("error: too many failures checking status:", err)
				break
			}
		} else {
			failures = 0
			// Print the result so far
			if !argJSON {
				log.Println("Status:", status.Attributes.Status)
			}
			lastStatus = status
			if status.Attributes.Status != notary.StatusInProgress {
				// Exit when a terminal state is reached
				break
			}
		}
	}
	if ctx.Err() != nil {
		log.Printf("Timeout of %s exceeded. Last status:", argTimeout)
	}
	printStatus(lastStatus)
	if lastStatus == nil || lastStatus.Attributes.Status != notary.StatusAccepted {
		os.Exit(1)
	}
	return nil
}
