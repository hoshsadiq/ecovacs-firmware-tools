package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// Color palette
	colorSuccess = lipgloss.Color("#00FF00")
	colorError   = lipgloss.Color("#FF0000")
	colorWarning = lipgloss.Color("#FFFF00")
	colorInfo    = lipgloss.Color("#00FFFF")
	colorDebug   = lipgloss.Color("#888888")

	// Text styles
	successStyle = lipgloss.NewStyle().Foreground(colorSuccess).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(colorError).Bold(true)
	warningStyle = lipgloss.NewStyle().Foreground(colorWarning).Bold(true)
	infoStyle    = lipgloss.NewStyle().Foreground(colorInfo).Bold(true)
	debugStyle   = lipgloss.NewStyle().Foreground(colorDebug)

	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FFFF")).
			Bold(true).
			Underline(true)

	checkmarkStyle = lipgloss.NewStyle().Foreground(colorSuccess)

	verbose bool
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ecovacs-firmware-tools",
		Short: "Ecovacs firmware decryption and download tools",
		Long: lipgloss.JoinVertical(lipgloss.Left,
			titleStyle.Render("Ecovacs Firmware Tools"),
			"",
			"A comprehensive toolkit for working with Ecovacs DEEBOT firmware:",
			"  • Decrypt firmware images",
			"  • Download firmware via OTA API",
			"",
			"Use --help with any command for more information.",
		),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if verbose {
				log.SetLevel(log.DebugLevel)
			}
		},
	}

	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	cmd.AddCommand(newDecryptCmd())
	cmd.AddCommand(newDownloadCmd())
	cmd.AddCommand(newRepackCmd())

	return cmd
}

// Execute runs the root command
func Execute() error {
	return newRootCmd().Execute()
}

func exitWithError(msg string, args ...interface{}) {
	fmt.Fprintln(os.Stderr, errorStyle.Render("✗ "+fmt.Sprintf(msg, args...)))
	os.Exit(1)
}

func renderSuccess(text string) string {
	return successStyle.Render("✓ " + text)
}

func renderError(text string) string {
	return errorStyle.Render("✗ " + text)
}

func renderWarning(text string) string {
	return warningStyle.Render("⚠ " + text)
}

func renderInfo(text string) string {
	return infoStyle.Render("ℹ " + text)
}
