package cmd

import (
	"fmt"

	"github.com/denysvitali/ecovacs-firmware-tools/pkg/encrypt"
	"github.com/spf13/cobra"
)

func newRepackCmd() *cobra.Command {
	var overrides encrypt.ManifestOverrides

	cmd := &cobra.Command{
		Use:   "repack [decrypted-dir] [output.bin]",
		Short: "Re-encrypt decrypted sections into a firmware binary",
		Long: `Re-encrypt all sections in a decrypted directory back into a valid firmware binary.

Requires the .ecovacs_sections.json metadata file written by decrypt.
Section keys are derived from (type, encryptedSize), identical to the original.

The manifest section is space-padded to fill the original encrypted size.
Binary sections (type=3) produce different ciphertext than the original
(different key derivation), but decrypt correctly with the decrypt command.

Use --fw-ver/--hw-ver/--product/--release-date to override manifest fields
during repacking (e.g. bump version for OTA update testing).`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if overrides.HasAny() {
				fmt.Println(renderInfo("Manifest overrides applied"))
			}

			if err := encrypt.Repack(args[0], args[1], &overrides); err != nil {
				exitWithError("Repack failed: %v", err)
			}

			fmt.Println(renderSuccess(fmt.Sprintf("Repacked: %s → %s", args[0], args[1])))
		},
	}

	cmd.Flags().StringVar(&overrides.FwVer, "fw-ver", "", "Override firmware version")
	cmd.Flags().StringVar(&overrides.HwVer, "hw-ver", "", "Override hardware version")
	cmd.Flags().StringVar(&overrides.Product, "product", "", "Override product code")
	cmd.Flags().StringVar(&overrides.ReleaseDate, "release-date", "", "Override release date")

	return cmd
}
