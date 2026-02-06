package cmd

import "github.com/spf13/cobra"

// BuildVersion is injected at build time via -ldflags "-X .../cmd.BuildVersion=...".
var BuildVersion = "dev"

var rootCmd = &cobra.Command{
	Use:   "openauth",
	Short: "OpenAuth CLI",
	Long:  "CLI for OpenAuth operations.",
}

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number of OpenAuth CLI",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("%s\n", BuildVersion)
		},
	})
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
