package cmd

import "github.com/spf13/cobra"

func init() {
	rootCmd.AddCommand(newMigrateCommand())
}

func newMigrateCommand() *cobra.Command {
	migrateCmd := &cobra.Command{
		Use:   "migrate",
		Short: "Run OpenAuth migration and seed routines",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	migrateCmd.AddCommand(&cobra.Command{
		Use:   "up",
		Short: "Run schema migrations",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println("migration runner skeleton: implementation pending")
		},
	})

	migrateCmd.AddCommand(&cobra.Command{
		Use:   "seed",
		Short: "Run idempotent seed routines",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println("seed runner skeleton: implementation pending")
		},
	})

	return migrateCmd
}
