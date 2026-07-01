package cmd

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/scheduler"
)

func schedulerCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "scheduler",
		Short: "Install or remove the background scheduled update on this host",
	}
	c.AddCommand(schedulerInstallCmd())
	c.AddCommand(schedulerRemoveCmd())
	c.AddCommand(schedulerStatusCmd())
	c.AddCommand(schedulerPreviewCmd())
	return c
}

func schedulerInstallCmd() *cobra.Command {
	var interval time.Duration
	var binary string
	var quiet bool
	c := &cobra.Command{
		Use:   "install",
		Short: "Install a recurring update task (launchd/systemd/Task Scheduler depending on OS)",
		RunE: func(c *cobra.Command, args []string) error {
			cfg, err := resolveSchedulerConfig(binary, interval, quiet)
			if err != nil {
				return err
			}
			if err := scheduler.Install(cfg); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "installed scheduled update on %s (every %s)\n", runtime.GOOS, cfg.Interval)
			return nil
		},
	}
	c.Flags().DurationVar(&interval, "interval", 6*time.Hour, "interval between runs")
	c.Flags().StringVar(&binary, "binary", "", "absolute path to secure-vibe binary (default: current binary)")
	c.Flags().BoolVar(&quiet, "quiet", true, "ask the scheduled run to suppress non-error output")
	return c
}

func schedulerRemoveCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "remove",
		Short: "Remove the scheduled update from this host",
		RunE: func(c *cobra.Command, args []string) error {
			if err := scheduler.Remove(); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "removed scheduled update on %s\n", runtime.GOOS)
			return nil
		},
	}
	return c
}

func schedulerStatusCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "status",
		Short: "Show whether a scheduled update is installed",
		RunE: func(c *cobra.Command, args []string) error {
			status, err := scheduler.Status()
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if status == "" {
				fmt.Fprintln(out, "no scheduled update installed")
				return nil
			}
			fmt.Fprintln(out, status)
			return nil
		},
	}
	return c
}

func schedulerPreviewCmd() *cobra.Command {
	var interval time.Duration
	var binary, target string
	c := &cobra.Command{
		Use:   "preview",
		Short: "Print the launchd/systemd/Task Scheduler artifact this CLI would write",
		RunE: func(c *cobra.Command, args []string) error {
			cfg, err := resolveSchedulerConfig(binary, interval, true)
			if err != nil {
				return err
			}
			t := target
			if t == "" {
				t = runtime.GOOS
			}
			out := c.OutOrStdout()
			switch t {
			case "darwin", "macos":
				body, err := scheduler.RenderLaunchAgentPlist(cfg)
				if err != nil {
					return err
				}
				fmt.Fprint(out, body)
			case "linux":
				svc, err := scheduler.RenderSystemdService(cfg)
				if err != nil {
					return err
				}
				timer, err := scheduler.RenderSystemdTimer(cfg)
				if err != nil {
					return err
				}
				fmt.Fprintln(out, "# "+scheduler.SystemdServiceName+".service")
				fmt.Fprint(out, svc)
				fmt.Fprintln(out)
				fmt.Fprintln(out, "# "+scheduler.SystemdServiceName+".timer")
				fmt.Fprint(out, timer)
			case "windows":
				body, err := scheduler.RenderTaskSchedulerXML(cfg)
				if err != nil {
					return err
				}
				fmt.Fprint(out, body)
			default:
				return fmt.Errorf("unknown scheduler target %q (expected darwin, linux, windows)", t)
			}
			return nil
		},
	}
	c.Flags().DurationVar(&interval, "interval", 6*time.Hour, "interval between runs")
	c.Flags().StringVar(&binary, "binary", "", "absolute path to secure-vibe binary (default: current binary)")
	c.Flags().StringVar(&target, "target", "", "scheduler target (darwin, linux, windows). Default: current OS.")
	return c
}

func resolveSchedulerConfig(binary string, interval time.Duration, quiet bool) (scheduler.Config, error) {
	if binary == "" {
		exe, err := os.Executable()
		if err != nil {
			return scheduler.Config{}, fmt.Errorf("resolve current binary: %w", err)
		}
		binary = exe
	}
	cfg := scheduler.Defaults(binary)
	if interval > 0 {
		cfg.Interval = interval
	}
	cfg.Quiet = quiet
	args := []string{"update", "--regenerate"}
	if quiet {
		args = append(args, "--quiet")
	}
	cfg.Args = args
	return cfg, nil
}
