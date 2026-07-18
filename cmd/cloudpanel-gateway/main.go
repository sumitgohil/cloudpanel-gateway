package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/psng-tech/cloudpanel-gateway/internal/gateway"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	root := gateway.NewRootCommand()
	root.SetArgs(os.Args[1:])
	root.SetContext(ctx)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
