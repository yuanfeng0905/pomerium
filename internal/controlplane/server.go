package controlplane

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type versionedOptions struct {
	options  config.Options
	policies []config.Policy
	version  int64
}

type atomicVersionedOptions struct {
	value atomic.Value
}

func (avo *atomicVersionedOptions) Load() versionedOptions {
	return avo.value.Load().(versionedOptions)
}

func (avo *atomicVersionedOptions) Store(options versionedOptions) {
	avo.value.Store(options)
}

// A Server is the control-plane gRPC and HTTP servers.
type Server struct {
	GRPCListener net.Listener
	GRPCServer   *grpc.Server
	HTTPListener net.Listener
	HTTPRouter   *mux.Router

	policyManager *config.PolicyManager

	currentConfig atomicVersionedOptions
	configUpdated chan struct{}
}

// NewServer creates a new Server. Listener ports are chosen by the OS.
func NewServer(name string) (*Server, error) {
	srv := &Server{
		configUpdated: make(chan struct{}, 1),
	}
	srv.currentConfig.Store(versionedOptions{})

	dataBrokerConn, err := grpc.NewGRPCClientConn(
		&grpc.Options{
			Addr:                    opts.DataBrokerURL,
			OverrideCertificateName: opts.OverrideCertificateName,
			CA:                      opts.CA,
			CAFile:                  opts.CAFile,
			RequestTimeout:          opts.GRPCClientTimeout,
			ClientDNSRoundRobin:     opts.GRPCClientDNSRoundRobin,
			WithInsecure:            opts.GRPCInsecure,
			ServiceName:             opts.Services,
		})
	if err != nil {
		return nil, fmt.Errorf("proxy: error creating data broker connection: %w", err)
	}
	dataBrokerClient := databroker.NewDataBrokerServiceClient(dataBrokerConn)
	srv.policyManager = config.NewPolicyManager(dataBrokerClient, func(policies []config.Policy) {
		srv.UpdatePolicies(policies)
	})

	// setup gRPC
	srv.GRPCListener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srv.GRPCServer = grpc.NewServer(
		grpc.StatsHandler(telemetry.NewGRPCServerStatsHandler(name)),
		grpc.UnaryInterceptor(requestid.UnaryServerInterceptor()),
		grpc.StreamInterceptor(requestid.StreamServerInterceptor()),
	)
	reflection.Register(srv.GRPCServer)
	srv.registerXDSHandlers()
	srv.registerAccessLogHandlers()

	// setup HTTP
	srv.HTTPListener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = srv.GRPCListener.Close()
		return nil, err
	}
	srv.HTTPRouter = mux.NewRouter()
	srv.addHTTPMiddleware()

	return srv, nil
}

// Run runs the control-plane gRPC and HTTP servers.
func (srv *Server) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	// start the policy manager
	eg.Go(func() error {
		return srv.policyManager.Run(ctx)
	})

	// start the gRPC server
	eg.Go(func() error {
		log.Info().Str("addr", srv.GRPCListener.Addr().String()).Msg("starting control-plane gRPC server")
		return srv.GRPCServer.Serve(srv.GRPCListener)
	})

	// gracefully stop the gRPC server on context cancellation
	eg.Go(func() error {
		<-ctx.Done()

		ctx, cancel := context.WithCancel(ctx)
		ctx, cleanup := context.WithTimeout(ctx, time.Second*5)
		defer cleanup()

		go func() {
			srv.GRPCServer.GracefulStop()
			cancel()
		}()

		go func() {
			<-ctx.Done()
			srv.GRPCServer.Stop()
			cancel()
		}()

		<-ctx.Done()

		return nil
	})

	hsrv := (&http.Server{
		BaseContext: func(li net.Listener) context.Context {
			return ctx
		},
		Handler: srv.HTTPRouter,
	})

	// start the HTTP server
	eg.Go(func() error {
		log.Info().Str("addr", srv.HTTPListener.Addr().String()).Msg("starting control-plane HTTP server")
		return hsrv.Serve(srv.HTTPListener)
	})

	// gracefully stop the HTTP server on context cancellation
	eg.Go(func() error {
		<-ctx.Done()

		ctx, cleanup := context.WithTimeout(ctx, time.Second*5)
		defer cleanup()

		return hsrv.Shutdown(ctx)
	})

	return eg.Wait()
}

// UpdateOptions updates the pomerium config options.
func (srv *Server) UpdateOptions(options config.Options) error {
	select {
	case <-srv.configUpdated:
	default:
	}
	prev := srv.currentConfig.Load()
	srv.currentConfig.Store(versionedOptions{
		options:  options,
		policies: prev.policies,
		version:  prev.version + 1,
	})
	srv.configUpdated <- struct{}{}
	return nil
}

// UpdatePolicies updates the policies.
func (srv *Server) UpdatePolicies(policies []config.Policy) {
	select {
	case <-srv.configUpdated:
	default:
	}
	prev := srv.currentConfig.Load()
	srv.currentConfig.Store(versionedOptions{
		options:  prev.options,
		policies: policies,
		version:  prev.version + 1,
	})
	srv.configUpdated <- struct{}{}
}
