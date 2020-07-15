package config

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/policy"
)

var policyConfigTypeURL string

func init() {
	any, _ := ptypes.MarshalAny(new(policy.PolicyConfig))
	policyConfigTypeURL = any.GetTypeUrl()
}

// The PolicyManager syncs policy routes from the given data broker and merges them
// with any routes defined in the config options.
type PolicyManager struct {
	dataBroker databroker.DataBrokerServiceClient
	onUpdate   func([]Policy)
	cfgs       map[string]*policy.PolicyConfig
	policies   []Policy
}

// NewPolicyManager creates a new policy manager.
func NewPolicyManager(dataBroker databroker.DataBrokerServiceClient, onUpdate func(policies []Policy)) *PolicyManager {
	mgr := &PolicyManager{
		dataBroker: dataBroker,
		onUpdate:   onUpdate,
		cfgs:       make(map[string]*policy.PolicyConfig),
	}
	return mgr
}

func (mgr *PolicyManager) Run(ctx context.Context) error {
	var serverVersion, recordVersion string

	// load the initial data
	err := tryForever(ctx, func(backoff interface{ Reset() }) error {
		res, err := mgr.dataBroker.GetAll(ctx, &databroker.GetAllRequest{
			Type: policyConfigTypeURL,
		})
		if err != nil {
			return nil
		}

		serverVersion = res.GetServerVersion()
		recordVersion = res.GetRecordVersion()

		for _, rec := range res.GetRecords() {
			var cfg policy.PolicyConfig
			err = ptypes.UnmarshalAny(rec.GetData(), &cfg)
			if err != nil {
				continue
			}

			if rec.GetDeletedAt() == nil {
				mgr.cfgs[rec.GetId()] = &cfg
			}
		}
		mgr.update()

		return stop
	})
	if err != nil {
		return err
	}

	// start syncing
	return tryForever(ctx, func(backoff interface{ Reset() }) error {
		stream, err := mgr.dataBroker.Sync(ctx, &databroker.SyncRequest{
			ServerVersion: serverVersion,
			RecordVersion: recordVersion,
			Type:          policyConfigTypeURL,
		})
		if err != nil {
			return err
		}

		for {
			res, err := stream.Recv()
			if err != nil {
				return err
			}

			backoff.Reset()

			if res.GetServerVersion() != serverVersion {
				serverVersion = res.GetServerVersion()
				mgr.cfgs = make(map[string]*policy.PolicyConfig)
			}
			for _, rec := range res.GetRecords() {
				if rec.GetDeletedAt() != nil {
					delete(mgr.cfgs, rec.GetId())
					continue
				}

				var cfg policy.PolicyConfig
				err = ptypes.UnmarshalAny(rec.GetData(), &cfg)
				if err != nil {
					continue
				}

				if rec.GetDeletedAt() == nil {
					mgr.cfgs[rec.GetId()] = &cfg
				}
			}
			mgr.update()
		}
	})
}

// update recomputes the policies based on the options and data broker policy routes.
func (mgr *PolicyManager) update() {
	var ids []string
	for id := range mgr.cfgs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return mgr.cfgs[ids[i]].GetName() < mgr.cfgs[ids[j]].GetName()
	})

	mgr.policies = nil
	for _, id := range ids {
		cfg := mgr.cfgs[id]

		for _, pbr := range cfg.GetRoutes() {
			p, err := NewPolicyFromProto(pbr)
			if err != nil {
				log.Warn().Str("service", "policy-manager").Err(err).Interface("policy", pbr).Msg("invalid policy")
				continue
			}

			//TODO: handle duplicate policies
			mgr.policies = append(mgr.policies, *p)
		}
	}

	log.Info().Str("service", "policy-manager").Int("count", len(mgr.policies)).Msg("updated policies")
	mgr.onUpdate(mgr.policies)
}

var stop = errors.New("STOP")

func tryForever(ctx context.Context, callback func(onSuccess interface{ Reset() }) error) error {
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	for {
		err := callback(bo)
		if errors.Is(err, stop) {
			return nil
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		} else if err != nil {
			log.Warn().Err(err).Msg("sync error")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(bo.NextBackOff()):
		}
	}
}
